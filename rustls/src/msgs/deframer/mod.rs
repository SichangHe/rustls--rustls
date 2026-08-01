use core::mem;

use crate::error::{Error, InvalidMessage};
use crate::msgs::message::InboundOpaqueMessage;
use crate::{ContentType, ProtocolVersion};
use verus_tls13_record::{FrameError, FrameStatus, HEADER_LEN, classify_frame};

pub(crate) mod buffers;
pub(crate) mod handshake;

/// A deframer of TLS wire messages.
///
/// Returns `Some(Ok(_))` containing each `InboundOpaqueMessage` deframed
/// from the buffer.
///
/// Returns `None` if no further messages can be deframed from the
/// buffer.  More data is required for further progress.
///
/// Returns `Some(Err(_))` if the peer is not talking TLS, but some
/// other protocol.  The caller should abort the connection, because
/// the deframer cannot recover.
///
/// Call `bytes_consumed()` to learn how many bytes the iterator has
/// processed from the front of the original buffer.  This is only updated
/// when a message is successfully deframed (ie. `Some(Ok(_))` is returned).
pub(crate) struct DeframerIter<'a> {
    buf: &'a mut [u8],
    consumed: usize,
    allow_selected_tls13_legacy_version: bool,
}

impl<'a> DeframerIter<'a> {
    /// Make a new `DeframerIter`
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self::new_with_selected_tls13(buf, false)
    }

    /// Make a deframer for an active selected TLS 1.3 record direction.
    pub(crate) fn new_with_selected_tls13(buf: &'a mut [u8], selected_tls13: bool) -> Self {
        Self {
            buf,
            consumed: 0,
            allow_selected_tls13_legacy_version: selected_tls13,
        }
    }

    /// How many bytes were processed successfully from the front
    /// of the buffer passed to `new()`?
    pub(crate) fn bytes_consumed(&self) -> usize {
        self.consumed
    }
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<InboundOpaqueMessage<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let frame = match classify_frame(self.buf) {
            FrameStatus::NeedMore { .. } => return None,
            FrameStatus::Invalid(error) => {
                let error = match error {
                    FrameError::InvalidContentType => InvalidMessage::InvalidContentType,
                    FrameError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
                    FrameError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    FrameError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                };
                return Some(Err(error.into()));
            }
            FrameStatus::Complete(frame) => frame,
        };

        if (frame.version & 0xff00) != 0x0300
            && !(self.allow_selected_tls13_legacy_version
                && frame.content_type == ContentType::ApplicationData.to_array()[0])
        {
            return Some(Err(InvalidMessage::UnknownProtocolVersion.into()));
        }

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(frame.frame_len);
        self.buf = remainder;
        self.consumed += frame.frame_len;

        Some(Ok(InboundOpaqueMessage::new(
            ContentType::from(frame.content_type),
            ProtocolVersion::from(frame.version),
            &mut consumed[HEADER_LEN..],
        )))
    }
}

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut iter = DeframerIter::new(&mut buf);

    for message in iter.by_ref() {
        if message.is_err() {
            break;
        }
    }

    assert!(iter.bytes_consumed() <= buf.len());
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::prelude::v1::*;

    use super::*;
    use crate::ContentType;

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(
            DeframerIter::new(&mut [])
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16])
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03])
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03])
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00])
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00, 0x01])
                .next()
                .is_none()
        );
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 6);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_selected_tls13_accepts_legacy_version_on_protected_record() {
        let mut buffer = [0x17, 0x01, 0x23, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new_with_selected_tls13(&mut buffer, true);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 6);
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(iter.next().unwrap().unwrap().typ, ContentType::Handshake);
        assert_eq!(iter.bytes_consumed(), 6);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 12);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload))
        );
    }

    #[test]
    fn iterator_over_many_messages() {
        let client_hello = include_bytes!("../../testdata/deframer-test.1.bin");
        let mut buffer = Vec::with_capacity(3 * client_hello.len());
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        let mut iter = DeframerIter::new(&mut buffer);
        let mut count = 0;

        for message in iter.by_ref() {
            let message = message.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, iter.bytes_consumed());
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
