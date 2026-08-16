use alloc::vec::Vec;

use crate::verified::{
    Error, HEADER_LEN, MAX_PLAINTEXT, MAX_WIRE, RecordHeader, StreamDecision, accepted_prefix,
    inner_fragment_content_limit, inspect_record, next_bounded_fragment_len,
    transport_fragment_content_limit,
};
use crate::Limit;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

impl OwnedRecord {
    /// Decode exactly one complete record prefix using the verified framing
    /// decision. The returned wire length is the only transport cursor value
    /// the integration needs to retain.
    pub fn decode_prefix(input: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let (header, wire_len) = match inspect_record(input)? {
            StreamDecision::NeedMore => return Ok(None),
            StreamDecision::Record { header, wire_len } => (header, wire_len),
        };
        Ok(Some((
            Self {
                header,
                payload: input[HEADER_LEN..wire_len].to_vec(),
            },
            wire_len,
        )))
    }
}

/// Bounded incremental TLS record input. It never retains more than one
/// maximum TLS 1.3 ciphertext record plus its header.
#[derive(Debug)]
pub struct RecordBuffer {
    bytes: Vec<u8>,
}

impl RecordBuffer {
    pub fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_WIRE),
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn remaining_capacity(&self) -> usize {
        MAX_WIRE - self.bytes.len()
    }

    pub fn buffered(&self) -> &[u8] {
        &self.bytes
    }

    pub fn buffered_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Accepts the largest bounded prefix and returns its length. Callers use
    /// this value for transport backpressure.
    pub fn feed(&mut self, input: &[u8]) -> usize {
        let accepted = accepted_prefix(self.bytes.len(), input.len());
        self.bytes.extend_from_slice(&input[..accepted]);
        accepted
    }

    pub fn discard_prefix(&mut self, length: usize) -> Result<(), Error> {
        if length > self.bytes.len() {
            return Err(Error::InvalidState);
        }
        self.bytes.drain(..length);
        Ok(())
    }

    pub fn next_record(&mut self) -> Result<Option<OwnedRecord>, Error> {
        let Some((record, wire_len)) = OwnedRecord::decode_prefix(&self.bytes)? else {
            return Ok(None);
        };
        self.discard_prefix(wire_len)?;
        Ok(Some(record))
    }

    pub fn finish(&self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}

impl Default for RecordBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine-owned sender fragmentation policy. Transport configuration and the
/// peer's directional RFC 8449 limit remain distinct and only tighten the
/// effective content cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragmenter {
    transport_content_limit: usize,
    peer_inner_content_limit: usize,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fragmenter {
    pub const fn new() -> Self {
        Self {
            transport_content_limit: MAX_PLAINTEXT,
            peer_inner_content_limit: MAX_PLAINTEXT,
        }
    }

    pub fn set_max_wire_size(&mut self, size: Option<usize>) -> Result<(), Error> {
        self.transport_content_limit = match size {
            Some(size) => transport_fragment_content_limit(size)?,
            None => MAX_PLAINTEXT,
        };
        Ok(())
    }

    pub fn tighten_peer_inner_limit(&mut self, limit: Limit) {
        self.peer_inner_content_limit = core::cmp::min(
            self.peer_inner_content_limit,
            inner_fragment_content_limit(limit),
        );
    }

    pub fn content_limit(&self) -> usize {
        core::cmp::min(
            self.transport_content_limit,
            self.peer_inner_content_limit,
        )
    }

    pub fn plan(&self, content_len: usize) -> FragmentPlan {
        FragmentPlan {
            remaining: content_len,
            max_content: self.content_limit(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentPlan {
    remaining: usize,
    max_content: usize,
}

impl Iterator for FragmentPlan {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let take = match next_bounded_fragment_len(self.remaining, self.max_content) {
            Ok(take) => take,
            Err(_) => {
                // Private construction keeps `max_content` nonzero.  Keep the
                // public iterator panic-free if that invariant ever changes.
                self.remaining = 0;
                return None;
            }
        };
        self.remaining -= take;
        Some(take)
    }
}

impl ExactSizeIterator for FragmentPlan {
    fn len(&self) -> usize {
        if self.remaining == 0 {
            0
        } else {
            1 + (self.remaining - 1) / self.max_content
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_header_splits_and_coalescing() {
        let first = [22, 3, 1, 0, 1, 7];
        let second = [23, 3, 3, 0, 2, 8, 9];
        for split in 0..=5 {
            let mut buffer = RecordBuffer::new();
            assert_eq!(buffer.feed(&first[..split]), split);
            assert_eq!(buffer.next_record().unwrap(), None);
            assert_eq!(buffer.feed(&first[split..]), first.len() - split);
            let record = buffer.next_record().unwrap().unwrap();
            assert_eq!(record.header.content_type, 22);
            assert_eq!(record.payload, [7]);
        }
        let mut buffer = RecordBuffer::new();
        let mut joined = first.to_vec();
        joined.extend_from_slice(&second);
        assert_eq!(buffer.feed(&joined), joined.len());
        assert_eq!(buffer.next_record().unwrap().unwrap().payload, [7]);
        assert_eq!(buffer.next_record().unwrap().unwrap().payload, [8, 9]);
        assert!(buffer.next_record().unwrap().is_none());
    }

    #[test]
    fn finish_distinguishes_boundary_from_truncation() {
        let mut buffer = RecordBuffer::new();
        assert_eq!(buffer.finish(), Ok(()));
        buffer.feed(&[22]);
        assert_eq!(buffer.finish(), Err(Error::Truncated));
    }

    #[test]
    fn buffer_is_bounded() {
        let mut buffer = RecordBuffer::new();
        assert_eq!(buffer.feed(&[0; MAX_WIRE + 1]), MAX_WIRE);
        assert_eq!(buffer.buffered_len(), MAX_WIRE);
        assert_eq!(buffer.feed(&[1]), 0);
    }

    #[test]
    fn fragment_policy_combines_transport_and_directional_limits() {
        let mut fragmenter = Fragmenter::new();
        fragmenter.set_max_wire_size(Some(100)).unwrap();
        assert_eq!(fragmenter.content_limit(), 95);
        fragmenter
            .tighten_peer_inner_limit(Limit::new(64).unwrap());
        assert_eq!(fragmenter.content_limit(), 63);
        assert_eq!(fragmenter.plan(130).collect::<Vec<_>>(), [63, 63, 4]);
        fragmenter.set_max_wire_size(None).unwrap();
        assert_eq!(fragmenter.content_limit(), 63);
    }
}
