use alloc::vec::Vec;

use crate::{
    AeadLimits, ContentType, Error, HandshakeReassembler, InboundRecordCore, InboundRecordKind,
    KeyUpdateRequest, Limit, OwnedRecord, PendingReceiveLimit, ReceiveDisposition,
    TrafficKeyProvider, TrafficOpener, inbound_activate_protection,
    inbound_classify_record, inbound_complete_record, inbound_fail,
};

/// Alert description selected by the verified record-error classifier. The
/// integration layer only converts these semantic values to rustls enums.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordAlert {
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    DecodeError,
    IllegalParameter,
    InternalError,
}

pub fn record_error_alert(error: Error) -> Option<RecordAlert> {
    match error {
        Error::RecordOverflow => Some(RecordAlert::RecordOverflow),
        Error::UnexpectedMessage => Some(RecordAlert::UnexpectedMessage),
        Error::BadRecordMac | Error::ProviderContract => Some(RecordAlert::BadRecordMac),
        Error::DecodeError | Error::Truncated => Some(RecordAlert::DecodeError),
        Error::IllegalParameter => Some(RecordAlert::IllegalParameter),
        Error::ProviderExhausted => Some(RecordAlert::InternalError),
        Error::InvalidState => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPlainRecord {
    pub content_type: ContentType,
    /// The exact received legacy version for plaintext records. Protected
    /// records report semantic TLS 1.3 (`0x0304`) after authenticating the
    /// exact, uninterpreted wire header as AEAD additional data.
    pub legacy_version: u16,
    pub payload: Vec<u8>,
    pub protected: bool,
    pub want_close_before_decrypt: bool,
}

enum ReceiveKeys {
    Plaintext,
    Epoch(TrafficOpener),
}

/// Selected-profile record receiver. It owns record protection activation,
/// exact received-header authentication, independent read usage/epochs,
/// plaintext/protected policy, interleaving, empty-fragment limits, pending
/// RFC 8449 observation, and terminal failure.
pub struct RecordReceiver {
    core: InboundRecordCore,
    keys: ReceiveKeys,
    pending_receive_limit: Option<PendingReceiveLimit>,
}

impl Default for RecordReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordReceiver {
    pub const fn new() -> Self {
        Self {
            core: InboundRecordCore {
                protection_active: false,
                has_decrypted: false,
                consecutive_empty_fragments: 0,
                terminal: false,
            },
            keys: ReceiveKeys::Plaintext,
            pending_receive_limit: None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.core.terminal
    }

    pub fn has_decrypted(&self) -> bool {
        self.core.has_decrypted
    }

    pub fn is_protected(&self) -> bool {
        self.core.protection_active
    }

    pub fn sequence(&self) -> u64 {
        match &self.keys {
            ReceiveKeys::Plaintext => 0,
            ReceiveKeys::Epoch(opener) => opener.sequence(),
        }
    }

    pub fn traffic_secret(&self) -> Option<&[u8]> {
        match &self.keys {
            ReceiveKeys::Epoch(opener) => Some(opener.current_secret()),
            _ => None,
        }
    }

    pub fn install_handshake(
        &mut self,
        provider: alloc::boxed::Box<dyn TrafficKeyProvider>,
        secret: &[u8],
        receive_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<(), Error> {
        if self.core.terminal {
            return Err(Error::InvalidState);
        }
        if let Some(pending) = self.pending_receive_limit.as_mut() {
            *pending = PendingReceiveLimit::new(pending.offered);
        }
        self.keys = ReceiveKeys::Epoch(TrafficOpener::new(
            provider,
            secret,
            receive_inner_limit,
            limits,
        )?);
        self.core = inbound_activate_protection(self.core);
        Ok(())
    }

    pub fn install_traffic(
        &mut self,
        provider: alloc::boxed::Box<dyn TrafficKeyProvider>,
        secret: &[u8],
        receive_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<(), Error> {
        if self.core.terminal {
            return Err(Error::InvalidState);
        }
        self.keys = ReceiveKeys::Epoch(TrafficOpener::new(
            provider,
            secret,
            receive_inner_limit,
            limits,
        )?);
        self.core = inbound_activate_protection(self.core);
        Ok(())
    }

    pub fn tighten_receive_inner_limit(&mut self, limit: Limit) -> Result<(), Error> {
        match &mut self.keys {
            ReceiveKeys::Plaintext => Ok(()),
            ReceiveKeys::Epoch(opener) => opener.tighten_receive_inner_limit(limit),
        }
    }

    pub fn begin_receive_limit_offer(&mut self, limit: Limit) {
        self.pending_receive_limit = Some(PendingReceiveLimit::new(limit));
    }

    pub fn resolve_receive_limit_offer(
        &mut self,
        negotiated: bool,
    ) -> Result<Option<Limit>, Error> {
        let Some(pending) = self.pending_receive_limit.take() else {
            return if negotiated {
                Err(Error::InvalidState)
            } else {
                Ok(None)
            };
        };
        pending.resolve(negotiated)
    }

    pub fn advance_after_key_update(
        &mut self,
        reassembler: &mut HandshakeReassembler,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        if self.core.terminal {
            return Err(Error::InvalidState);
        }
        let result = match &mut self.keys {
            ReceiveKeys::Epoch(opener) => {
                opener.advance_after_reassembled_key_update(reassembler, request)
            }
            _ => Err(Error::InvalidState),
        };
        if result.is_err() {
            self.core = inbound_fail(self.core);
        }
        result
    }

    pub fn open_record(
        &mut self,
        mut record: OwnedRecord,
        handshake_active: bool,
        disposition: ReceiveDisposition,
    ) -> Result<Option<OwnedPlainRecord>, Error> {
        if disposition == ReceiveDisposition::DiscardAfterClose {
            return Ok(None);
        }

        let classified = inbound_classify_record(self.core, record.header, record.payload.len());
        self.core = classified.state;
        let kind = classified.result?;
        let want_close_before_decrypt = kind == InboundRecordKind::Protected
            && self.sequence() == 0xffff_ffff_ffff_0000;

        let (content_type, content_len, legacy_version) = match kind {
            InboundRecordKind::Plaintext => {
                let content_type = ContentType::from_wire(record.header.content_type)
                    .ok_or_else(|| self.fail(Error::UnexpectedMessage))?;
                (content_type, record.payload.len(), record.header.legacy_version)
            }
            InboundRecordKind::Protected => {
                let opened = match &mut self.keys {
                    ReceiveKeys::Epoch(opener) => {
                        opener.open(record.header, &mut record.payload)
                    }
                    ReceiveKeys::Plaintext => Err(Error::InvalidState),
                }
                .map_err(|error| self.fail(error))?;
                if let Some(pending) = self.pending_receive_limit.as_mut() {
                    *pending = pending.observe(opened.inner_len);
                }
                (opened.content_type, opened.content_len, 0x0304)
            }
        };

        let completed = inbound_complete_record(
            self.core,
            kind,
            content_type,
            content_len,
            handshake_active,
        );
        self.core = completed.state;
        completed.result?;
        record.payload.truncate(content_len);
        Ok(Some(OwnedPlainRecord {
            content_type,
            legacy_version,
            payload: record.payload,
            protected: kind == InboundRecordKind::Protected,
            want_close_before_decrypt,
        }))
    }

    pub fn fail(&mut self, error: Error) -> Error {
        self.core = inbound_fail(self.core);
        error
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;
    use crate::{Aead, ProviderError, RecordHeader, UsageLimits};

    struct CountingAead {
        calls: usize,
    }

    struct TestProvider;

    impl TrafficKeyProvider for TestProvider {
        fn hash_len(&self) -> usize {
            1
        }

        fn key_len(&self) -> usize {
            1
        }

        fn expand(
            &self,
            _secret: &[u8],
            _label: crate::HkdfLabel<'_>,
            output: &mut [u8],
        ) -> Result<(), ProviderError> {
            output.fill(0);
            Ok(())
        }

        fn aead(
            &self,
            _key: &[u8],
        ) -> Result<alloc::boxed::Box<dyn Aead>, ProviderError> {
            Ok(Box::new(CountingAead { calls: 0 }))
        }
    }

    impl Aead for CountingAead {
        fn tag_len(&self) -> usize {
            1
        }

        fn seal(
            &mut self,
            _nonce: &[u8; 12],
            _aad: &[u8; 5],
            _payload: &mut Vec<u8>,
        ) -> Result<(), ProviderError> {
            unreachable!()
        }

        fn open(
            &mut self,
            _nonce: &[u8; 12],
            _aad: &[u8; 5],
            payload: &mut [u8],
        ) -> Result<usize, ProviderError> {
            self.calls += 1;
            Ok(payload.len() - 1)
        }
    }

    fn limits() -> AeadLimits {
        AeadLimits::new(UsageLimits::new(8, 100_000, 1), 1)
    }

    #[test]
    fn protected_outer_type_failure_is_terminal_before_provider() {
        let mut receiver = RecordReceiver::new();
        receiver
            .install_handshake(
                Box::new(TestProvider),
                &[0],
                Limit::rfc8446(),
                limits(),
            )
            .unwrap();
        let bad = OwnedRecord {
            header: RecordHeader {
                content_type: ContentType::Handshake as u8,
                legacy_version: 0x0303,
                length: 1,
            },
            payload: vec![0],
        };
        assert_eq!(
            receiver.open_record(bad, false, ReceiveDisposition::Process),
            Err(Error::UnexpectedMessage)
        );
        assert!(receiver.is_terminal());
    }
}
