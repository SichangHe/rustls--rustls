use alloc::boxed::Box;
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::verified::{
    ContentType, Error, Limit, MAX_CIPHERTEXT, NONCE_LEN, RecordHeader, Usage, UsageLimits,
    checked_inner_len, decode_inner, make_nonce, validate_protected_header,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderError;

/// Primitive-only AEAD contract. The engine supplies the complete nonce, AAD,
/// and in-place payload. Implementations must not interpret TLS.
pub trait Aead: Send + Sync {
    fn tag_len(&self) -> usize;

    fn seal(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8; 5],
        payload: &mut Vec<u8>,
    ) -> Result<(), ProviderError>;

    fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8; 5],
        payload: &mut [u8],
    ) -> Result<usize, ProviderError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadLimits {
    pub usage: UsageLimits,
    pub max_expansion: usize,
}

impl AeadLimits {
    pub const fn new(usage: UsageLimits, max_expansion: usize) -> Self {
        Self {
            usage,
            max_expansion,
        }
    }

    /// Accept caller policy only when it tightens every provider-declared
    /// bound. This never allows a caller to widen a suite's safety contract.
    pub fn tighten(self, requested: Self) -> Result<Self, Error> {
        if requested.usage.max_records > self.usage.max_records
            || requested.usage.max_bytes > self.usage.max_bytes
            || requested.usage.max_failed_opens > self.usage.max_failed_opens
            || requested.max_expansion > self.max_expansion
        {
            return Err(Error::ProviderContract);
        }
        Ok(requested)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProtectedRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

impl ProtectedRecord {
    pub fn encode(self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(5 + self.payload.len());
        wire.extend_from_slice(&self.header.encode());
        wire.extend_from_slice(&self.payload);
        wire
    }
}

pub struct Sealer {
    aead: Box<dyn Aead>,
    tag_len: usize,
    iv: [u8; NONCE_LEN],
    send_inner_limit: Limit,
    limits: AeadLimits,
    usage: Usage,
    terminal: bool,
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreSealAction {
    Ready,
    RefreshOrClose,
    Refuse,
}

impl Sealer {
    pub fn new(
        aead: Box<dyn Aead>,
        iv: [u8; NONCE_LEN],
        send_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<Self, Error> {
        let tag_len = aead.tag_len();
        if tag_len == 0 || tag_len > limits.max_expansion || limits.usage.max_records == 0 {
            return Err(Error::ProviderContract);
        }
        Ok(Self {
            aead,
            tag_len,
            iv,
            send_inner_limit,
            limits,
            usage: Usage::default(),
            terminal: false,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.usage.sequence
    }

    pub fn send_inner_limit(&self) -> Limit {
        self.send_inner_limit
    }

    pub fn tighten_send_inner_limit(&mut self, limit: Limit) -> Result<(), Error> {
        if limit.get() > self.send_inner_limit.get() {
            return Err(Error::IllegalParameter);
        }
        self.send_inner_limit = limit;
        Ok(())
    }

    pub fn pre_seal_action(&self, additional_records: u64) -> PreSealAction {
        if self.terminal {
            return PreSealAction::Refuse;
        }
        match self.usage.records.checked_add(additional_records) {
            Some(next) if next < self.limits.usage.max_records => PreSealAction::Ready,
            Some(next) if next == self.limits.usage.max_records => {
                PreSealAction::RefreshOrClose
            }
            _ => PreSealAction::Refuse,
        }
    }

    pub fn encrypted_payload_len(&self, content_len: usize, padding_len: usize) -> Option<usize> {
        if self.terminal {
            return None;
        }
        checked_inner_len(content_len, padding_len, self.send_inner_limit)
            .ok()?
            .checked_add(self.tag_len)
    }

    pub fn seal(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        padding_len: usize,
    ) -> Result<ProtectedRecord, Error> {
        let result = self.seal_inner(content_type, content, padding_len);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn seal_inner(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        padding_len: usize,
    ) -> Result<ProtectedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        if content_type == ContentType::Handshake && content.is_empty() {
            return Err(Error::DecodeError);
        }
        let inner_len = checked_inner_len(content.len(), padding_len, self.send_inner_limit)?;
        let expected_len = inner_len
            .checked_add(self.tag_len)
            .ok_or(Error::RecordOverflow)?;
        if expected_len > MAX_CIPHERTEXT
            || self.tag_len > self.limits.max_expansion
            || !self.usage.permits(expected_len, self.limits.usage)
        {
            return Err(Error::ProviderExhausted);
        }
        let length = u16::try_from(expected_len).map_err(|_| Error::RecordOverflow)?;
        let header = RecordHeader {
            content_type: ContentType::ApplicationData as u8,
            legacy_version: 0x0303,
            length,
        };
        let aad = header.encode();
        let nonce = make_nonce(&self.iv, self.usage.sequence);
        let mut payload = Vec::with_capacity(expected_len);
        payload.extend_from_slice(content);
        payload.push(content_type as u8);
        payload.resize(inner_len, 0);
        self.aead
            .seal(&nonce, &aad, &mut payload)
            .map_err(|_| Error::ProviderContract)?;
        if payload.len() != expected_len {
            return Err(Error::ProviderContract);
        }
        self.usage = self.usage.record_success(expected_len, self.limits.usage);
        Ok(ProtectedRecord { header, payload })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedRecord {
    pub content_type: ContentType,
    pub content_len: usize,
    pub inner_len: usize,
}

pub struct Opener {
    aead: Box<dyn Aead>,
    tag_len: usize,
    iv: [u8; NONCE_LEN],
    receive_inner_limit: Limit,
    limits: AeadLimits,
    usage: Usage,
    terminal: bool,
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl Opener {
    pub fn new(
        aead: Box<dyn Aead>,
        iv: [u8; NONCE_LEN],
        receive_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<Self, Error> {
        let tag_len = aead.tag_len();
        if tag_len == 0 || tag_len > limits.max_expansion || limits.usage.max_records == 0 {
            return Err(Error::ProviderContract);
        }
        Ok(Self {
            aead,
            tag_len,
            iv,
            receive_inner_limit,
            limits,
            usage: Usage::default(),
            terminal: false,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.usage.sequence
    }

    pub fn receive_inner_limit(&self) -> Limit {
        self.receive_inner_limit
    }

    pub fn tighten_receive_inner_limit(&mut self, limit: Limit) -> Result<(), Error> {
        if limit.get() > self.receive_inner_limit.get() {
            return Err(Error::IllegalParameter);
        }
        self.receive_inner_limit = limit;
        Ok(())
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn open(
        &mut self,
        header: RecordHeader,
        payload: &mut [u8],
    ) -> Result<OpenedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        if let Err(error) = validate_protected_header(header) {
            self.terminal = true;
            return Err(error);
        }
        if header.length as usize != payload.len() || payload.len() > MAX_CIPHERTEXT {
            self.terminal = true;
            return Err(Error::RecordOverflow);
        }
        let maximum_ciphertext = (self.receive_inner_limit.get() as usize)
            .checked_add(self.tag_len)
            .ok_or(Error::RecordOverflow)?;
        if payload.len() > maximum_ciphertext {
            self.terminal = true;
            return Err(Error::RecordOverflow);
        }
        if payload.len() < self.tag_len
            || !self.usage.permits(payload.len(), self.limits.usage)
            || self.usage.failed_opens >= self.limits.usage.max_failed_opens
        {
            self.terminal = true;
            return Err(Error::ProviderExhausted);
        }
        let aad = header.encode();
        let nonce = make_nonce(&self.iv, self.usage.sequence);
        let plain_len = match self.aead.open(&nonce, &aad, payload) {
            Ok(length) => length,
            Err(_) => {
                self.usage = self.usage.record_failed_open().unwrap_or(self.usage);
                self.terminal = true;
                return Err(Error::BadRecordMac);
            }
        };
        if plain_len > payload.len() {
            self.terminal = true;
            return Err(Error::ProviderContract);
        }
        let decoded = match decode_inner(&payload[..plain_len], self.receive_inner_limit) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.terminal = true;
                return Err(error);
            }
        };
        self.usage = self.usage.record_success(payload.len(), self.limits.usage);
        Ok(OpenedRecord {
            content_type: decoded.content_type,
            content_len: decoded.content_len,
            inner_len: plain_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct TestAead {
        calls: Arc<AtomicUsize>,
    }

    impl Aead for TestAead {
        fn tag_len(&self) -> usize {
            1
        }

        fn seal(
            &mut self,
            nonce: &[u8; NONCE_LEN],
            aad: &[u8; 5],
            payload: &mut Vec<u8>,
        ) -> Result<(), ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            payload.push(aad[1] ^ aad[2] ^ nonce[11]);
            Ok(())
        }

        fn open(
            &mut self,
            nonce: &[u8; NONCE_LEN],
            aad: &[u8; 5],
            payload: &mut [u8],
        ) -> Result<usize, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (tag, plaintext) = payload.split_last().ok_or(ProviderError)?;
            if *tag != aad[1] ^ aad[2] ^ nonce[11] {
                return Err(ProviderError);
            }
            Ok(plaintext.len())
        }
    }

    fn limits(max_records: u64) -> AeadLimits {
        AeadLimits::new(UsageLimits::new(max_records, 100_000, 1), 1)
    }

    #[test]
    fn only_tighter_caller_limits_are_accepted() {
        let provider = AeadLimits::new(UsageLimits::new(100, 10_000, 2), 16);
        let tighter = AeadLimits::new(UsageLimits::new(10, 1_000, 1), 16);
        assert_eq!(provider.tighten(tighter), Ok(tighter));
        let wider = AeadLimits::new(UsageLimits::new(101, 1_000, 1), 16);
        assert_eq!(provider.tighten(wider), Err(Error::ProviderContract));

        let calls = Arc::new(AtomicUsize::new(0));
        let mut sealer = Sealer::new(
            Box::new(TestAead { calls }),
            [0; NONCE_LEN],
            Limit::rfc8446(),
            limits(2),
        )
        .unwrap();
        let small = Limit::new(64).unwrap();
        assert_eq!(sealer.tighten_send_inner_limit(small), Ok(()));
        assert_eq!(sealer.send_inner_limit(), small);
        assert_eq!(
            sealer.tighten_send_inner_limit(Limit::rfc8446()),
            Err(Error::IllegalParameter)
        );
    }

    #[test]
    fn received_version_bytes_are_authenticated_aad() {
        let seal_calls = Arc::new(AtomicUsize::new(0));
        let open_calls = Arc::new(AtomicUsize::new(0));
        let mut sealer = Sealer::new(
            Box::new(TestAead {
                calls: seal_calls.clone(),
            }),
            [7; NONCE_LEN],
            Limit::rfc8446(),
            limits(4),
        )
        .unwrap();
        let protected = sealer
            .seal(ContentType::ApplicationData, b"hello", 3)
            .unwrap();
        assert_eq!(seal_calls.load(Ordering::SeqCst), 1);

        let mut opener = Opener::new(
            Box::new(TestAead {
                calls: open_calls.clone(),
            }),
            [7; NONCE_LEN],
            Limit::rfc8446(),
            limits(4),
        )
        .unwrap();
        let mut payload = protected.payload;
        let mutated = RecordHeader {
            legacy_version: 0x0302,
            ..protected.header
        };
        assert_eq!(opener.open(mutated, &mut payload), Err(Error::BadRecordMac));
        assert!(opener.is_terminal());
        assert_eq!(open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            opener.open(mutated, &mut payload),
            Err(Error::InvalidState)
        );
        assert_eq!(open_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exhaustion_is_terminal_before_an_extra_provider_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sealer = Sealer::new(
            Box::new(TestAead {
                calls: calls.clone(),
            }),
            [0; NONCE_LEN],
            Limit::rfc8446(),
            limits(1),
        )
        .unwrap();
        sealer
            .seal(ContentType::ApplicationData, b"once", 0)
            .unwrap();
        assert_eq!(
            sealer.seal(ContentType::ApplicationData, b"twice", 0),
            Err(Error::ProviderExhausted)
        );
        assert!(sealer.is_terminal());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wrong_protected_outer_type_never_reaches_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut opener = Opener::new(
            Box::new(TestAead {
                calls: calls.clone(),
            }),
            [0; NONCE_LEN],
            Limit::rfc8446(),
            limits(1),
        )
        .unwrap();
        let header = RecordHeader {
            content_type: ContentType::Handshake as u8,
            legacy_version: 0x0303,
            length: 1,
        };
        assert_eq!(
            opener.open(header, &mut [0]),
            Err(Error::UnexpectedMessage)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
