use alloc::boxed::Box;

use zeroize::Zeroize;

use crate::{
    Aead, AeadLimits, ContentType, Error, HandshakeMilestone, HandshakeReassembler,
    HandshakeTracker, HkdfLabel, KeyUpdateRequest, Limit, OpenedRecord, Opener, PreSealAction,
    ProtectedRecord, ProviderError, RecordHeader, Sealer, iv_label, key_label,
    traffic_update_label,
};

const MAX_SECRET_LEN: usize = 64;
const MAX_KEY_LEN: usize = 32;

/// Primitive provider contract for one negotiated TLS 1.3 cipher suite.
/// TLS labels, traffic-secret state, epochs, and record ordering remain in
/// this crate.
pub trait TrafficKeyProvider: Send + Sync {
    fn hash_len(&self) -> usize;
    fn key_len(&self) -> usize;

    fn expand(
        &self,
        secret: &[u8],
        label: HkdfLabel<'_>,
        output: &mut [u8],
    ) -> Result<(), ProviderError>;

    fn aead(&self, key: &[u8]) -> Result<Box<dyn Aead>, ProviderError>;
}

struct TrafficSecret {
    bytes: [u8; MAX_SECRET_LEN],
    used: usize,
}

impl TrafficSecret {
    fn new(bytes: &[u8], expected_len: usize) -> Result<Self, Error> {
        if expected_len == 0 || expected_len > MAX_SECRET_LEN || bytes.len() != expected_len {
            return Err(Error::ProviderContract);
        }
        let mut secret = Self {
            bytes: [0; MAX_SECRET_LEN],
            used: expected_len,
        };
        secret.bytes[..expected_len].copy_from_slice(bytes);
        Ok(secret)
    }

    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.used.zeroize();
    }
}

struct PreparedEpoch {
    secret: TrafficSecret,
    aead: Box<dyn Aead>,
    iv: [u8; 12],
}

fn prepare_epoch(
    provider: &dyn TrafficKeyProvider,
    secret: TrafficSecret,
) -> Result<PreparedEpoch, Error> {
    let key_len = provider.key_len();
    if key_len == 0 || key_len > MAX_KEY_LEN || provider.hash_len() != secret.used {
        return Err(Error::ProviderContract);
    }

    let mut key = [0u8; MAX_KEY_LEN];
    if provider
        .expand(secret.as_ref(), key_label(key_len)?, &mut key[..key_len])
        .is_err()
    {
        key.zeroize();
        return Err(Error::ProviderContract);
    }
    let mut iv = [0u8; 12];
    if provider
        .expand(secret.as_ref(), iv_label()?, &mut iv)
        .is_err()
    {
        key.zeroize();
        return Err(Error::ProviderContract);
    }
    let aead = provider
        .aead(&key[..key_len])
        .map_err(|_| Error::ProviderContract);
    key.zeroize();
    Ok(PreparedEpoch {
        secret,
        aead: aead?,
        iv,
    })
}

fn prepare_next_epoch(
    provider: &dyn TrafficKeyProvider,
    current: &TrafficSecret,
) -> Result<PreparedEpoch, Error> {
    let hash_len = provider.hash_len();
    if hash_len == 0 || hash_len > MAX_SECRET_LEN {
        return Err(Error::ProviderContract);
    }
    let zeroes = [0; MAX_SECRET_LEN];
    let mut next = TrafficSecret::new(&zeroes[..hash_len], hash_len)?;
    provider
        .expand(
            current.as_ref(),
            traffic_update_label(hash_len)?,
            &mut next.bytes[..hash_len],
        )
        .map_err(|_| Error::ProviderContract)?;
    prepare_epoch(provider, next)
}

/// Sending application-traffic epoch. A KeyUpdate record is sealed under the
/// current epoch before the prepared successor becomes active.
pub struct TrafficSealer {
    provider: Box<dyn TrafficKeyProvider>,
    secret: TrafficSecret,
    epoch: u64,
    sealer: Sealer,
    limits: AeadLimits,
    terminal: bool,
}

impl TrafficSealer {
    pub fn new(
        provider: Box<dyn TrafficKeyProvider>,
        secret: &[u8],
        send_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<Self, Error> {
        let secret = TrafficSecret::new(secret, provider.hash_len())?;
        let prepared = prepare_epoch(provider.as_ref(), secret)?;
        let sealer = Sealer::new(prepared.aead, prepared.iv, send_inner_limit, limits)?;
        Ok(Self {
            provider,
            secret: prepared.secret,
            epoch: 0,
            sealer,
            limits,
            terminal: false,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sequence(&self) -> u64 {
        self.sealer.sequence()
    }

    pub fn current_secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    pub fn send_inner_limit(&self) -> Limit {
        self.sealer.send_inner_limit()
    }

    pub fn tighten_send_inner_limit(&mut self, limit: Limit) -> Result<(), Error> {
        self.sealer.tighten_send_inner_limit(limit)
    }

    /// Reserves the final permitted record for a KeyUpdate.
    pub fn pre_seal_action(&self, additional_records: u64) -> PreSealAction {
        if self.terminal {
            return PreSealAction::Refuse;
        }
        match additional_records.checked_add(2) {
            Some(with_update_reserve) => self.sealer.pre_seal_action(with_update_reserve),
            None => PreSealAction::Refuse,
        }
    }

    pub fn encrypted_payload_len(&self, content_len: usize, padding_len: usize) -> Option<usize> {
        if self.terminal {
            None
        } else {
            self.sealer.encrypted_payload_len(content_len, padding_len)
        }
    }

    pub fn seal(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        padding_len: usize,
    ) -> Result<ProtectedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        let result = self.sealer.seal(content_type, content, padding_len);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    /// Consume the physical record reserved for terminal alert closure.  This
    /// deliberately bypasses the KeyUpdate reserve policy while retaining the
    /// underlying AEAD usage limit.
    pub fn seal_final_alert(&mut self, content: &[u8]) -> Result<ProtectedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        let result = self.sealer.seal(ContentType::Alert, content, 0);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    pub fn seal_key_update(
        &mut self,
        request: KeyUpdateRequest,
    ) -> Result<ProtectedRecord, Error> {
        let result = self.seal_key_update_inner(request);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn seal_key_update_inner(
        &mut self,
        request: KeyUpdateRequest,
    ) -> Result<ProtectedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        let next_epoch = self.epoch.checked_add(1).ok_or(Error::ProviderExhausted)?;
        let prepared = prepare_next_epoch(self.provider.as_ref(), &self.secret)?;
        let record = self.sealer.seal(
            ContentType::Handshake,
            &[24, 0, 0, 1, request as u8],
            0,
        )?;
        let next = Sealer::new(
            prepared.aead,
            prepared.iv,
            self.sealer.send_inner_limit(),
            self.limits,
        )?;
        self.secret = prepared.secret;
        self.epoch = next_epoch;
        self.sealer = next;
        Ok(record)
    }
}

/// Receiving application-traffic epoch. Advancement is allowed only after
/// the caller has authenticated and decoded a complete KeyUpdate message.
pub struct TrafficOpener {
    provider: Box<dyn TrafficKeyProvider>,
    secret: TrafficSecret,
    epoch: u64,
    opener: Opener,
    limits: AeadLimits,
    terminal: bool,
}

impl TrafficOpener {
    pub fn new(
        provider: Box<dyn TrafficKeyProvider>,
        secret: &[u8],
        receive_inner_limit: Limit,
        limits: AeadLimits,
    ) -> Result<Self, Error> {
        let secret = TrafficSecret::new(secret, provider.hash_len())?;
        let prepared = prepare_epoch(provider.as_ref(), secret)?;
        let opener = Opener::new(prepared.aead, prepared.iv, receive_inner_limit, limits)?;
        Ok(Self {
            provider,
            secret: prepared.secret,
            epoch: 0,
            opener,
            limits,
            terminal: false,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sequence(&self) -> u64 {
        self.opener.sequence()
    }

    pub fn current_secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    pub fn receive_inner_limit(&self) -> Limit {
        self.opener.receive_inner_limit()
    }

    pub fn tighten_receive_inner_limit(&mut self, limit: Limit) -> Result<(), Error> {
        self.opener.tighten_receive_inner_limit(limit)
    }

    pub fn open(
        &mut self,
        header: RecordHeader,
        payload: &mut [u8],
    ) -> Result<OpenedRecord, Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        let result = self.opener.open(header, payload);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    pub fn advance_after_key_update(
        &mut self,
        tracker: &mut HandshakeTracker,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        let result = self.advance_inner(request, |expected| tracker.activate_after(expected));
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    pub fn advance_after_reassembled_key_update(
        &mut self,
        reassembler: &mut HandshakeReassembler,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        let result = self.advance_inner(request, |expected| reassembler.activate_after(expected));
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn advance_inner(
        &mut self,
        request: KeyUpdateRequest,
        activate: impl FnOnce(HandshakeMilestone) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::InvalidState);
        }
        activate(HandshakeMilestone::KeyUpdate(request))?;
        let next_epoch = self.epoch.checked_add(1).ok_or(Error::ProviderExhausted)?;
        let prepared = prepare_next_epoch(self.provider.as_ref(), &self.secret)?;
        let next = Opener::new(
            prepared.aead,
            prepared.iv,
            self.opener.receive_inner_limit(),
            self.limits,
        )?;
        self.secret = prepared.secret;
        self.epoch = next_epoch;
        self.opener = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::UsageLimits;

    struct TestProvider {
        dropped_aeads: Arc<AtomicUsize>,
        fail_update: bool,
    }

    impl TrafficKeyProvider for TestProvider {
        fn hash_len(&self) -> usize {
            32
        }

        fn key_len(&self) -> usize {
            16
        }

        fn expand(
            &self,
            secret: &[u8],
            label: HkdfLabel<'_>,
            output: &mut [u8],
        ) -> Result<(), ProviderError> {
            let label_parts = label.parts();
            if self.fail_update && label_parts[3] == b"traffic upd" {
                return Err(ProviderError);
            }
            let discriminator = label_parts[3].iter().fold(0u8, |sum, byte| sum ^ byte);
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = secret[index % secret.len()] ^ discriminator ^ index as u8;
            }
            Ok(())
        }

        fn aead(&self, key: &[u8]) -> Result<Box<dyn Aead>, ProviderError> {
            Ok(Box::new(TestAead {
                key: key[0],
                dropped: self.dropped_aeads.clone(),
            }))
        }
    }

    struct TestAead {
        key: u8,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for TestAead {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Aead for TestAead {
        fn tag_len(&self) -> usize {
            1
        }

        fn seal(
            &mut self,
            nonce: &[u8; 12],
            aad: &[u8; 5],
            payload: &mut Vec<u8>,
        ) -> Result<(), ProviderError> {
            payload.push(self.key ^ nonce[11] ^ aad[4]);
            Ok(())
        }

        fn open(
            &mut self,
            nonce: &[u8; 12],
            aad: &[u8; 5],
            payload: &mut [u8],
        ) -> Result<usize, ProviderError> {
            let (tag, plain) = payload.split_last().ok_or(ProviderError)?;
            if *tag != self.key ^ nonce[11] ^ aad[4] {
                return Err(ProviderError);
            }
            Ok(plain.len())
        }
    }

    fn provider(dropped_aeads: Arc<AtomicUsize>) -> Box<dyn TrafficKeyProvider> {
        Box::new(TestProvider {
            dropped_aeads,
            fail_update: false,
        })
    }

    fn limits(max_records: u64) -> AeadLimits {
        AeadLimits::new(UsageLimits::new(max_records, 100_000, 1), 1)
    }

    #[test]
    fn key_update_is_last_old_epoch_record_and_resets_sequence() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let secret = [7u8; 32];
        let mut sender = TrafficSealer::new(
            provider(dropped.clone()),
            &secret,
            Limit::rfc8446(),
            limits(8),
        )
        .unwrap();
        let mut receiver = TrafficOpener::new(
            provider(dropped.clone()),
            &secret,
            Limit::rfc8446(),
            limits(8),
        )
        .unwrap();

        let update = sender
            .seal_key_update(KeyUpdateRequest::UpdateNotRequested)
            .unwrap();
        assert_eq!(sender.epoch(), 1);
        assert_eq!(sender.sequence(), 0);
        assert!(dropped.load(Ordering::SeqCst) >= 1);

        let mut update_payload = update.payload;
        let opened = receiver.open(update.header, &mut update_payload).unwrap();
        assert_eq!(opened.content_type, ContentType::Handshake);
        assert_eq!(&update_payload[..opened.content_len], &[24, 0, 0, 1, 0]);
        assert_eq!(receiver.epoch(), 0);
        let mut tracker = HandshakeTracker::new();
        tracker
            .observe_record(&update_payload[..opened.content_len])
            .unwrap();
        receiver
            .advance_after_key_update(&mut tracker, KeyUpdateRequest::UpdateNotRequested)
            .unwrap();
        assert_eq!(receiver.epoch(), 1);
        assert_eq!(receiver.sequence(), 0);

        let application = sender
            .seal(ContentType::ApplicationData, b"new epoch", 0)
            .unwrap();
        assert_eq!(sender.sequence(), 1);
        let mut application_payload = application.payload;
        let opened = receiver
            .open(application.header, &mut application_payload)
            .unwrap();
        assert_eq!(opened.content_type, ContentType::ApplicationData);
        assert_eq!(&application_payload[..opened.content_len], b"new epoch");
    }

    #[test]
    fn final_record_is_reserved_for_key_update() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut sender = TrafficSealer::new(
            provider(dropped),
            &[3; 32],
            Limit::rfc8446(),
            limits(3),
        )
        .unwrap();
        assert_eq!(sender.pre_seal_action(0), PreSealAction::Ready);
        sender
            .seal(ContentType::ApplicationData, b"one", 0)
            .unwrap();
        assert_eq!(
            sender.pre_seal_action(0),
            PreSealAction::RefreshOrClose
        );
        sender
            .seal(ContentType::ApplicationData, b"two", 0)
            .unwrap();
        assert_eq!(sender.pre_seal_action(0), PreSealAction::Refuse);
        sender
            .seal_key_update(KeyUpdateRequest::UpdateRequested)
            .unwrap();
        assert_eq!(sender.epoch(), 1);
    }

    #[test]
    fn terminal_alert_can_consume_the_reserved_final_record() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut sender = TrafficSealer::new(
            provider(dropped),
            &[4; 32],
            Limit::rfc8446(),
            limits(3),
        )
        .unwrap();
        sender
            .seal(ContentType::ApplicationData, b"one", 0)
            .unwrap();
        sender
            .seal(ContentType::ApplicationData, b"two", 0)
            .unwrap();
        assert_eq!(sender.pre_seal_action(0), PreSealAction::Refuse);
        sender.seal_final_alert(&[2, 80]).unwrap();
        assert_eq!(sender.sequence(), 3);
        assert_eq!(
            sender.seal_final_alert(&[2, 80]),
            Err(Error::ProviderExhausted)
        );
    }

    #[test]
    fn failed_update_makes_sender_terminal_without_sealing() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let provider = Box::new(TestProvider {
            dropped_aeads: dropped,
            fail_update: true,
        });
        let mut sender = TrafficSealer::new(
            provider,
            &[9; 32],
            Limit::rfc8446(),
            limits(8),
        )
        .unwrap();
        assert_eq!(
            sender.seal_key_update(KeyUpdateRequest::UpdateRequested),
            Err(Error::ProviderContract)
        );
        assert_eq!(
            sender.seal(ContentType::ApplicationData, b"blocked", 0),
            Err(Error::InvalidState)
        );
        assert_eq!(sender.sequence(), 0);
    }

    #[test]
    fn read_epoch_requires_the_exact_one_shot_key_update_boundary() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut receiver = TrafficOpener::new(
            provider(dropped.clone()),
            &[5; 32],
            Limit::rfc8446(),
            limits(8),
        )
        .unwrap();
        let mut missing = HandshakeTracker::new();
        assert_eq!(
            receiver.advance_after_key_update(
                &mut missing,
                KeyUpdateRequest::UpdateNotRequested,
            ),
            Err(Error::InvalidState)
        );
        assert_eq!(receiver.epoch(), 0);

        let mut wrong = TrafficOpener::new(
            provider(dropped),
            &[5; 32],
            Limit::rfc8446(),
            limits(8),
        )
        .unwrap();
        let mut tracker = HandshakeTracker::new();
        tracker.observe_record(&[24, 0, 0, 1, 0]).unwrap();
        assert_eq!(
            wrong.advance_after_key_update(&mut tracker, KeyUpdateRequest::UpdateRequested),
            Err(Error::InvalidState)
        );
        assert_eq!(wrong.epoch(), 0);
    }
}
