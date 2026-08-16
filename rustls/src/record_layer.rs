use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::min;

use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::message::{
    InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage,
};
use crate::ContentType;
#[cfg(test)]
use crate::ProtocolVersion;
use verus_tls13_record::{
    AeadLimits as TlsrecAeadLimits, ContentType as TlsrecContentType, Error as TlsrecError,
    Limit as TlsrecLimit, PreSealAction as TlsrecPreSealAction,
    RecordReceiver as TlsrecRecordReceiver,
    TrafficKeyProvider as TlsrecTrafficKeyProvider, TrafficSealer as TlsrecTrafficSealer,
    UsageLimits as TlsrecUsageLimits,
};

#[derive(PartialEq)]
enum DirectionState {
    /// No keying material.
    Invalid,

    /// Keying material present, but not yet in use.
    Prepared,

    /// Keying material in use.
    Active,
}

/// Record layer that tracks decryption and encryption keys.
pub(crate) struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,
    tlsrec_receiver: TlsrecRecordReceiver,
    tlsrec_traffic_sealer: Option<TlsrecTrafficSealer>,
    write_seq_max: u64,
    write_seq: u64,
    read_seq: u64,
    has_decrypted: bool,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            tlsrec_receiver: TlsrecRecordReceiver::new(),
            tlsrec_traffic_sealer: None,
            write_seq_max: 0,
            write_seq: 0,
            read_seq: 0,
            has_decrypted: false,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            trial_decryption_len: None,
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt(encr, self.read_seq)
        {
            Ok(plaintext) => {
                self.read_seq += 1;
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    pub(crate) fn decrypt_tlsrec_record(
        &mut self,
        record: verus_tls13_record::OwnedRecord,
        handshake_active: bool,
        disposition: verus_tls13_record::ReceiveDisposition,
    ) -> Result<Option<verus_tls13_record::OwnedPlainRecord>, TlsrecError> {
        self.tlsrec_receiver
            .open_record(record, handshake_active, disposition)
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(self.next_pre_encrypt_action() != PreEncryptAction::Refuse);
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter
            .encrypt(plain, seq)
            .unwrap()
    }

    pub(crate) fn encrypt_outgoing_alert(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<OutboundOpaqueMessage, Error> {
        debug_assert_eq!(plain.typ, ContentType::Alert);
        debug_assert!(self.encrypt_state == DirectionState::Active);
        let seq = self.write_seq;
        let encrypted = self.message_encrypter.encrypt(plain, seq)?;
        self.write_seq = self.write_seq.checked_add(1).ok_or(Error::EncryptError)?;
        Ok(encrypted)
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    pub(crate) fn encrypt_tlsrec_wire(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<Vec<u8>, Error> {
        let content_type = tlsrec_content_type(plain.typ)?;
        let sealer = self
            .tlsrec_traffic_sealer
            .as_mut()
            .ok_or(Error::EncryptError)?;
        let protected = sealer
            .seal(content_type, &plain.payload.to_vec(), 0)
            .map_err(|_| Error::EncryptError)?;
        self.write_seq = sealer.sequence();
        Ok(protected.encode())
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    pub(crate) fn encrypt_tlsrec_alert_wire(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<Vec<u8>, Error> {
        if plain.typ != ContentType::Alert {
            return Err(Error::EncryptError);
        }
        let sealer = self
            .tlsrec_traffic_sealer
            .as_mut()
            .ok_or(Error::EncryptError)?;
        let protected = sealer
            .seal_final_alert(&plain.payload.to_vec())
            .map_err(|_| Error::EncryptError)?;
        self.write_seq = sealer.sequence();
        Ok(protected.encode())
    }

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.message_encrypter = cipher;
        self.tlsrec_traffic_sealer = None;
        self.write_seq = 0;
        self.write_seq_max = min(SEQ_SOFT_LIMIT, max_messages);
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
        self.read_seq = 0;
        self.decrypt_state = DirectionState::Prepared;
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        self.decrypt_state = DirectionState::Active;
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.prepare_message_encrypter(cipher, max_messages);
        self.start_encrypting();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    pub(crate) fn set_tlsrec_encrypter(
        &mut self,
        provider: Box<dyn TlsrecTrafficKeyProvider>,
        secret: &[u8],
        max_messages: u64,
        send_inner_limit: TlsrecLimit,
    ) {
        self.tlsrec_traffic_sealer = Some(
            TlsrecTrafficSealer::new(
                provider,
                secret,
                send_inner_limit,
                tlsrec_aead_limits(max_messages),
            )
            .expect("rustls supplied a valid TLS 1.3 traffic-key contract"),
        );
        self.write_seq = 0;
        self.write_seq_max = min(SEQ_SOFT_LIMIT, max_messages);
        self.encrypt_state = DirectionState::Active;
    }

    pub(crate) fn set_tlsrec_decrypter(
        &mut self,
        provider: Box<dyn TlsrecTrafficKeyProvider>,
        secret: &[u8],
        max_messages: u64,
        receive_inner_limit: TlsrecLimit,
    ) {
        self.tlsrec_receiver
            .install_handshake(
                provider,
                secret,
                receive_inner_limit,
                tlsrec_aead_limits(max_messages),
            )
            .expect("rustls supplied a valid TLS 1.3 AEAD contract");
        self.decrypt_state = DirectionState::Active;
        self.trial_decryption_len = None;
    }

    pub(crate) fn set_tlsrec_application_encrypter(
        &mut self,
        provider: Box<dyn TlsrecTrafficKeyProvider>,
        secret: &[u8],
        max_messages: u64,
        send_inner_limit: TlsrecLimit,
    ) {
        self.tlsrec_traffic_sealer = Some(
            TlsrecTrafficSealer::new(
                provider,
                secret,
                send_inner_limit,
                tlsrec_aead_limits(max_messages),
            )
            .expect("rustls supplied a valid TLS 1.3 traffic-key contract"),
        );
        self.write_seq = 0;
        self.write_seq_max = min(SEQ_SOFT_LIMIT, max_messages);
        self.encrypt_state = DirectionState::Active;
    }

    pub(crate) fn set_tlsrec_application_decrypter(
        &mut self,
        provider: Box<dyn TlsrecTrafficKeyProvider>,
        secret: &[u8],
        max_messages: u64,
        receive_inner_limit: TlsrecLimit,
    ) {
        self.tlsrec_receiver
            .install_traffic(
                provider,
                secret,
                receive_inner_limit,
                tlsrec_aead_limits(max_messages),
            )
            .expect("rustls supplied a valid TLS 1.3 traffic-key contract");
        self.decrypt_state = DirectionState::Active;
        self.trial_decryption_len = None;
    }

    pub(crate) fn seal_tlsrec_key_update(
        &mut self,
        request: verus_tls13_record::KeyUpdateRequest,
    ) -> Result<Vec<u8>, Error> {
        let sealer = self
            .tlsrec_traffic_sealer
            .as_mut()
            .ok_or_else(|| Error::General("TLS 1.3 traffic sender is unavailable".into()))?;
        let protected = sealer
            .seal_key_update(request)
            .map_err(|_| Error::General("TLS 1.3 traffic sender failed KeyUpdate".into()))?;
        self.write_seq = sealer.sequence();
        Ok(protected.encode())
    }

    pub(crate) fn advance_tlsrec_read_epoch(
        &mut self,
        reassembler: &mut verus_tls13_record::HandshakeReassembler,
        request: verus_tls13_record::KeyUpdateRequest,
    ) -> Result<(), Error> {
        self.tlsrec_receiver
            .advance_after_key_update(reassembler, request)
            .map_err(|_| Error::General("TLS 1.3 traffic receiver failed KeyUpdate".into()))
    }

    pub(crate) fn tlsrec_write_secret(&self) -> Option<&[u8]> {
        self.tlsrec_traffic_sealer
            .as_ref()
            .map(TlsrecTrafficSealer::current_secret)
    }

    pub(crate) fn tlsrec_read_secret(&self) -> Option<&[u8]> {
        self.tlsrec_receiver.traffic_secret()
    }

    pub(crate) fn tighten_tlsrec_limits(
        &mut self,
        send_inner_limit: TlsrecLimit,
        receive_inner_limit: TlsrecLimit,
    ) -> Result<(), TlsrecError> {
        if let Some(sealer) = self.tlsrec_traffic_sealer.as_mut() {
            sealer.tighten_send_inner_limit(send_inner_limit)?;
        }
        self.tlsrec_receiver
            .tighten_receive_inner_limit(receive_inner_limit)?;
        Ok(())
    }

    pub(crate) fn begin_tlsrec_receive_limit_offer(&mut self, limit: TlsrecLimit) {
        self.tlsrec_receiver.begin_receive_limit_offer(limit);
    }

    pub(crate) fn resolve_tlsrec_receive_limit_offer(
        &mut self,
        negotiated: bool,
    ) -> Result<Option<TlsrecLimit>, TlsrecError> {
        self.tlsrec_receiver
            .resolve_receive_limit_offer(negotiated)
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    pub(crate) fn next_pre_encrypt_action(&self) -> PreEncryptAction {
        self.pre_encrypt_action(0)
    }

    /// Return a remedial action when we are near to encrypting too many messages.
    ///
    /// `add` is added to the current sequence number.  `add` as `0` means
    /// "the next message processed by `encrypt_outgoing`"
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> PreEncryptAction {
        if let Some(sealer) = self.tlsrec_traffic_sealer.as_ref() {
            return match sealer.pre_seal_action(add) {
                TlsrecPreSealAction::Ready => PreEncryptAction::Nothing,
                TlsrecPreSealAction::RefreshOrClose => PreEncryptAction::RefreshOrClose,
                TlsrecPreSealAction::Refuse => PreEncryptAction::Refuse,
            };
        }
        match self.write_seq.saturating_add(add) {
            v if v == self.write_seq_max => PreEncryptAction::RefreshOrClose,
            SEQ_HARD_LIMIT.. => PreEncryptAction::Refuse,
            _ => PreEncryptAction::Nothing,
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted || self.tlsrec_receiver.has_decrypted()
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.tlsrec_traffic_sealer
            .as_ref()
            .map(TlsrecTrafficSealer::sequence)
            .unwrap_or(self.write_seq)
    }

    pub(crate) fn read_seq(&self) -> u64 {
        if self.tlsrec_receiver.is_protected() {
            self.tlsrec_receiver.sequence()
        } else {
            self.read_seq
        }
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        if let Some(sealer) = self.tlsrec_traffic_sealer.as_ref() {
            return sealer
                .encrypted_payload_len(payload_len, 0)
                .unwrap_or(usize::MAX);
        }
        self.message_encrypter
            .encrypted_payload_len(payload_len)
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }
}

fn tlsrec_aead_limits(max_messages: u64) -> TlsrecAeadLimits {
    let max_records_by_bytes = u64::MAX / verus_tls13_record::MAX_CIPHERTEXT as u64;
    let max_records = min(max_messages, max_records_by_bytes);
    let max_bytes = max_records * verus_tls13_record::MAX_CIPHERTEXT as u64;
    TlsrecAeadLimits::new(TlsrecUsageLimits::new(max_records, max_bytes, 1), 16)
}

fn tlsrec_content_type(content_type: ContentType) -> Result<TlsrecContentType, Error> {
    match content_type {
        ContentType::ChangeCipherSpec => Ok(TlsrecContentType::ChangeCipherSpec),
        ContentType::Alert => Ok(TlsrecContentType::Alert),
        ContentType::Handshake => Ok(TlsrecContentType::Handshake),
        ContentType::ApplicationData => Ok(TlsrecContentType::ApplicationData),
        _ => Err(Error::EncryptError),
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: InboundPlainMessage<'a>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PreEncryptAction {
    /// No action is needed before calling `encrypt_outgoing`
    Nothing,

    /// A `key_update` request should be sent ASAP.
    ///
    /// If that is not possible (for example, the connection is TLS1.2), a `close_notify`
    /// alert should be sent instead.
    RefreshOrClose,

    /// Do not call `encrypt_outgoing` further, it will panic rather than
    /// over-use the key.
    Refuse,
}

const SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
const SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    struct PlainInnerAead;

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    impl verus_tls13_record::Aead for PlainInnerAead {
        fn tag_len(&self) -> usize {
            1
        }

        fn seal(
            &mut self,
            _nonce: &[u8; verus_tls13_record::NONCE_LEN],
            _aad: &[u8; 5],
            _payload: &mut Vec<u8>,
        ) -> Result<(), verus_tls13_record::ProviderError> {
            unreachable!("record-layer receive-limit fixture never seals")
        }

        fn open(
            &mut self,
            _nonce: &[u8; verus_tls13_record::NONCE_LEN],
            _aad: &[u8; 5],
            payload: &mut [u8],
        ) -> Result<usize, verus_tls13_record::ProviderError> {
            payload
                .len()
                .checked_sub(1)
                .ok_or(verus_tls13_record::ProviderError)
        }
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    struct PlainInnerProvider;

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    impl TlsrecTrafficKeyProvider for PlainInnerProvider {
        fn hash_len(&self) -> usize {
            1
        }

        fn key_len(&self) -> usize {
            1
        }

        fn expand(
            &self,
            _secret: &[u8],
            _label: verus_tls13_record::HkdfLabel<'_>,
            output: &mut [u8],
        ) -> Result<(), verus_tls13_record::ProviderError> {
            output.fill(0);
            Ok(())
        }

        fn aead(
            &self,
            _key: &[u8],
        ) -> Result<Box<dyn verus_tls13_record::Aead>, verus_tls13_record::ProviderError> {
            Ok(Box::new(PlainInnerAead))
        }
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    fn padded_handshake_record(inner_len: usize) -> Vec<u8> {
        assert!(inner_len >= 2);
        let mut payload = vec![0; inner_len + 1];
        payload[0] = 1;
        payload[1] = ContentType::Handshake.into();
        payload
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    fn open_padded_handshake(record_layer: &mut RecordLayer, inner_len: usize) {
        let payload = padded_handshake_record(inner_len);
        record_layer
            .decrypt_tlsrec_record(
                verus_tls13_record::OwnedRecord {
                    header: verus_tls13_record::RecordHeader {
                        content_type: ContentType::ApplicationData.into(),
                        legacy_version: 0x0303,
                        length: u16::try_from(payload.len()).unwrap(),
                    },
                    payload,
                },
                true,
                verus_tls13_record::ReceiveDisposition::Process,
            )
            .unwrap()
            .unwrap();
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    fn record_layer_with_pending_limit(limit: TlsrecLimit) -> RecordLayer {
        let mut record_layer = RecordLayer::new();
        record_layer.begin_tlsrec_receive_limit_offer(limit);
        record_layer.set_tlsrec_decrypter(
            Box::new(PlainInnerProvider),
            &[0],
            100,
            TlsrecLimit::rfc8446(),
        );
        record_layer
    }

    #[test]
    #[cfg(all(feature = "aws_lc_rs", not(feature = "tls12")))]
    fn pending_receive_limit_observes_every_authenticated_inner_plaintext() {
        let offered = TlsrecLimit::new(64).unwrap();
        let mut echoed = record_layer_with_pending_limit(offered);
        // A small handshake fragment with padding makes the first record's
        // complete TLSInnerPlaintext exceed the offer.  A smaller record then
        // completes the hypothetical fragmented EncryptedExtensions.
        open_padded_handshake(&mut echoed, 65);
        open_padded_handshake(&mut echoed, 40);
        assert_eq!(
            echoed.resolve_tlsrec_receive_limit_offer(true),
            Err(TlsrecError::RecordOverflow)
        );

        let mut omitted = record_layer_with_pending_limit(offered);
        open_padded_handshake(&mut omitted, 65);
        open_padded_handshake(&mut omitted, 40);
        assert_eq!(omitted.resolve_tlsrec_receive_limit_offer(false), Ok(None));
        assert_eq!(
            omitted.resolve_tlsrec_receive_limit_offer(true),
            Err(TlsrecError::InvalidState)
        );

        let mut exact = record_layer_with_pending_limit(offered);
        open_padded_handshake(&mut exact, 64);
        assert_eq!(
            exact.resolve_tlsrec_receive_limit_offer(true),
            Ok(Some(offered))
        );
    }

    #[test]
    fn test_has_decrypted() {
        use crate::{ContentType, ProtocolVersion};

        struct PassThroughDecrypter;
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: InboundOpaqueMessage<'a>,
                _: u64,
            ) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(m.into_plain_message())
            }
        }

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = RecordLayer::new();
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Invalid
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut [0xC0, 0xFF, 0xEE],
            ))
            .unwrap();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
