use alloc::boxed::Box;
use core::cmp::min;

use crate::ContentType;
use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};
use verus_tls13_record::{DirectionalLimits, ProviderLimits, TrafficEpoch, UsageError};

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
    write_usage: TrafficEpoch,
    read_usage: TrafficEpoch,
    directional_limits: DirectionalLimits,
    write_selected_tls13: bool,
    read_selected_tls13: bool,
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
            write_usage: TrafficEpoch::new(),
            read_usage: TrafficEpoch::new(),
            directional_limits: DirectionalLimits::default(),
            write_selected_tls13: false,
            read_selected_tls13: false,
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

        if self.read_selected_tls13 && encr.typ != ContentType::ApplicationData {
            return Err(Error::DecryptError);
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = self.read_usage.sequence() == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        let permit = if self.read_selected_tls13 {
            self.read_usage
                .permit_open(
                    encrypted_len,
                    self.directional_limits
                        .receive_inner_limit,
                )
                .map_err(map_open_usage_error)?
        } else {
            self.read_usage
                .permit_legacy_open(encrypted_len)
                .map_err(map_open_usage_error)?
        };
        match self
            .message_decrypter
            .decrypt(encr, permit.sequence)
        {
            Ok(plaintext) => {
                self.read_usage
                    .commit_open(permit)
                    .map_err(|_| Error::DecryptError)?;
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
            Err(err) => {
                let _ = self.read_usage.fail_open(permit);
                Err(err)
            }
        }
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<OutboundOpaqueMessage, Error> {
        if self.encrypt_state != DirectionState::Active {
            return Err(Error::EncryptError);
        }
        let ciphertext_len = self
            .message_encrypter
            .encrypted_payload_len(plain.payload.len());
        let sequence = if self.write_selected_tls13 {
            let inner_len = plain
                .payload
                .len()
                .checked_add(1)
                .ok_or(Error::EncryptError)?;
            match self.write_usage.issue_seal(
                inner_len,
                ciphertext_len,
                self.directional_limits.send_inner_limit,
            ) {
                Ok(sequence) => sequence,
                Err(_) => {
                    self.write_usage.fail_seal();
                    return Err(Error::EncryptError);
                }
            }
        } else {
            match self
                .write_usage
                .issue_legacy_seal(ciphertext_len)
            {
                Ok(sequence) => sequence,
                Err(_) => return Err(Error::EncryptError),
            }
        };
        match self
            .message_encrypter
            .encrypt(plain, sequence)
        {
            Ok(message) => Ok(message),
            Err(error) => {
                if self.write_selected_tls13 {
                    self.write_usage.fail_seal();
                }
                Err(error)
            }
        }
    }

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    #[cfg(feature = "tls12")]
    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.message_encrypter = cipher;
        let _ = self
            .write_usage
            .prepare(ProviderLimits::legacy(min(SEQ_SOFT_LIMIT, max_messages), 0));
        self.write_selected_tls13 = false;
        self.encrypt_state = DirectionState::Prepared;
    }

    pub(crate) fn prepare_tls13_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        provider_limits: ProviderLimits,
        selected_aws_lc_profile: bool,
    ) {
        let limits =
            provider_limits.with_max_records(min(SEQ_SOFT_LIMIT, provider_limits.max_records));
        self.message_encrypter = cipher;
        let _ = self.write_usage.prepare(limits);
        self.write_selected_tls13 = selected_aws_lc_profile;
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
        let _ = self
            .read_usage
            .prepare(ProviderLimits::legacy(u64::MAX - 1, 0));
        self.read_selected_tls13 = false;
        self.decrypt_state = DirectionState::Prepared;
    }

    pub(crate) fn prepare_tls13_message_decrypter(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        provider_limits: ProviderLimits,
        selected_aws_lc_profile: bool,
    ) {
        self.message_decrypter = cipher;
        let _ = self.read_usage.prepare(provider_limits);
        self.read_selected_tls13 = selected_aws_lc_profile;
        self.decrypt_state = DirectionState::Prepared;
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        let _ = self.write_usage.activate();
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        let _ = self.read_usage.activate();
        self.decrypt_state = DirectionState::Active;
    }

    pub(crate) fn set_tls13_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        provider_limits: ProviderLimits,
        selected_aws_lc_profile: bool,
    ) {
        self.prepare_tls13_message_encrypter(cipher, provider_limits, selected_aws_lc_profile);
        self.start_encrypting();
    }

    pub(crate) fn set_tls13_message_decrypter(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        provider_limits: ProviderLimits,
        selected_aws_lc_profile: bool,
    ) {
        self.prepare_tls13_message_decrypter(cipher, provider_limits, selected_aws_lc_profile);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    pub(crate) fn set_directional_limits(&mut self, limits: DirectionalLimits) {
        self.directional_limits = limits;
    }

    pub(crate) fn terminate(&mut self) {
        self.write_usage.terminate();
        self.read_usage.terminate();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_tls13_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        provider_limits: ProviderLimits,
        selected_aws_lc_profile: bool,
        max_length: usize,
    ) {
        self.prepare_tls13_message_decrypter(cipher, provider_limits, selected_aws_lc_profile);
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
        let records = self
            .write_usage
            .records()
            .saturating_add(add);
        let max_records = self.write_usage.max_records();
        if records >= max_records || self.write_usage.sequence() >= SEQ_HARD_LIMIT {
            PreEncryptAction::Refuse
        } else if records.saturating_add(1) >= max_records
            || (self.write_selected_tls13 && records.saturating_add(2) >= max_records)
            || self.write_usage.sequence() == SEQ_SOFT_LIMIT
        {
            PreEncryptAction::RefreshOrClose
        } else {
            PreEncryptAction::Nothing
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    /// Whether an active inbound epoch accepts selected-profile protected records.
    pub(crate) fn accepts_selected_tls13_protected_records(&self) -> bool {
        self.read_selected_tls13 && self.decrypt_state == DirectionState::Active
    }

    /// Whether either traffic direction uses the selected AWS-LC TLS 1.3 profile.
    pub(crate) fn uses_selected_tls13(&self) -> bool {
        self.write_selected_tls13 || self.read_selected_tls13
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_usage.sequence()
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_usage.sequence()
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
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

fn map_open_usage_error(error: UsageError) -> Error {
    match error {
        UsageError::InvalidLength | UsageError::DirectionalLimit => Error::PeerSentOversizedRecord,
        _ => Error::DecryptError,
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
    use super::*;

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
        assert_eq!(record_layer.read_usage.sequence(), 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.read_usage.sequence(), 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_usage.sequence(), 0);
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
        assert_eq!(record_layer.read_usage.sequence(), 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_usage.sequence(), 0);
        assert!(record_layer.has_decrypted());
    }

    #[test]
    fn selected_trial_decryption_uses_an_active_selected_read_epoch() {
        use crate::{ContentType, ProtocolVersion};
        use verus_tls13_record::AwsLcSuite;

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

        let mut record_layer = RecordLayer::new();
        assert!(!record_layer.accepts_selected_tls13_protected_records());

        record_layer.set_tls13_message_decrypter_with_trial_decryption(
            Box::new(PassThroughDecrypter),
            ProviderLimits::aws_lc(AwsLcSuite::Aes128GcmSha256),
            true,
            1024,
        );

        assert!(record_layer.accepts_selected_tls13_protected_records());
        assert!(record_layer.read_selected_tls13);
        assert_eq!(record_layer.trial_decryption_len, Some(1024));
        assert!(
            record_layer
                .decrypt_incoming(InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut [0u8; 17],
                ))
                .is_ok()
        );
    }
}
