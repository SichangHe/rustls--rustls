use alloc::boxed::Box;

use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::{aead, hkdf, hmac};

use crate::crypto;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use crate::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::message::{
    InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
};
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls13::Tls13CipherSuite;

// These private component objects, rather than caller-provided provider bounds,
// identify the AWS-LC TLS 1.3 record profile.  A copied suite retains the same
// adapter identity while a different AEAD or HKDF implementation cannot opt in.
static AWS_LC_HKDF_SHA256: AwsLcHkdf = AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256);
static AWS_LC_HKDF_SHA384: AwsLcHkdf = AwsLcHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384);
static AWS_LC_CHACHA20_POLY1305: Chacha20Poly1305Aead =
    Chacha20Poly1305Aead(AeadAlgorithm(&aead::CHACHA20_POLY1305));
static AWS_LC_AES_256_GCM: Aes256GcmAead = Aes256GcmAead(AeadAlgorithm(&aead::AES_256_GCM));
static AWS_LC_AES_128_GCM: Aes128GcmAead = Aes128GcmAead(AeadAlgorithm(&aead::AES_128_GCM));

fn same_aead_adapter(
    left: &'static dyn Tls13AeadAlgorithm,
    right: &'static dyn Tls13AeadAlgorithm,
) -> bool {
    let left: *const dyn Tls13AeadAlgorithm = left;
    let right: *const dyn Tls13AeadAlgorithm = right;
    core::ptr::eq(left.cast::<()>(), right.cast::<()>())
}

fn same_hkdf_adapter(left: &'static dyn Hkdf, right: &'static dyn Hkdf) -> bool {
    let left: *const dyn Hkdf = left;
    let right: *const dyn Hkdf = right;
    core::ptr::eq(left.cast::<()>(), right.cast::<()>())
}

pub(crate) fn is_selected_tls13_suite(suite: &Tls13CipherSuite) -> bool {
    // Trait-object vtables can be duplicated across dependent crate builds, so
    // selection compares the adapter data addresses and intentionally ignores
    // their metadata.
    (same_aead_adapter(suite.aead_alg, &AWS_LC_AES_128_GCM)
        && same_hkdf_adapter(suite.hkdf_provider, &AWS_LC_HKDF_SHA256))
        || (same_aead_adapter(suite.aead_alg, &AWS_LC_AES_256_GCM)
            && same_hkdf_adapter(suite.hkdf_provider, &AWS_LC_HKDF_SHA384))
        || (same_aead_adapter(suite.aead_alg, &AWS_LC_CHACHA20_POLY1305)
            && same_hkdf_adapter(suite.hkdf_provider, &AWS_LC_HKDF_SHA256))
}

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        // ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &AWS_LC_HKDF_SHA256,
    aead_alg: &AWS_LC_CHACHA20_POLY1305,
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::CHACHA20_POLY1305,
        header_alg: &aead::quic::CHACHA20,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        confidentiality_limit: u64::MAX,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_256_GCM_SHA384_INTERNAL);

pub(crate) static TLS13_AES_256_GCM_SHA384_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &AWS_LC_HKDF_SHA384,
    aead_alg: &AWS_LC_AES_256_GCM,
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_256_GCM,
        header_alg: &aead::quic::AES_256,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &AWS_LC_HKDF_SHA256,
    aead_alg: &AWS_LC_AES_128_GCM,
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_128_GCM,
        header_alg: &aead::quic::AES_128,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(AeadMessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(AeadMessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn record_limits(&self) -> verus_tls13_record::ProviderLimits {
        verus_tls13_record::ProviderLimits::aws_lc(
            verus_tls13_record::AwsLcSuite::Chacha20Poly1305Sha256,
        )
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> bool {
        false // not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn record_limits(&self) -> verus_tls13_record::ProviderLimits {
        verus_tls13_record::ProviderLimits::aws_lc(verus_tls13_record::AwsLcSuite::Aes256GcmSha384)
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn record_limits(&self) -> verus_tls13_record::ProviderLimits {
        verus_tls13_record::ProviderLimits::aws_lc(verus_tls13_record::AwsLcSuite::Aes128GcmSha256)
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    // using aead::TlsRecordSealingKey
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(GcmMessageEncrypter {
            enc_key: aead::TlsRecordSealingKey::new(
                self.0,
                aead::TlsProtocolId::TLS13,
                key.as_ref(),
            )
            .unwrap(),
            iv,
        })
    }

    // using aead::TlsRecordOpeningKey
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(GcmMessageDecrypter {
            dec_key: aead::TlsRecordOpeningKey::new(
                self.0,
                aead::TlsProtocolId::TLS13,
                key.as_ref(),
            )
            .unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct AeadMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct AeadMessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for AeadMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(
            verus_tls13_record::protected_header(total_len).map_err(|_| Error::EncryptError)?,
        );
        encode_inner(&mut payload, &msg)?;

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

impl MessageDecrypter for AeadMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let aad = received_aad(&msg)?;
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(aad);
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        decode_inner(msg, plain_len)
    }
}

struct GcmMessageEncrypter {
    enc_key: aead::TlsRecordSealingKey,
    iv: Iv,
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(
            verus_tls13_record::protected_header(total_len).map_err(|_| Error::EncryptError)?,
        );
        encode_inner(&mut payload, &msg)?;

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

struct GcmMessageDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
    iv: Iv,
}

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let aad = received_aad(&msg)?;
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(aad);
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        decode_inner(msg, plain_len)
    }
}

fn received_aad(msg: &InboundOpaqueMessage<'_>) -> Result<[u8; 5], Error> {
    let version = msg.version.to_array();
    verus_tls13_record::received_protected_header(
        msg.typ.to_array()[0],
        u16::from_be_bytes(version),
        msg.payload.len(),
    )
    .map_err(|_| Error::DecryptError)
}

fn encode_inner(
    payload: &mut PrefixedPayload,
    msg: &OutboundPlainMessage<'_>,
) -> Result<(), Error> {
    let content_len = msg.payload.len();
    payload.extend_from_chunks(&msg.payload);
    payload.extend_from_slice(&[0]);
    verus_tls13_record::encode_inner(payload.as_mut(), content_len, msg.typ.to_array()[0])
        .map_err(|_| Error::EncryptError)?;
    debug_assert_eq!(payload.as_ref()[content_len], msg.typ.to_array()[0]);
    Ok(())
}

fn decode_inner<'a>(
    mut msg: InboundOpaqueMessage<'a>,
    plain_len: usize,
) -> Result<InboundPlainMessage<'a>, Error> {
    msg.payload.truncate(plain_len);
    let decoded = verus_tls13_record::decode_inner(&msg.payload).map_err(|error| match error {
        verus_tls13_record::InnerError::MessageTooLarge => Error::PeerSentOversizedRecord,
        _ => PeerMisbehaved::IllegalTlsInnerPlaintext.into(),
    })?;
    msg.typ = ContentType::from(decoded.content_type);
    msg.version = ProtocolVersion::TLSv1_3;
    msg.payload
        .truncate(decoded.content_len);
    Ok(msg.into_plain_message())
}

struct AwsLcHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for AwsLcHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct AwsLcHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for AwsLcHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .unwrap();
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_profile_requires_aws_lc_components() {
        assert!(is_selected_tls13_suite(TLS13_AES_128_GCM_SHA256_INTERNAL));
        assert!(is_selected_tls13_suite(TLS13_AES_256_GCM_SHA384_INTERNAL));
        assert!(is_selected_tls13_suite(
            TLS13_CHACHA20_POLY1305_SHA256_INTERNAL
        ));

        let copied = Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &crypto::aws_lc_rs::hash::SHA256,
                confidentiality_limit: 1024,
            },
            hkdf_provider: TLS13_AES_128_GCM_SHA256_INTERNAL.hkdf_provider,
            aead_alg: TLS13_AES_128_GCM_SHA256_INTERNAL.aead_alg,
            quic: TLS13_AES_128_GCM_SHA256_INTERNAL.quic,
        };
        assert!(is_selected_tls13_suite(&copied));

        let non_selected = Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &crypto::aws_lc_rs::hash::SHA256,
                confidentiality_limit: 1 << 24,
            },
            hkdf_provider: &AWS_LC_HKDF_SHA384,
            aead_alg: &AWS_LC_AES_128_GCM,
            quic: TLS13_AES_128_GCM_SHA256_INTERNAL.quic,
        };
        assert!(!is_selected_tls13_suite(&non_selected));
    }
}
