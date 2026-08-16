use std::boxed::Box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::vec::Vec;

use verus_tls13_record::{
    Aead, AeadLimits, AlertEvent, ContentType, ControlState, Error, Fragmenter,
    HandshakeMilestone, HandshakeTracker, HkdfLabel, KeyUpdateRequest, Limit, NONCE_LEN,
    OwnedRecord, PlaintextSenderState, ProviderError, ReceiveDisposition, RecordBuffer,
    RecordHeader, RecordReceiver, Sealer, TrafficKeyProvider, UsageLimits, MAX_CIPHERTEXT,
    MAX_INNER_PLAINTEXT, MAX_PLAINTEXT, MAX_WIRE, plaintext_send_step,
};

#[derive(Clone)]
struct DeterministicProvider {
    calls: Arc<AtomicUsize>,
}

impl TrafficKeyProvider for DeterministicProvider {
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
        if secret.is_empty() {
            return Err(ProviderError);
        }
        let label_mix = label
            .parts()
            .into_iter()
            .flatten()
            .fold(0u8, |acc, byte| acc.rotate_left(1) ^ *byte);
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = secret[index % secret.len()] ^ label_mix ^ index as u8;
        }
        Ok(())
    }

    fn aead(&self, key: &[u8]) -> Result<Box<dyn Aead>, ProviderError> {
        if key.is_empty() {
            return Err(ProviderError);
        }
        Ok(Box::new(DeterministicAead {
            key: key.to_vec(),
            calls: self.calls.clone(),
        }))
    }
}

struct DeterministicAead {
    key: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl DeterministicAead {
    fn mask(&self, index: usize, nonce: &[u8; NONCE_LEN]) -> u8 {
        self.key[index % self.key.len()] ^ nonce[index % nonce.len()]
    }

    fn tag(&self, nonce: &[u8; NONCE_LEN], aad: &[u8; 5], payload: &[u8]) -> u8 {
        self.key
            .iter()
            .chain(nonce)
            .chain(aad)
            .chain(payload)
            .fold(0x5au8, |acc, byte| acc.rotate_left(1) ^ *byte)
    }
}

impl Aead for DeterministicAead {
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
        for index in 0..payload.len() {
            payload[index] ^= self.mask(index, nonce);
        }
        payload.push(self.tag(nonce, aad, payload));
        Ok(())
    }

    fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8; 5],
        payload: &mut [u8],
    ) -> Result<usize, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (tag, ciphertext) = payload.split_last_mut().ok_or(ProviderError)?;
        if *tag != self.tag(nonce, aad, ciphertext) {
            return Err(ProviderError);
        }
        for index in 0..ciphertext.len() {
            ciphertext[index] ^= self.mask(index, nonce);
        }
        Ok(ciphertext.len())
    }
}

fn provider(calls: &Arc<AtomicUsize>) -> Box<dyn TrafficKeyProvider> {
    Box::new(DeterministicProvider {
        calls: calls.clone(),
    })
}

fn limits(max_records: u64, max_bytes: u64, max_failed_opens: u64) -> AeadLimits {
    AeadLimits::new(
        UsageLimits::new(max_records, max_bytes, max_failed_opens),
        1,
    )
}

fn record_from_wire(wire: &[u8]) -> OwnedRecord {
    let (record, used) = OwnedRecord::decode_prefix(wire).unwrap().unwrap();
    assert_eq!(used, wire.len());
    record
}

#[test]
fn required_length_and_fragment_boundaries() {
    assert_eq!(Limit::new(63), Err(Error::IllegalParameter));
    assert_eq!(Limit::new(64).unwrap().get(), 64);
    assert_eq!(Limit::new(MAX_INNER_PLAINTEXT).unwrap().get(), 16_385);
    assert_eq!(Limit::new(16_386), Err(Error::IllegalParameter));

    let mut fragmenter = Fragmenter::new();
    fragmenter.tighten_peer_inner_limit(Limit::new(64).unwrap());
    for (length, expected) in [
        (0, Vec::new()),
        (1, vec![1]),
        (63, vec![63]),
        (64, vec![63, 1]),
        (MAX_PLAINTEXT, {
            let mut plan = vec![63; 260];
            plan.push(4);
            plan
        }),
        (16_385, {
            let mut plan = vec![63; 260];
            plan.push(5);
            plan
        }),
        (16_386, {
            let mut plan = vec![63; 260];
            plan.push(6);
            plan
        }),
        (MAX_CIPHERTEXT, {
            let mut plan = vec![63; 264];
            plan.push(8);
            plan
        }),
    ] {
        assert_eq!(fragmenter.plan(length).collect::<Vec<_>>(), expected);
    }

    assert_eq!(fragmenter.set_max_wire_size(Some(31)), Err(Error::IllegalParameter));
    assert_eq!(fragmenter.set_max_wire_size(Some(32)), Ok(()));
    assert_eq!(fragmenter.content_limit(), 27);
    assert_eq!(fragmenter.set_max_wire_size(Some(16_390)), Err(Error::IllegalParameter));
}

#[test]
fn every_header_split_coalescing_and_eof_are_bounded() {
    let first = [22, 3, 1, 0, 2, 7, 8];
    let second = [23, 3, 3, 0, 1, 9];
    for split in 0..=first.len() {
        let mut buffer = RecordBuffer::new();
        assert_eq!(buffer.feed(&first[..split]), split);
        if split > 0 && split < first.len() {
            assert!(buffer.next_record().unwrap().is_none());
            assert_eq!(buffer.finish(), Err(Error::Truncated));
        } else if split == 0 {
            assert_eq!(buffer.finish(), Ok(()));
        }
        assert_eq!(buffer.feed(&first[split..]), first.len() - split);
        assert_eq!(buffer.next_record().unwrap().unwrap().payload, [7, 8]);
        assert_eq!(buffer.finish(), Ok(()));
    }

    let mut coalesced = first.to_vec();
    coalesced.extend_from_slice(&second);
    let mut buffer = RecordBuffer::new();
    assert_eq!(buffer.feed(&coalesced), coalesced.len());
    assert_eq!(buffer.next_record().unwrap().unwrap().payload, [7, 8]);
    assert_eq!(buffer.next_record().unwrap().unwrap().payload, [9]);
    assert!(buffer.next_record().unwrap().is_none());
    assert!(buffer.buffered_len() <= MAX_WIRE);

    let oversized = [23, 3, 3, 0x41, 0x01];
    assert_eq!(
        OwnedRecord::decode_prefix(&oversized),
        Err(Error::RecordOverflow)
    );
}

#[test]
fn plaintext_versions_are_state_derived_and_failure_does_not_advance() {
    let client = PlaintextSenderState::new(verus_tls13_record::EndpointRole::Client);
    let failed = plaintext_send_step(client, ContentType::Handshake, 0, Some(1));
    assert_eq!(failed.result, Err(Error::DecodeError));
    assert!(!failed.state.initial_client_hello_emitted);

    let first = plaintext_send_step(client, ContentType::Handshake, 4, Some(1));
    assert_eq!(first.result.unwrap().legacy_version, 0x0301);
    let later = plaintext_send_step(first.state, ContentType::Handshake, 4, Some(1));
    assert_eq!(later.result.unwrap().legacy_version, 0x0303);
    let server = plaintext_send_step(
        PlaintextSenderState::new(verus_tls13_record::EndpointRole::Server),
        ContentType::Handshake,
        4,
        Some(1),
    );
    assert_eq!(server.result.unwrap().legacy_version, 0x0303);
}

#[test]
fn padding_round_trips_and_invalid_inner_plaintexts_fail_terminally() {
    for padding in [0, 1, 63, 255, 1024] {
        let seal_calls = Arc::new(AtomicUsize::new(0));
        let open_calls = Arc::new(AtomicUsize::new(0));
        let secret = [0x3c; 32];
        let mut sender = verus_tls13_record::TrafficSealer::new(
            provider(&seal_calls),
            &secret,
            Limit::rfc8446(),
            limits(8, 100_000, 1),
        )
        .unwrap();
        let protected = sender
            .seal(ContentType::ApplicationData, b"payload", padding)
            .unwrap();
        let mut receiver = RecordReceiver::new();
        receiver
            .install_traffic(
                provider(&open_calls),
                &secret,
                Limit::rfc8446(),
                limits(8, 100_000, 1),
            )
            .unwrap();
        let opened = receiver
            .open_record(
                OwnedRecord {
                    header: protected.header,
                    payload: protected.payload,
                },
                false,
                ReceiveDisposition::Process,
            )
            .unwrap()
            .unwrap();
        assert_eq!(opened.content_type, ContentType::ApplicationData);
        assert_eq!(opened.payload, b"payload");
        assert_eq!(seal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(open_calls.load(Ordering::SeqCst), 1);
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let aead = DeterministicAead {
        key: vec![0; 16],
        calls,
    };
    let mut sealer = Sealer::new(
        Box::new(aead),
        [0; NONCE_LEN],
        Limit::rfc8446(),
        limits(2, 100_000, 1),
    )
    .unwrap();
    assert_eq!(
        sealer.seal(ContentType::Handshake, b"", 0),
        Err(Error::DecodeError)
    );
    assert!(sealer.is_terminal());
}

#[test]
fn replay_bad_tag_and_exhaustion_never_call_provider_after_terminal() {
    let seal_calls = Arc::new(AtomicUsize::new(0));
    let open_calls = Arc::new(AtomicUsize::new(0));
    let secret = [0xa5; 32];
    let mut sender = verus_tls13_record::TrafficSealer::new(
        provider(&seal_calls),
        &secret,
        Limit::rfc8446(),
        limits(8, 100_000, 1),
    )
    .unwrap();
    let protected = sender
        .seal(ContentType::ApplicationData, b"once", 0)
        .unwrap();
    let wire = protected.encode();
    let mut receiver = RecordReceiver::new();
    receiver
        .install_traffic(
            provider(&open_calls),
            &secret,
            Limit::rfc8446(),
            limits(8, 100_000, 1),
        )
        .unwrap();
    receiver
        .open_record(record_from_wire(&wire), false, ReceiveDisposition::Process)
        .unwrap();
    assert_eq!(
        receiver.open_record(record_from_wire(&wire), false, ReceiveDisposition::Process),
        Err(Error::BadRecordMac)
    );
    let calls_after_failure = open_calls.load(Ordering::SeqCst);
    assert_eq!(
        receiver.open_record(record_from_wire(&wire), false, ReceiveDisposition::Process),
        Err(Error::InvalidState)
    );
    assert_eq!(open_calls.load(Ordering::SeqCst), calls_after_failure);

    let calls = Arc::new(AtomicUsize::new(0));
    let mut one_use = Sealer::new(
        Box::new(DeterministicAead {
            key: vec![7; 16],
            calls: calls.clone(),
        }),
        [0; NONCE_LEN],
        Limit::rfc8446(),
        limits(1, 100_000, 1),
    )
    .unwrap();
    one_use
        .seal(ContentType::ApplicationData, b"last", 0)
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        one_use.seal(ContentType::ApplicationData, b"extra", 0),
        Err(Error::ProviderExhausted)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn protected_header_mutations_have_exact_provider_boundary() {
    let seal_calls = Arc::new(AtomicUsize::new(0));
    let secret = [0x11; 32];
    let mut sender = verus_tls13_record::TrafficSealer::new(
        provider(&seal_calls),
        &secret,
        Limit::rfc8446(),
        limits(8, 100_000, 1),
    )
    .unwrap();
    let protected = sender
        .seal(ContentType::ApplicationData, b"header", 0)
        .unwrap();

    let outer_calls = Arc::new(AtomicUsize::new(0));
    let mut outer_receiver = RecordReceiver::new();
    outer_receiver
        .install_traffic(
            provider(&outer_calls),
            &secret,
            Limit::rfc8446(),
            limits(8, 100_000, 1),
        )
        .unwrap();
    let mut wrong_outer = OwnedRecord {
        header: protected.header,
        payload: protected.payload.clone(),
    };
    wrong_outer.header.content_type = ContentType::Handshake as u8;
    assert_eq!(
        outer_receiver.open_record(wrong_outer, false, ReceiveDisposition::Process),
        Err(Error::UnexpectedMessage)
    );
    assert_eq!(outer_calls.load(Ordering::SeqCst), 0);

    let version_calls = Arc::new(AtomicUsize::new(0));
    let mut version_receiver = RecordReceiver::new();
    version_receiver
        .install_traffic(
            provider(&version_calls),
            &secret,
            Limit::rfc8446(),
            limits(8, 100_000, 1),
        )
        .unwrap();
    let mut wrong_version = OwnedRecord {
        header: protected.header,
        payload: protected.payload,
    };
    wrong_version.header.legacy_version ^= 1;
    assert_eq!(
        version_receiver.open_record(wrong_version, false, ReceiveDisposition::Process),
        Err(Error::BadRecordMac)
    );
    assert_eq!(version_calls.load(Ordering::SeqCst), 1);
    assert!(version_receiver.is_terminal());
}

#[test]
fn ccs_alert_close_and_key_update_state_traces_are_fail_closed() {
    for payload in [&[][..], &[0][..], &[1, 0][..], &[1, 1][..]] {
        let mut early = ControlState::new();
        assert_eq!(
            early.validate_ccs(false, payload),
            Err(Error::UnexpectedMessage)
        );
        assert!(early.is_fatal());
    }

    let mut ccs = ControlState::new();
    ccs.observe_local_milestone(HandshakeMilestone::ClientHello)
        .unwrap();
    assert_eq!(ccs.validate_ccs(false, &[1]), Ok(()));
    ccs.observe_peer_milestone(HandshakeMilestone::Finished)
        .unwrap();
    assert_eq!(
        ccs.validate_ccs(false, &[1]),
        Err(Error::UnexpectedMessage)
    );

    let mut close = ControlState::new();
    assert_eq!(close.receive_alert(&[1, 0]), Ok(AlertEvent::CloseNotify));
    assert_eq!(close.receive_disposition(), Ok(ReceiveDisposition::DiscardAfterClose));
    assert!(close.may_write_application_data());

    let mut cancel = ControlState::new();
    assert_eq!(cancel.receive_alert(&[1, 90]), Ok(AlertEvent::UserCanceled));
    assert_eq!(cancel.receive_disposition(), Ok(ReceiveDisposition::Process));
    for malformed in [&[][..], &[1][..], &[1, 0, 0][..]] {
        let mut state = ControlState::new();
        assert_eq!(state.receive_alert(malformed), Err(Error::DecodeError));
        assert!(state.is_fatal());
    }

    let mut update = ControlState::new();
    assert_eq!(update.permit_outbound_key_update(), Err(Error::InvalidState));
    update
        .observe_local_milestone(HandshakeMilestone::Finished)
        .unwrap();
    update
        .observe_peer_milestone(HandshakeMilestone::Finished)
        .unwrap();
    update
        .observe_peer_milestone(HandshakeMilestone::KeyUpdate(
            KeyUpdateRequest::UpdateRequested,
        ))
        .unwrap();
    assert!(!update.may_write_application_data());
    update
        .observe_local_milestone(HandshakeMilestone::KeyUpdate(
            KeyUpdateRequest::UpdateNotRequested,
        ))
        .unwrap();
    assert!(update.may_write_application_data());
    assert_eq!((update.read_generation(), update.write_generation()), (1, 1));
}

#[test]
fn maximum_declared_handshake_length_uses_fixed_tracker_state() {
    let mut tracker = HandshakeTracker::new();
    let header = [11, 0xff, 0xff, 0xff];
    for byte in header {
        tracker.observe_record(&[byte]).unwrap();
    }
    assert_eq!(tracker.declared_remaining(), 0x00ff_ffff);
    assert_eq!(tracker.header_bytes_held(), 4);
    assert!(std::mem::size_of::<HandshakeTracker>() <= 32);
    for _ in 0..1024 {
        tracker.observe_record(&[0]).unwrap();
    }
    assert_eq!(tracker.declared_remaining(), 0x00ff_fbff);
    assert_eq!(tracker.header_bytes_held(), 4);
}

#[test]
fn finite_short_header_model_and_deterministic_stream_fuzz_are_panic_free() {
    let content_types = [0, 20, 21, 22, 23, 24, 255];
    let versions = [0x0000u16, 0x0301, 0x0303, 0xffff];
    let mut cases = 0usize;
    for content_type in content_types {
        for version in versions {
            for length in 0..=3u16 {
                for supplied in 0..=3usize {
                    let mut wire = vec![
                        content_type,
                        (version >> 8) as u8,
                        version as u8,
                        (length >> 8) as u8,
                        length as u8,
                    ];
                    wire.resize(5 + supplied, 0xa5);
                    let _ = OwnedRecord::decode_prefix(&wire);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 448);

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _case in 0..4096 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let length = (seed as usize) % (MAX_WIRE * 2 + 1);
        let mut input = Vec::with_capacity(length);
        for index in 0..length {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            input.push((seed >> ((index & 7) * 8)) as u8);
        }
        let mut buffer = RecordBuffer::new();
        let mut offset = 0usize;
        while offset < input.len() && buffer.remaining_capacity() != 0 {
            let chunk = 1 + ((seed as usize) & 31);
            let end = (offset + chunk).min(input.len());
            let accepted = buffer.feed(&input[offset..end]);
            offset += accepted;
            assert!(buffer.buffered_len() <= MAX_WIRE);
            match buffer.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(_) => break,
            }
            if accepted == 0 {
                break;
            }
        }
        assert!(buffer.buffered_len() <= MAX_WIRE);
        let _ = buffer.finish();
    }
}

#[test]
fn plaintext_receive_versions_are_ignored() {
    for legacy_version in [0x0000, 0x0301, 0x0303, 0xffff] {
        let mut receiver = RecordReceiver::new();
        let opened = receiver
            .open_record(
                OwnedRecord {
                    header: RecordHeader {
                        content_type: ContentType::Handshake as u8,
                        legacy_version,
                        length: 4,
                    },
                    payload: vec![1, 0, 0, 0],
                },
                false,
                ReceiveDisposition::Process,
            )
            .unwrap()
            .unwrap();
        assert_eq!(opened.legacy_version, legacy_version);
    }
}
