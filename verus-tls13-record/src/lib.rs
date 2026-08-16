#![no_std]
#![cfg_attr(verus_keep_ghost, feature(proc_macro_hygiene))]
#![allow(unexpected_cfgs)]

extern crate alloc;

mod control;
mod epoch;
mod handshake;
mod hkdf;
mod protection;
mod receiver;
mod stream;
mod verified;

pub use control::{
    AlertEvent, ControlState, OutboundAlertPlan, ReceiveDisposition,
};
pub use epoch::{TrafficKeyProvider, TrafficOpener, TrafficSealer};
pub use handshake::{
    HANDSHAKE_HEADER_LEN, MAX_HANDSHAKE_BODY, HandshakeMilestone, HandshakeObservation,
    HandshakeReassembler, HandshakeTracker, KeyUpdateRequest, OwnedHandshakeMessage,
};
pub use hkdf::{
    HkdfLabel, TLS13_LABEL_PREFIX, iv_label, key_label, traffic_update_label,
};
pub use protection::{
    Aead, AeadLimits, OpenedRecord, Opener, PreSealAction, ProtectedRecord, ProviderError, Sealer,
};
pub use receiver::{
    OwnedPlainRecord, RecordAlert, RecordReceiver, record_error_alert,
};
pub use stream::{FragmentPlan, Fragmenter, OwnedRecord, RecordBuffer};
pub use verified::{
    AlertPlanStep, AlertStep, ContentType, ControlCore, ControlMilestone, ControlStep, DecodedInner,
    EndpointRole, Error, InboundClassifyStep, InboundCompleteStep, InboundRecordCore,
    InboundRecordKind, Limit, NextOutboundRecord, ParseResult, PendingReceiveLimit,
    PlaintextSendStep, PlaintextSenderState, RecordHeader, StreamDecision, Usage, UsageLimits,
    HEADER_LEN, MAX_CIPHERTEXT, MAX_INNER_PLAINTEXT, MAX_PLAINTEXT, MAX_WIRE, NONCE_LEN,
    accepted_prefix, control_fail, control_may_write_application_data, control_observe_local,
    control_observe_peer, control_permit_inbound_key_update,
    control_permit_outbound_key_update, control_plan_cancel, control_plan_close,
    control_receive_alert, control_receive_disposition, control_validate_ccs, inspect_record,
    inbound_activate_protection, inbound_classify_record, inbound_complete_record, inbound_fail,
    inner_fragment_content_limit,
    make_nonce, next_bounded_fragment_len, next_fragment_len, observe_pending_receive_limit,
    parse_header, plaintext_header, plaintext_send_step, resolve_pending_receive_limit,
    select_next_outbound_record, validate_plaintext_header, validate_protected_header,
    transport_fragment_content_limit,
};
