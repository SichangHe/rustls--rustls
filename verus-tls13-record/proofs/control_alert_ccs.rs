#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

// The transition helpers currently have no semantic postconditions. These two
// entrypoints still check that arbitrary Alert and CCS inputs are accepted by
// the Verus-visible call surface; stronger claims belong in the source specs.
#[verus_verify]
fn ccs_transition_is_callable(
    state: ControlCore,
    protected: bool,
    payload_is_one: bool,
) -> ControlStep {
    control_validate_ccs(state, protected, payload_is_one)
}

#[verus_verify]
fn alert_transition_is_callable(
    state: ControlCore,
    payload_len: usize,
    level: u8,
    description: u8,
) -> AlertStep {
    control_receive_alert(state, payload_len, level, description)
}

#[verus_spec(result =>
    ensures
        result ==> !state.fatal,
        result ==> !state.write_closed,
        result ==> !state.pending_key_update_response,
)]
fn application_write_permission_is_fail_closed(state: ControlCore) -> bool {
    control_may_write_application_data(state)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> !state.fatal,
        result == Ok::<u8, Error>(1u8) ==> state.read_closed,
        result == Ok::<u8, Error>(0u8) ==> !state.read_closed,
)]
fn receive_disposition_tracks_read_close(state: ControlCore) -> Result<u8, Error> {
    control_receive_disposition(state)
}

#[verus_spec(result =>
    ensures
        state.terminal ==>
            result.result
                == Err::<InboundRecordKind, Error>(Error::InvalidState),
        result.result.is_err() ==> result.state.terminal,
        result.result
                == Ok::<InboundRecordKind, Error>(InboundRecordKind::Protected)
            ==> state.protection_active
                && header.content_type == ContentType::ApplicationData as u8,
)]
fn inbound_alert_and_ccs_classification_is_fail_closed(
    state: InboundRecordCore,
    header: RecordHeader,
    payload_len: usize,
) -> InboundClassifyStep {
    inbound_classify_record(state, header, payload_len)
}

#[verus_spec(result =>
    ensures
        state.terminal ==> result.result == Err::<(), Error>(Error::InvalidState),
        result.result.is_err() ==> result.state.terminal,
        result.result.is_ok()
                && kind as u8 == InboundRecordKind::Protected as u8
            ==> result.state.has_decrypted,
        result.result.is_ok() && content_len > 0
            ==> result.state.consecutive_empty_fragments == 0,
)]
fn inbound_completion_is_fail_closed(
    state: InboundRecordCore,
    kind: InboundRecordKind,
    content_type: ContentType,
    content_len: usize,
    handshake_active: bool,
) -> InboundCompleteStep {
    inbound_complete_record(state, kind, content_type, content_len, handshake_active)
}

#[verus_spec(result =>
    ensures
        result.protection_active,
        result.has_decrypted == state.has_decrypted,
        result.consecutive_empty_fragments == state.consecutive_empty_fragments,
        result.terminal == state.terminal,
)]
fn protection_activation_preserves_receive_history(state: InboundRecordCore) -> InboundRecordCore {
    inbound_activate_protection(state)
}

fn main() {}
