#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

// TrafficSealer and TrafficOpener are not yet verifier-visible. The verified
// epoch surface currently consists of the per-key usage gate plus uncontracted
// control-generation steps; keep both kinds of entrypoint explicit here.
#[verus_spec(result =>
    ensures
        !result,
)]
fn exhausted_sequence_rejects_another_record(
    records: u64,
    bytes_used: u64,
    failed_opens: u64,
    next_bytes: usize,
    limits: UsageLimits,
) -> bool {
    let exhausted = Usage {
        sequence: u64::MAX,
        records,
        bytes: bytes_used,
        failed_opens,
    };
    usage_permits(exhausted, next_bytes, limits)
}

#[verus_spec(result =>
    requires
        limits.max_records > 0,
        next_bytes as u64 <= limits.max_bytes,
    ensures
        result,
)]
fn fresh_epoch_can_consume_its_first_record(next_bytes: usize, limits: UsageLimits) -> bool {
    let fresh = Usage {
        sequence: 0,
        records: 0,
        bytes: 0,
        failed_opens: 0,
    };
    usage_permits(fresh, next_bytes, limits)
}

#[verus_verify]
fn local_generation_transition_is_callable(state: ControlCore, requested: bool) -> ControlStep {
    let milestone = if requested {
        ControlMilestone::KeyUpdateRequested
    } else {
        ControlMilestone::KeyUpdateNotRequested
    };
    control_observe_local(state, milestone)
}

#[verus_verify]
fn peer_generation_transition_is_callable(state: ControlCore, requested: bool) -> ControlStep {
    let milestone = if requested {
        ControlMilestone::KeyUpdateRequested
    } else {
        ControlMilestone::KeyUpdateNotRequested
    };
    control_observe_peer(state, milestone)
}

fn main() {}
