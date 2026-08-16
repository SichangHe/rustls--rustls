#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

#[verus_spec(result =>
    ensures
        result.is_ok() ==> 0 < result.unwrap(),
        result.is_ok() ==> result.unwrap() <= remaining,
        result.is_ok() ==> result.unwrap() <= max_content,
)]
fn bounded_fragment_is_nonempty(remaining: usize, max_content: usize) -> Result<usize, Error> {
    next_bounded_fragment_len(remaining, max_content)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> 0 < result.unwrap(),
        result.is_ok() ==> result.unwrap() <= remaining,
        result.is_ok() ==> result.unwrap() + 1 <= MAX_INNER_PLAINTEXT,
)]
fn typed_limit_bounds_fragment(remaining: usize, inner_limit: Limit) -> Result<usize, Error> {
    next_fragment_len(remaining, inner_limit)
}

#[verus_spec(result =>
    ensures
        in_flight_application ==> result == NextOutboundRecord::FinishCommittedApplication,
        !in_flight_application && control_pending ==> result == NextOutboundRecord::Control,
        !in_flight_application && !control_pending && application_pending
            ==> result == NextOutboundRecord::SealPendingApplication,
        !in_flight_application && !control_pending && !application_pending
            ==> result == NextOutboundRecord::Idle,
)]
fn scheduler_preserves_commit_and_control_priority(
    in_flight_application: bool,
    control_pending: bool,
    application_pending: bool,
) -> NextOutboundRecord {
    select_next_outbound_record(in_flight_application, control_pending, application_pending)
}

fn main() {}
