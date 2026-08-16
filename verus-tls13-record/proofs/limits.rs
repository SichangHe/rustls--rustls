#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

#[verus_spec(result =>
    ensures
        result.is_ok() <==> 64 <= value && value <= MAX_INNER_PLAINTEXT,
        result.is_ok() ==> result.unwrap() as usize == value,
)]
fn record_size_limit_range_is_exact(value: usize) -> Result<u16, Error> {
    validate_limit(value)
}

#[verus_spec(result =>
    ensures
        result.offered == state.offered,
        result.max_inner_seen >= state.max_inner_seen,
        result.max_inner_seen >= inner_len,
        result.max_inner_seen == state.max_inner_seen || result.max_inner_seen == inner_len,
)]
fn pending_limit_observation_is_monotone(
    state: PendingReceiveLimit,
    inner_len: usize,
) -> PendingReceiveLimit {
    observe_pending_receive_limit(state, inner_len)
}

#[verus_spec(result =>
    ensures
        !negotiated ==> result == Ok::<Option<Limit>, Error>(None::<Limit>),
        negotiated && state.max_inner_seen <= limit_value_spec(state.offered) as usize
            ==> result == Ok::<Option<Limit>, Error>(Some(state.offered)),
        negotiated && state.max_inner_seen > limit_value_spec(state.offered) as usize
            ==> result == Err::<Option<Limit>, Error>(Error::RecordOverflow),
)]
fn pending_limit_resolution_checks_every_observation(
    state: PendingReceiveLimit,
    negotiated: bool,
) -> Result<Option<Limit>, Error> {
    resolve_pending_receive_limit(state, negotiated)
}

#[verus_spec(result =>
    ensures
        result == limit_value_spec(limit),
)]
fn typed_limit_exposes_its_validated_value(limit: Limit) -> u16 {
    limit_value(limit)
}

fn main() {}
