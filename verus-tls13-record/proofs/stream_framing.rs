#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

#[verus_spec(result =>
    requires
        input.len() < HEADER_LEN,
    ensures
        result == Ok::<ParseResult, Error>(ParseResult::NeedMore),
)]
fn incomplete_header_needs_more(input: &[u8]) -> Result<ParseResult, Error> {
    parse_header(input)
}

#[verus_spec(result =>
    ensures
        result.is_ok() && result.unwrap() != StreamDecision::NeedMore ==>
            match result.unwrap() {
                StreamDecision::Record { header, wire_len } =>
                    wire_len <= input.len()
                        && wire_len == HEADER_LEN + header.length as usize
                        && wire_len <= MAX_WIRE,
                StreamDecision::NeedMore => true,
            },
)]
fn complete_frame_is_present_and_bounded(input: &[u8]) -> Result<StreamDecision, Error> {
    inspect_record(input)
}

#[verus_spec(result =>
    requires
        buffered <= MAX_WIRE,
    ensures
        result <= input_len,
        buffered + result <= MAX_WIRE,
)]
fn bounded_feed_prefix(buffered: usize, input_len: usize) -> usize {
    accepted_prefix(buffered, input_len)
}

#[verus_spec(result =>
    requires
        buffered >= MAX_WIRE,
    ensures
        result == 0,
)]
fn full_buffer_applies_backpressure(buffered: usize, input_len: usize) -> usize {
    accepted_prefix(buffered, input_len)
}

fn main() {}
