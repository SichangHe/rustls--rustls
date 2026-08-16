#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

#[verus_spec(result =>
    ensures
        result == usage_permits_spec(usage, bytes, limits),
        result ==> usage.sequence < u64::MAX,
        result ==> usage.records < limits.max_records,
        result ==> usage.bytes <= limits.max_bytes,
)]
fn per_key_usage_gate(usage: Usage, bytes: usize, limits: UsageLimits) -> bool {
    usage_permits(usage, bytes, limits)
}

#[verus_spec(result =>
    requires
        usage_permits_spec(usage, bytes, limits),
    ensures
        result.sequence == usage.sequence + 1,
        result.records == usage.records + 1,
        result.bytes == usage.bytes + bytes as u64,
        result.failed_opens == usage.failed_opens,
)]
fn successful_record_consumes_exactly_one_sequence(
    usage: Usage,
    bytes: usize,
    limits: UsageLimits,
) -> Usage {
    usage_record_success(usage, bytes, limits)
}

#[verus_spec(result =>
    requires
        left != right,
    ensures
        result,
)]
fn distinct_sequences_make_distinct_nonces(iv: [u8; NONCE_LEN], left: u64, right: u64) -> bool {
    let left_nonce = make_nonce(&iv, left);
    let right_nonce = make_nonce(&iv, right);
    let iv4 = iv[4];
    let iv5 = iv[5];
    let iv6 = iv[6];
    let iv7 = iv[7];
    let iv8 = iv[8];
    let iv9 = iv[9];
    let iv10 = iv[10];
    let iv11 = iv[11];
    let left4 = (left >> 56) as u8;
    let left5 = (left >> 48) as u8;
    let left6 = (left >> 40) as u8;
    let left7 = (left >> 32) as u8;
    let left8 = (left >> 24) as u8;
    let left9 = (left >> 16) as u8;
    let left10 = (left >> 8) as u8;
    let left11 = left as u8;
    let right4 = (right >> 56) as u8;
    let right5 = (right >> 48) as u8;
    let right6 = (right >> 40) as u8;
    let right7 = (right >> 32) as u8;
    let right8 = (right >> 24) as u8;
    let right9 = (right >> 16) as u8;
    let right10 = (right >> 8) as u8;
    let right11 = right as u8;
    proof! {
        assert(
            ((left >> 56) as u8 == (right >> 56) as u8
                && (left >> 48) as u8 == (right >> 48) as u8
                && (left >> 40) as u8 == (right >> 40) as u8
                && (left >> 32) as u8 == (right >> 32) as u8
                && (left >> 24) as u8 == (right >> 24) as u8
                && (left >> 16) as u8 == (right >> 16) as u8
                && (left >> 8) as u8 == (right >> 8) as u8
                && left as u8 == right as u8) ==> left == right
        ) by (bit_vector);
        assert(
            (left4 == right4
                && left5 == right5
                && left6 == right6
                && left7 == right7
                && left8 == right8
                && left9 == right9
                && left10 == right10
                && left11 == right11) ==> left == right
        );
        assert((iv4 ^ left4 == iv4 ^ right4) <==> left4 == right4) by (bit_vector);
        assert((iv5 ^ left5 == iv5 ^ right5) <==> left5 == right5) by (bit_vector);
        assert((iv6 ^ left6 == iv6 ^ right6) <==> left6 == right6) by (bit_vector);
        assert((iv7 ^ left7 == iv7 ^ right7) <==> left7 == right7) by (bit_vector);
        assert((iv8 ^ left8 == iv8 ^ right8) <==> left8 == right8) by (bit_vector);
        assert((iv9 ^ left9 == iv9 ^ right9) <==> left9 == right9) by (bit_vector);
        assert((iv10 ^ left10 == iv10 ^ right10) <==> left10 == right10) by (bit_vector);
        assert((iv11 ^ left11 == iv11 ^ right11) <==> left11 == right11) by (bit_vector);
        assert(
            left_nonce[4] != right_nonce[4]
                || left_nonce[5] != right_nonce[5]
                || left_nonce[6] != right_nonce[6]
                || left_nonce[7] != right_nonce[7]
                || left_nonce[8] != right_nonce[8]
                || left_nonce[9] != right_nonce[9]
                || left_nonce[10] != right_nonce[10]
                || left_nonce[11] != right_nonce[11]
        );
    }
    left_nonce[4] != right_nonce[4]
        || left_nonce[5] != right_nonce[5]
        || left_nonce[6] != right_nonce[6]
        || left_nonce[7] != right_nonce[7]
        || left_nonce[8] != right_nonce[8]
        || left_nonce[9] != right_nonce[9]
        || left_nonce[10] != right_nonce[10]
        || left_nonce[11] != right_nonce[11]
}

fn main() {}
