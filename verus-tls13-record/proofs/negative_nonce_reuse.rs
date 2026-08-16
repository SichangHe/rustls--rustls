#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

// Intentionally false: nonce uniqueness requires distinct sequence numbers.
// This file is expected to fail verification and guards against accidentally
// weakening the proof harness into accepting nonce reuse.
#[verus_spec(result =>
    ensures
        result,
)]
fn reused_sequence_produces_a_distinct_nonce(iv: [u8; NONCE_LEN], sequence: u64) -> bool {
    let first = make_nonce(&iv, sequence);
    let reused = make_nonce(&iv, sequence);
    first[11] != reused[11]
}

fn main() {}
