#![feature(proc_macro_hygiene)]
#![allow(dead_code)]

use vstd::prelude::*;

include!("../src/verified.rs");

#[verus_spec(result =>
    requires
        length as usize <= MAX_CIPHERTEXT,
    ensures
        result,
)]
fn header_codec_round_trip(content_type: u8, legacy_version: u16, length: u16) -> bool {
    let header = RecordHeader {
        content_type,
        legacy_version,
        length,
    };
    let encoded = encode_header(header);
    let encoded1 = encoded[1];
    let encoded2 = encoded[2];
    let encoded3 = encoded[3];
    let encoded4 = encoded[4];
    proof! {
        assert(
            (((legacy_version >> 8) as u8) as u16) * 256
                + ((legacy_version as u8) as u16) == legacy_version
        ) by (bit_vector);
        assert(
            (((length >> 8) as u8) as u16) * 256
                + ((length as u8) as u16) == length
        ) by (bit_vector);
        assert((encoded1 as u16) * 256 + encoded2 as u16 == legacy_version);
        assert((encoded3 as u16) * 256 + encoded4 as u16 == length);
    }
    match parse_header(&encoded) {
        Ok(ParseResult::Complete {
            header: decoded,
            wire_len,
        }) => {
            decoded.content_type == header.content_type
                && decoded.legacy_version == header.legacy_version
                && decoded.length == header.length
                && wire_len == HEADER_LEN + length as usize
        }
        _ => false,
    }
}

#[verus_spec(result =>
    requires
        wire == 20 || wire == 21 || wire == 22 || wire == 23,
    ensures
        result.is_some(),
        result.unwrap() as u8 == wire,
)]
fn known_content_type_decodes(wire: u8) -> Option<ContentType> {
    content_type_from_wire(wire)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap().content_type == content_type as u8,
        result.is_ok() ==> result.unwrap().length as usize == payload_len,
        result.is_ok() ==> result.unwrap().legacy_version
            == if initial_client_hello { 0x0301u16 } else { 0x0303u16 },
        result.is_ok() ==> payload_len <= MAX_PLAINTEXT,
)]
// This low-level helper proves only the shape selected by its caller-provided
// flag. The stateful entrypoint below proves when 0x0301 is actually eligible.
fn raw_plaintext_header_encodes_selected_version(
    content_type: ContentType,
    payload_len: usize,
    initial_client_hello: bool,
) -> Result<RecordHeader, Error> {
    plaintext_header(content_type, payload_len, initial_client_hello)
}

#[verus_spec(result =>
    ensures
        result.result.is_ok() ==> (result.result.unwrap().legacy_version == 0x0301
            <==> state.role as u8 == EndpointRole::Client as u8
                && !state.initial_client_hello_emitted
                && content_type as u8 == ContentType::Handshake as u8
                && first_content_byte == Some(1u8)),
        result.state.initial_client_hello_emitted
            == (state.initial_client_hello_emitted
                || (state.role as u8 == EndpointRole::Client as u8
                    && content_type as u8 == ContentType::Handshake as u8
                    && first_content_byte == Some(1u8))),
)]
fn sender_state_derives_initial_client_hello_version(
    state: PlaintextSenderState,
    content_type: ContentType,
    payload_len: usize,
    first_content_byte: Option<u8>,
) -> PlaintextSendStep {
    plaintext_send_step(state, content_type, payload_len, first_content_byte)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap() as u8 == header.content_type,
        result.is_ok() ==> header.length as usize <= MAX_PLAINTEXT,
)]
fn accepted_plaintext_header_has_known_type(header: RecordHeader) -> Result<ContentType, Error> {
    validate_plaintext_header(header)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> header.content_type == ContentType::ApplicationData as u8,
        result.is_ok() ==> header.length as usize <= MAX_CIPHERTEXT,
)]
fn accepted_protected_header_has_canonical_outer_type(header: RecordHeader) -> Result<(), Error> {
    validate_protected_header(header)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap().content_len < plaintext.len(),
        result.is_ok() ==> plaintext[result.unwrap().content_len as int] != 0,
)]
fn decoded_inner_has_a_content_type_octet(
    plaintext: &[u8],
    receive_limit: Limit,
) -> Result<DecodedInner, Error> {
    decode_inner(plaintext, receive_limit)
}

#[verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap() == content_len + 1 + padding_len,
        result.is_ok() ==> result.unwrap() <= limit_value_spec(send_limit) as usize,
)]
fn encoded_inner_length_accounts_for_type_and_padding(
    content_len: usize,
    padding_len: usize,
    send_limit: Limit,
) -> Result<usize, Error> {
    checked_inner_len(content_len, padding_len, send_limit)
}

fn main() {}
