#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(not(verus_keep_ghost))]
macro_rules! proof {
    ($($tokens:tt)*) => {};
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const HEADER_LEN: usize = 5;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_PLAINTEXT: usize = 16_384;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_INNER_PLAINTEXT: usize = 16_385;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_CIPHERTEXT: usize = 16_640;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_WIRE: usize = 16_645;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NONCE_LEN: usize = 12;

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RecordOverflow,
    UnexpectedMessage,
    BadRecordMac,
    DecodeError,
    IllegalParameter,
    Truncated,
    InvalidState,
    ProviderExhausted,
    ProviderContract,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InboundRecordKind {
    Plaintext,
    Protected,
}

/// Complete verified policy state for record-level receive classification.
/// Cryptographic key material remains in the primitive-backed receiver, while
/// this state decides which records may reach it and whether processing is
/// permanently terminal.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InboundRecordCore {
    pub protection_active: bool,
    pub has_decrypted: bool,
    pub consecutive_empty_fragments: u8,
    pub terminal: bool,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundClassifyStep {
    pub state: InboundRecordCore,
    pub result: Result<InboundRecordKind, Error>,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundCompleteStep {
    pub state: InboundRecordCore,
    pub result: Result<(), Error>,
}

impl ContentType {
    pub fn from_wire(wire: u8) -> Option<Self> {
        content_type_from_wire(wire)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_some() <==> wire == 20 || wire == 21 || wire == 22 || wire == 23,
        result.is_some() ==> result.unwrap() as u8 == wire,
))]
pub fn content_type_from_wire(wire: u8) -> Option<ContentType> {
    match wire {
        20 => Some(ContentType::ChangeCipherSpec),
        21 => Some(ContentType::Alert),
        22 => Some(ContentType::Handshake),
        23 => Some(ContentType::ApplicationData),
        _ => None,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub fn encode(self) -> [u8; HEADER_LEN] {
        encode_header(self)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result[0] == header.content_type,
        result[1] == (header.legacy_version >> 8) as u8,
        result[2] == header.legacy_version as u8,
        result[3] == (header.length >> 8) as u8,
        result[4] == header.length as u8,
))]
pub fn encode_header(header: RecordHeader) -> [u8; HEADER_LEN] {
    [
        header.content_type,
        (header.legacy_version >> 8) as u8,
        header.legacy_version as u8,
        (header.length >> 8) as u8,
        header.length as u8,
    ]
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseResult {
    NeedMore,
    Complete {
        header: RecordHeader,
        wire_len: usize,
    },
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamDecision {
    NeedMore,
    Record {
        header: RecordHeader,
        wire_len: usize,
    },
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        input.len() < HEADER_LEN ==> match result {
            Ok(ParseResult::NeedMore) => true,
            _ => false,
        },
        input.len() >= HEADER_LEN &&
            (input[3] as usize) * 256 + input[4] as usize <= MAX_CIPHERTEXT ==>
            match result {
                Ok(ParseResult::Complete { .. }) => true,
                _ => false,
            },
        result.is_ok() && result.unwrap() != ParseResult::NeedMore ==>
            match result.unwrap() {
                ParseResult::Complete { header, wire_len } =>
                    header.length as usize <= MAX_CIPHERTEXT &&
                    wire_len == HEADER_LEN + header.length as usize &&
                    header.content_type == input[0] &&
                    header.legacy_version == (input[1] as u16) * 256 + input[2] as u16 &&
                    header.length == (input[3] as u16) * 256 + input[4] as u16,
                ParseResult::NeedMore => true,
            },
))]
pub fn parse_header(input: &[u8]) -> Result<ParseResult, Error> {
    if input.len() < HEADER_LEN {
        return Ok(ParseResult::NeedMore);
    }
    let length = (input[3] as u16) * 256 + input[4] as u16;
    if length as usize > MAX_CIPHERTEXT {
        return Err(Error::RecordOverflow);
    }
    Ok(ParseResult::Complete {
        header: RecordHeader {
            content_type: input[0],
            legacy_version: (input[1] as u16) * 256 + input[2] as u16,
            length,
        },
        wire_len: HEADER_LEN + length as usize,
    })
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_ok() && result.unwrap() != StreamDecision::NeedMore ==> match result.unwrap() {
            StreamDecision::Record { header, wire_len } =>
                wire_len <= input.len() &&
                wire_len == HEADER_LEN + header.length as usize &&
                wire_len <= MAX_WIRE,
            StreamDecision::NeedMore => true,
        },
))]
pub fn inspect_record(input: &[u8]) -> Result<StreamDecision, Error> {
    match parse_header(input)? {
        ParseResult::NeedMore => Ok(StreamDecision::NeedMore),
        ParseResult::Complete {
            header: _,
            wire_len,
        } if input.len() < wire_len => Ok(StreamDecision::NeedMore),
        ParseResult::Complete { header, wire_len } => {
            Ok(StreamDecision::Record { header, wire_len })
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result <= input_len,
        buffered <= MAX_WIRE ==> buffered + result <= MAX_WIRE,
        buffered >= MAX_WIRE ==> result == 0,
))]
pub fn accepted_prefix(buffered: usize, input_len: usize) -> usize {
    if buffered >= MAX_WIRE {
        return 0;
    }
    let remaining = MAX_WIRE - buffered;
    if input_len <= remaining {
        input_len
    } else {
        remaining
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EndpointRole {
    Client,
    Server,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextOutboundRecord {
    FinishCommittedApplication,
    Control,
    SealPendingApplication,
    Idle,
}

/// Select the next wire record without reordering committed sequence numbers.
/// A committed application record is indivisible; otherwise control traffic
/// (notably KeyUpdate) precedes application plaintext that has not been sealed.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        in_flight_application ==> result == NextOutboundRecord::FinishCommittedApplication,
        !in_flight_application && control_pending ==> result == NextOutboundRecord::Control,
        !in_flight_application && !control_pending && application_pending
            ==> result == NextOutboundRecord::SealPendingApplication,
        !in_flight_application && !control_pending && !application_pending
            ==> result == NextOutboundRecord::Idle,
))]
pub fn select_next_outbound_record(
    in_flight_application: bool,
    control_pending: bool,
    application_pending: bool,
) -> NextOutboundRecord {
    if in_flight_application {
        NextOutboundRecord::FinishCommittedApplication
    } else if control_pending {
        NextOutboundRecord::Control
    } else if application_pending {
        NextOutboundRecord::SealPendingApplication
    } else {
        NextOutboundRecord::Idle
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaintextSenderState {
    pub role: EndpointRole,
    pub initial_client_hello_emitted: bool,
}

impl PlaintextSenderState {
    pub const fn new(role: EndpointRole) -> Self {
        Self {
            role,
            initial_client_hello_emitted: false,
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaintextSendStep {
    pub state: PlaintextSenderState,
    pub result: Result<RecordHeader, Error>,
}

/// Decide the complete emitted TLSPlaintext header from sender state and the
/// actual fragment prefix. The initial ClientHello version cannot be selected
/// by an untrusted caller-provided flag.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
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
                    && first_content_byte == Some(1u8)
                    && result.result.is_ok())),
        result.result.is_err()
            ==> result.state.initial_client_hello_emitted
                == state.initial_client_hello_emitted,
))]
pub fn plaintext_send_step(
    state: PlaintextSenderState,
    content_type: ContentType,
    payload_len: usize,
    first_content_byte: Option<u8>,
) -> PlaintextSendStep {
    let initial_client_hello = state.role as u8 == EndpointRole::Client as u8
        && !state.initial_client_hello_emitted
        && content_type as u8 == ContentType::Handshake as u8
        && first_content_byte == Some(1);
    let result = plaintext_header(content_type, payload_len, initial_client_hello);
    PlaintextSendStep {
        state: PlaintextSenderState {
            initial_client_hello_emitted: state.initial_client_hello_emitted
                || (initial_client_hello && result.is_ok()),
            ..state
        },
        result,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlCore {
    pub first_client_hello: bool,
    pub local_finished: bool,
    pub peer_finished: bool,
    pub read_closed: bool,
    pub write_closed: bool,
    pub fatal: bool,
    pub pending_key_update_response: bool,
    pub read_generation: u64,
    pub write_generation: u64,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMilestone {
    ClientHello,
    ServerHello,
    Finished,
    KeyUpdateNotRequested,
    KeyUpdateRequested,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlStep {
    pub state: ControlCore,
    pub result: Result<(), Error>,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertStep {
    pub state: ControlCore,
    /// 0 = close_notify, 1 = user_canceled, 2 = fatal/unknown.
    pub event: Result<u8, Error>,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertPlanStep {
    pub state: ControlCore,
    pub first_description: u8,
    pub second_description: Option<u8>,
    pub result: Result<(), Error>,
}

/// Encode the two-octet TLS 1.3 Alert payload used by this profile.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result[0] == 1,
        result[1] == description,
))]
pub fn encode_warning_alert(description: u8) -> [u8; 2] {
    [1, description]
}

/// Encode the sole compatibility ChangeCipherSpec payload accepted by TLS 1.3.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result[0] == 1,
))]
pub fn encode_compatibility_ccs() -> [u8; 1] {
    [1]
}

/// Encode a complete KeyUpdate handshake message. `request_update` selects
/// update_requested (1) rather than update_not_requested (0).
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result[0] == 24,
        result[1] == 0,
        result[2] == 0,
        result[3] == 1,
        result[4] == if request_update { 1u8 } else { 0u8 },
))]
pub fn encode_key_update(request_update: bool) -> [u8; 5] {
    [24, 0, 0, 1, if request_update { 1 } else { 0 }]
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMilestoneKind {
    None,
    ClientHello,
    ServerHello,
    Finished,
    KeyUpdateNotRequested,
    KeyUpdateRequested,
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        value == 0 ==> result == Ok::<bool, Error>(false),
        value == 1 ==> result == Ok::<bool, Error>(true),
        value != 0 && value != 1 ==> result == Err::<bool, Error>(Error::IllegalParameter),
))]
pub fn decode_key_update_request(value: u8) -> Result<bool, Error> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::IllegalParameter),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        typ == 5 ==> result == Err::<(), Error>(Error::UnexpectedMessage),
        (typ == 1 || typ == 2 || typ == 20) && length == 0
            ==> result == Err::<(), Error>(Error::DecodeError),
        typ == 24 && length != 1
            ==> result == Err::<(), Error>(Error::DecodeError),
        typ != 5 && !((typ == 1 || typ == 2 || typ == 20) && length == 0)
                && !(typ == 24 && length != 1)
            ==> result == Ok::<(), Error>(()),
))]
pub fn validate_handshake_declaration(typ: u8, length: u32) -> Result<(), Error> {
    match typ {
        5 => Err(Error::UnexpectedMessage),
        1 | 2 | 20 if length == 0 => Err(Error::DecodeError),
        24 if length != 1 => Err(Error::DecodeError),
        _ => Ok(()),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        typ == 1 ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::ClientHello),
        typ == 2 ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::ServerHello),
        typ == 20 ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::Finished),
        typ == 24 && key_update_request == 0
            ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::KeyUpdateNotRequested),
        typ == 24 && key_update_request == 1
            ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::KeyUpdateRequested),
        typ == 24 && key_update_request != 0 && key_update_request != 1
            ==> result == Err::<HandshakeMilestoneKind, Error>(Error::IllegalParameter),
        typ != 1 && typ != 2 && typ != 20 && typ != 24
            ==> result == Ok::<HandshakeMilestoneKind, Error>(HandshakeMilestoneKind::None),
))]
pub fn classify_handshake_milestone(
    typ: u8,
    key_update_request: u8,
) -> Result<HandshakeMilestoneKind, Error> {
    match typ {
        1 => Ok(HandshakeMilestoneKind::ClientHello),
        2 => Ok(HandshakeMilestoneKind::ServerHello),
        20 => Ok(HandshakeMilestoneKind::Finished),
        24 => match decode_key_update_request(key_update_request)? {
            false => Ok(HandshakeMilestoneKind::KeyUpdateNotRequested),
            true => Ok(HandshakeMilestoneKind::KeyUpdateRequested),
        },
        _ => Ok(HandshakeMilestoneKind::None),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        named_milestone && !at_record_end
            ==> result == Err::<(), Error>(Error::UnexpectedMessage),
        !named_milestone || at_record_end ==> result == Ok::<(), Error>(()),
))]
pub fn validate_milestone_record_end(
    named_milestone: bool,
    at_record_end: bool,
) -> Result<(), Error> {
    if named_milestone && !at_record_end {
        Err(Error::UnexpectedMessage)
    } else {
        Ok(())
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        aligned && boundary_matches ==> result == Ok::<(), Error>(()),
        !aligned || !boundary_matches ==> result == Err::<(), Error>(Error::InvalidState),
))]
pub fn permit_handshake_activation(
    aligned: bool,
    boundary_matches: bool,
) -> Result<(), Error> {
    if aligned && boundary_matches {
        Ok(())
    } else {
        Err(Error::InvalidState)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result <==> !state.fatal && !state.write_closed
            && !state.pending_key_update_response,
))]
pub fn control_may_write_application_data(state: ControlCore) -> bool {
    !state.fatal && !state.write_closed && !state.pending_key_update_response
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal ==> result == Err::<u8, Error>(Error::InvalidState),
        !state.fatal && state.read_closed ==> result == Ok::<u8, Error>(1u8),
        !state.fatal && !state.read_closed ==> result == Ok::<u8, Error>(0u8),
))]
pub fn control_receive_disposition(state: ControlCore) -> Result<u8, Error> {
    if state.fatal {
        Err(Error::InvalidState)
    } else if state.read_closed {
        Ok(1)
    } else {
        Ok(0)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal ==> result == (ControlStep {
            state,
            result: Err::<(), Error>(Error::InvalidState),
        }),
        !state.fatal && milestone == ControlMilestone::ClientHello
            ==> result == (ControlStep {
                state: ControlCore { first_client_hello: true, ..state },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::Finished
            ==> result == (ControlStep {
                state: ControlCore { local_finished: true, ..state },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::ServerHello
            ==> result == (ControlStep {
                state,
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && (state.write_closed || !state.local_finished)
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::InvalidState),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && !state.write_closed && state.local_finished
                && state.write_generation == u64::MAX
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::ProviderExhausted),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && !state.write_closed && state.local_finished
                && state.write_generation < u64::MAX
            ==> result == (ControlStep {
                state: ControlCore {
                    pending_key_update_response: false,
                    write_generation: (state.write_generation + 1) as u64,
                    ..state
                },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && (state.write_closed || !state.local_finished)
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::InvalidState),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && !state.write_closed && state.local_finished
                && state.write_generation == u64::MAX
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::ProviderExhausted),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && !state.write_closed && state.local_finished
                && state.write_generation < u64::MAX
            ==> result == (ControlStep {
                state: ControlCore {
                    write_generation: (state.write_generation + 1) as u64,
                    ..state
                },
                result: Ok::<(), Error>(()),
            }),
))]
pub fn control_observe_local(mut state: ControlCore, milestone: ControlMilestone) -> ControlStep {
    if state.fatal {
        return ControlStep {
            state,
            result: Err(Error::InvalidState),
        };
    }
    let result = match milestone {
        ControlMilestone::ClientHello => {
            state.first_client_hello = true;
            Ok(())
        }
        ControlMilestone::Finished => {
            state.local_finished = true;
            Ok(())
        }
        ControlMilestone::KeyUpdateNotRequested => {
            if state.write_closed || !state.local_finished {
                Err(Error::InvalidState)
            } else if let Some(next) = state.write_generation.checked_add(1) {
                state.write_generation = next;
                state.pending_key_update_response = false;
                Ok(())
            } else {
                Err(Error::ProviderExhausted)
            }
        }
        ControlMilestone::KeyUpdateRequested => {
            if state.write_closed || !state.local_finished {
                Err(Error::InvalidState)
            } else if let Some(next) = state.write_generation.checked_add(1) {
                state.write_generation = next;
                Ok(())
            } else {
                Err(Error::ProviderExhausted)
            }
        }
        ControlMilestone::ServerHello => Ok(()),
    };
    ControlStep { state, result }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal ==> result == (ControlStep {
            state,
            result: Err::<(), Error>(Error::InvalidState),
        }),
        !state.fatal && milestone == ControlMilestone::ClientHello
            ==> result == (ControlStep {
                state: ControlCore { first_client_hello: true, ..state },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::Finished
            ==> result == (ControlStep {
                state: ControlCore { peer_finished: true, ..state },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::ServerHello
            ==> result == (ControlStep {
                state,
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && (state.read_closed || !state.peer_finished)
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::UnexpectedMessage),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && !state.read_closed && state.peer_finished
                && state.read_generation == u64::MAX
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::ProviderExhausted),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateNotRequested
                && !state.read_closed && state.peer_finished
                && state.read_generation < u64::MAX
            ==> result == (ControlStep {
                state: ControlCore {
                    read_generation: (state.read_generation + 1) as u64,
                    ..state
                },
                result: Ok::<(), Error>(()),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && (state.read_closed || !state.peer_finished)
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::UnexpectedMessage),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && !state.read_closed && state.peer_finished
                && state.read_generation == u64::MAX
            ==> result == (ControlStep {
                state,
                result: Err::<(), Error>(Error::ProviderExhausted),
            }),
        !state.fatal && milestone == ControlMilestone::KeyUpdateRequested
                && !state.read_closed && state.peer_finished
                && state.read_generation < u64::MAX
            ==> result == (ControlStep {
                state: ControlCore {
                    pending_key_update_response: if state.write_closed {
                        state.pending_key_update_response
                    } else {
                        true
                    },
                    read_generation: (state.read_generation + 1) as u64,
                    ..state
                },
                result: Ok::<(), Error>(()),
            }),
))]
pub fn control_observe_peer(mut state: ControlCore, milestone: ControlMilestone) -> ControlStep {
    if state.fatal {
        return ControlStep {
            state,
            result: Err(Error::InvalidState),
        };
    }
    let result = match milestone {
        ControlMilestone::ClientHello => {
            state.first_client_hello = true;
            Ok(())
        }
        ControlMilestone::Finished => {
            state.peer_finished = true;
            Ok(())
        }
        ControlMilestone::KeyUpdateNotRequested => {
            if state.read_closed || !state.peer_finished {
                Err(Error::UnexpectedMessage)
            } else if let Some(next) = state.read_generation.checked_add(1) {
                state.read_generation = next;
                Ok(())
            } else {
                Err(Error::ProviderExhausted)
            }
        }
        ControlMilestone::KeyUpdateRequested => {
            if state.read_closed || !state.peer_finished {
                Err(Error::UnexpectedMessage)
            } else if let Some(next) = state.read_generation.checked_add(1) {
                state.read_generation = next;
                if !state.write_closed {
                    state.pending_key_update_response = true;
                }
                Ok(())
            } else {
                Err(Error::ProviderExhausted)
            }
        }
        ControlMilestone::ServerHello => Ok(()),
    };
    ControlStep { state, result }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        !state.fatal && !protected && state.first_client_hello
                && !state.peer_finished && payload_is_one
            ==> result.result == Ok::<(), Error>(()) && result.state == state,
        (state.fatal || protected || !state.first_client_hello
                || state.peer_finished || !payload_is_one)
            ==> result.result == Err::<(), Error>(Error::UnexpectedMessage)
                && result.state == (ControlCore { fatal: true, ..state }),
))]
pub fn control_validate_ccs(
    mut state: ControlCore,
    protected: bool,
    payload_is_one: bool,
) -> ControlStep {
    if state.fatal
        || protected
        || !state.first_client_hello
        || state.peer_finished
        || !payload_is_one
    {
        state.fatal = true;
        return ControlStep {
            state,
            result: Err(Error::UnexpectedMessage),
        };
    }
    ControlStep {
        state,
        result: Ok(()),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal ==> result.event == Err::<u8, Error>(Error::InvalidState)
            && result.state == state,
        !state.fatal && payload_len != 2
            ==> result.event == Err::<u8, Error>(Error::DecodeError)
                && result.state == (ControlCore { fatal: true, ..state }),
        !state.fatal && payload_len == 2 && level == 1 && description == 0
            ==> result.event == Ok::<u8, Error>(0u8)
                && result.state == (ControlCore { read_closed: true, ..state }),
        !state.fatal && payload_len == 2 && level == 1 && description == 90
            ==> result.event == Ok::<u8, Error>(1u8) && result.state == state,
        !state.fatal && payload_len == 2 && !(level == 1 && description == 0)
                && !(level == 1 && description == 90)
            ==> result.event == Ok::<u8, Error>(2u8)
                && result.state == (ControlCore {
                    fatal: true,
                    read_closed: true,
                    write_closed: true,
                    ..state
                }),
))]
pub fn control_receive_alert(
    mut state: ControlCore,
    payload_len: usize,
    level: u8,
    description: u8,
) -> AlertStep {
    if state.fatal {
        return AlertStep {
            state,
            event: Err(Error::InvalidState),
        };
    }
    if payload_len != 2 {
        state.fatal = true;
        return AlertStep {
            state,
            event: Err(Error::DecodeError),
        };
    }
    match (level, description) {
        (1, 0) => {
            state.read_closed = true;
            AlertStep {
                state,
                event: Ok(0),
            }
        }
        (1, 90) => AlertStep {
            state,
            event: Ok(1),
        },
        _ => {
            state.fatal = true;
            state.read_closed = true;
            state.write_closed = true;
            AlertStep {
                state,
                event: Ok(2),
            }
        }
    }
}

/// Validate the exact compatibility CCS payload before applying the control
/// transition, keeping raw-byte interpretation inside the verified kernel.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        !state.fatal && !protected && state.first_client_hello
                && !state.peer_finished && payload.len() == 1 && payload[0] == 1
            ==> result.result == Ok::<(), Error>(()) && result.state == state,
        (state.fatal || protected || !state.first_client_hello || state.peer_finished
                || payload.len() != 1 || (payload.len() == 1 && payload[0] != 1))
            ==> result.result == Err::<(), Error>(Error::UnexpectedMessage)
                && result.state == (ControlCore { fatal: true, ..state }),
))]
pub fn control_validate_ccs_payload(
    state: ControlCore,
    protected: bool,
    payload: &[u8],
) -> ControlStep {
    let payload_is_one = payload.len() == 1 && payload[0] == 1;
    control_validate_ccs(state, protected, payload_is_one)
}

/// Decode an exact two-octet Alert payload and apply its verified lifecycle
/// transition. Malformed lengths never expose synthetic level/description
/// values to the transition semantics.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal ==> result.event == Err::<u8, Error>(Error::InvalidState)
            && result.state == state,
        !state.fatal && payload.len() != 2
            ==> result.event == Err::<u8, Error>(Error::DecodeError)
                && result.state == (ControlCore { fatal: true, ..state }),
        !state.fatal && payload.len() == 2 && payload[0] == 1 && payload[1] == 0
            ==> result.event == Ok::<u8, Error>(0u8)
                && result.state == (ControlCore { read_closed: true, ..state }),
        !state.fatal && payload.len() == 2 && payload[0] == 1 && payload[1] == 90
            ==> result.event == Ok::<u8, Error>(1u8) && result.state == state,
        !state.fatal && payload.len() == 2
                && !(payload[0] == 1 && payload[1] == 0)
                && !(payload[0] == 1 && payload[1] == 90)
            ==> result.event == Ok::<u8, Error>(2u8)
                && result.state == (ControlCore {
                    fatal: true,
                    read_closed: true,
                    write_closed: true,
                    ..state
                }),
))]
pub fn control_receive_alert_payload(state: ControlCore, payload: &[u8]) -> AlertStep {
    if payload.len() != 2 {
        return control_receive_alert(state, payload.len(), 0, 0);
    }
    control_receive_alert(state, payload.len(), payload[0], payload[1])
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal || state.write_closed
            ==> result.result == Err::<(), Error>(Error::InvalidState)
                && result.state == state
                && result.first_description == 0
                && result.second_description.is_none(),
        !state.fatal && !state.write_closed
            ==> result.result == Ok::<(), Error>(())
                && result.state == (ControlCore { write_closed: true, ..state })
                && result.first_description == if state.local_finished { 0u8 } else { 90u8 }
                && result.second_description == if state.local_finished {
                    None::<u8>
                } else {
                    Some(0u8)
                },
))]
pub fn control_plan_cancel(mut state: ControlCore) -> AlertPlanStep {
    if state.fatal || state.write_closed {
        return AlertPlanStep {
            state,
            first_description: 0,
            second_description: None,
            result: Err(Error::InvalidState),
        };
    }
    state.write_closed = true;
    AlertPlanStep {
        state,
        first_description: if state.local_finished { 0 } else { 90 },
        second_description: if state.local_finished { None } else { Some(0) },
        result: Ok(()),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal || state.write_closed
            ==> result.result == Err::<(), Error>(Error::InvalidState)
                && result.state == state,
        !state.fatal && !state.write_closed
            ==> result.result == Ok::<(), Error>(())
                && result.state == (ControlCore { write_closed: true, ..state }),
))]
pub fn control_plan_close(mut state: ControlCore) -> ControlStep {
    if state.fatal || state.write_closed {
        return ControlStep {
            state,
            result: Err(Error::InvalidState),
        };
    }
    state.write_closed = true;
    ControlStep {
        state,
        result: Ok(()),
    }
}

/// Largest authenticated TLSInnerPlaintext observed while a client's
/// record_size_limit offer is awaiting the server's EncryptedExtensions.
/// This spans record and handshake-message boundaries.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingReceiveLimit {
    pub offered: Limit,
    pub max_inner_seen: usize,
}

impl PendingReceiveLimit {
    pub const fn new(offered: Limit) -> Self {
        Self {
            offered,
            max_inner_seen: 0,
        }
    }

    pub fn observe(self, inner_len: usize) -> Self {
        observe_pending_receive_limit(self, inner_len)
    }

    pub fn resolve(self, negotiated: bool) -> Result<Option<Limit>, Error> {
        resolve_pending_receive_limit(self, negotiated)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.offered == state.offered,
        result.max_inner_seen >= state.max_inner_seen,
        result.max_inner_seen >= inner_len,
        result.max_inner_seen == state.max_inner_seen || result.max_inner_seen == inner_len,
))]
pub fn observe_pending_receive_limit(
    mut state: PendingReceiveLimit,
    inner_len: usize,
) -> PendingReceiveLimit {
    if inner_len > state.max_inner_seen {
        state.max_inner_seen = inner_len;
    }
    state
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        !negotiated ==> result == Ok::<Option<Limit>, Error>(None::<Limit>),
        negotiated && state.max_inner_seen <= limit_value_spec(state.offered) as usize
            ==> result == Ok::<Option<Limit>, Error>(Some(state.offered)),
        negotiated && state.max_inner_seen > limit_value_spec(state.offered) as usize
            ==> result == Err::<Option<Limit>, Error>(Error::RecordOverflow),
))]
pub fn resolve_pending_receive_limit(
    state: PendingReceiveLimit,
    negotiated: bool,
) -> Result<Option<Limit>, Error> {
    if !negotiated {
        return Ok(None);
    }
    if state.max_inner_seen > limit_value(state.offered) as usize {
        Err(Error::RecordOverflow)
    } else {
        Ok(Some(state.offered))
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result == (ControlCore {
            fatal: true,
            read_closed: true,
            write_closed: true,
            ..state
        }),
))]
pub fn control_fail(mut state: ControlCore) -> ControlCore {
    state.fatal = true;
    state.read_closed = true;
    state.write_closed = true;
    state
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal || state.write_closed || !state.local_finished
            ==> result == Err::<(), Error>(Error::InvalidState),
        !state.fatal && !state.write_closed && state.local_finished
            ==> result == Ok::<(), Error>(()),
))]
pub fn control_permit_outbound_key_update(state: ControlCore) -> Result<(), Error> {
    if state.fatal || state.write_closed || !state.local_finished {
        Err(Error::InvalidState)
    } else {
        Ok(())
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.fatal || state.read_closed || !state.peer_finished
            ==> result == Err::<(), Error>(Error::UnexpectedMessage),
        !state.fatal && !state.read_closed && state.peer_finished
            ==> result == Ok::<(), Error>(()),
))]
pub fn control_permit_inbound_key_update(state: ControlCore) -> Result<(), Error> {
    if state.fatal || state.read_closed || !state.peer_finished {
        Err(Error::UnexpectedMessage)
    } else {
        Ok(())
    }
}

/// Construct the canonical TLSPlaintext header for the selected profile.
/// Only the initial ClientHello record uses legacy version 0x0301.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap().content_type == content_type as u8,
        result.is_ok() ==> result.unwrap().length as usize == payload_len,
        result.is_ok() ==> result.unwrap().legacy_version == if initial_client_hello { 0x0301u16 } else { 0x0303u16 },
        result.is_ok() ==> payload_len <= MAX_PLAINTEXT,
        initial_client_hello && content_type as u8 != ContentType::Handshake as u8
            ==> result == Err::<RecordHeader, Error>(Error::IllegalParameter),
        content_type as u8 == ContentType::Handshake as u8 && payload_len == 0 ==> match result {
            Err(Error::DecodeError) => true,
            _ => false,
        },
))]
pub fn plaintext_header(
    content_type: ContentType,
    payload_len: usize,
    initial_client_hello: bool,
) -> Result<RecordHeader, Error> {
    if initial_client_hello && content_type as u8 != ContentType::Handshake as u8 {
        return Err(Error::IllegalParameter);
    }
    if payload_len > MAX_PLAINTEXT {
        return Err(Error::RecordOverflow);
    }
    if content_type as u8 == ContentType::Handshake as u8 && payload_len == 0 {
        return Err(Error::DecodeError);
    }
    Ok(RecordHeader {
        content_type: content_type as u8,
        legacy_version: if initial_client_hello { 0x0301 } else { 0x0303 },
        length: payload_len as u16,
    })
}

/// Validate an inbound unprotected record. Its legacy version is deliberately
/// ignored as required by RFC 8446; only its exact received bytes are retained.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        header.length as usize > MAX_PLAINTEXT
            ==> result == Err::<ContentType, Error>(Error::RecordOverflow),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type != 20 && header.content_type != 21
                && header.content_type != 22 && header.content_type != 23
            ==> result == Err::<ContentType, Error>(Error::UnexpectedMessage),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type == ContentType::Handshake as u8
                && header.length == 0
            ==> result == Err::<ContentType, Error>(Error::DecodeError),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type == ContentType::ChangeCipherSpec as u8
            ==> result == Ok::<ContentType, Error>(ContentType::ChangeCipherSpec),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type == ContentType::Alert as u8
            ==> result == Ok::<ContentType, Error>(ContentType::Alert),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type == ContentType::ApplicationData as u8
            ==> result == Ok::<ContentType, Error>(ContentType::ApplicationData),
        header.length as usize <= MAX_PLAINTEXT
                && header.content_type == ContentType::Handshake as u8
                && header.length > 0
            ==> result == Ok::<ContentType, Error>(ContentType::Handshake),
        result.is_ok() ==> result.unwrap() as u8 == header.content_type,
        result.is_ok() ==> header.length as usize <= MAX_PLAINTEXT,
))]
pub fn validate_plaintext_header(header: RecordHeader) -> Result<ContentType, Error> {
    if header.length as usize > MAX_PLAINTEXT {
        return Err(Error::RecordOverflow);
    }
    let content_type =
        content_type_from_wire(header.content_type).ok_or(Error::UnexpectedMessage)?;
    if content_type as u8 == ContentType::Handshake as u8 && header.length == 0 {
        return Err(Error::DecodeError);
    }
    Ok(content_type)
}

/// Validate only the selected profile's protected outer type and length. The
/// received legacy version is not interpreted: all five bytes remain AEAD AAD.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        header.length as usize > MAX_CIPHERTEXT
            ==> result == Err::<(), Error>(Error::RecordOverflow),
        header.length as usize <= MAX_CIPHERTEXT
                && header.content_type != ContentType::ApplicationData as u8
            ==> result == Err::<(), Error>(Error::UnexpectedMessage),
        header.length as usize <= MAX_CIPHERTEXT
                && header.content_type == ContentType::ApplicationData as u8
            ==> result == Ok::<(), Error>(()),
        result.is_ok() ==> header.content_type == ContentType::ApplicationData as u8,
        result.is_ok() ==> header.length as usize <= MAX_CIPHERTEXT,
))]
pub fn validate_protected_header(header: RecordHeader) -> Result<(), Error> {
    if header.length as usize > MAX_CIPHERTEXT {
        return Err(Error::RecordOverflow);
    }
    if header.content_type != ContentType::ApplicationData as u8 {
        return Err(Error::UnexpectedMessage);
    }
    Ok(())
}

/// Classify one complete received record before any provider call. Plaintext
/// legacy-version bytes are deliberately ignored. Once protection is active,
/// only compatibility CCS and a pre-first-ciphertext two-byte Alert may remain
/// plaintext; every other record must have the protected outer type.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.terminal ==> result == (InboundClassifyStep {
            state,
            result: Err::<InboundRecordKind, Error>(Error::InvalidState),
        }),
        !state.terminal && header.length as usize != payload_len
            ==> result == (InboundClassifyStep {
                state: InboundRecordCore { terminal: true, ..state },
                result: Err::<InboundRecordKind, Error>(Error::RecordOverflow),
            }),
        !state.terminal && header.length as usize == payload_len
                && state.protection_active
                && header.content_type == ContentType::ChangeCipherSpec as u8
                && header.length as usize <= MAX_PLAINTEXT
            ==> result == (InboundClassifyStep {
                state,
                result: Ok::<InboundRecordKind, Error>(InboundRecordKind::Plaintext),
            }),
        !state.terminal && header.length as usize == payload_len
                && state.protection_active && !state.has_decrypted
                && header.content_type == ContentType::Alert as u8 && payload_len == 2
            ==> result == (InboundClassifyStep {
                state,
                result: Ok::<InboundRecordKind, Error>(InboundRecordKind::Plaintext),
            }),
        !state.terminal && header.length as usize == payload_len
                && state.protection_active
                && header.content_type != ContentType::ChangeCipherSpec as u8
                && !(header.content_type == ContentType::Alert as u8
                    && !state.has_decrypted && payload_len == 2)
                && header.content_type == ContentType::ApplicationData as u8
                && header.length as usize <= MAX_CIPHERTEXT
            ==> result == (InboundClassifyStep {
                state,
                result: Ok::<InboundRecordKind, Error>(InboundRecordKind::Protected),
            }),
        result.result.is_err() ==> result.state.terminal,
        result.result == Ok::<InboundRecordKind, Error>(InboundRecordKind::Protected)
            ==> state.protection_active && header.content_type == ContentType::ApplicationData as u8,
))]
pub fn inbound_classify_record(
    mut state: InboundRecordCore,
    header: RecordHeader,
    payload_len: usize,
) -> InboundClassifyStep {
    if state.terminal {
        return InboundClassifyStep {
            state,
            result: Err(Error::InvalidState),
        };
    }
    if header.length as usize != payload_len {
        state.terminal = true;
        return InboundClassifyStep {
            state,
            result: Err(Error::RecordOverflow),
        };
    }

    let plaintext_exception = header.content_type == ContentType::ChangeCipherSpec as u8
        || (header.content_type == ContentType::Alert as u8
            && !state.has_decrypted
            && payload_len == 2);
    let result = if !state.protection_active || plaintext_exception {
        match validate_plaintext_header(header) {
            Ok(_content_type) => Ok(InboundRecordKind::Plaintext),
            Err(error) => Err(error),
        }
    } else {
        match validate_protected_header(header) {
            Ok(_unit) => Ok(InboundRecordKind::Protected),
            Err(error) => Err(error),
        }
    };
    if result.is_err() {
        state.terminal = true;
    }
    InboundClassifyStep { state, result }
}

/// Complete record-level policy after plaintext classification or successful
/// authenticated opening. This is the sole selected-profile interleaving,
/// protected-CCS, empty-fragment, and terminal-state decision.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        state.terminal ==> result == (InboundCompleteStep {
            state,
            result: Err::<(), Error>(Error::InvalidState),
        }),
        !state.terminal && (
                (kind as u8 == InboundRecordKind::Protected as u8
                    && content_type as u8 == ContentType::ChangeCipherSpec as u8)
                || (handshake_active
                    && content_type as u8 != ContentType::Handshake as u8)
                || (content_type as u8 == ContentType::Handshake as u8
                    && content_len == 0)
                || (content_len == 0 && state.consecutive_empty_fragments >= 32)
            ) ==> result == (InboundCompleteStep {
                state: InboundRecordCore { terminal: true, ..state },
                result: Err::<(), Error>(Error::UnexpectedMessage),
            }),
        !state.terminal
                && !(kind as u8 == InboundRecordKind::Protected as u8
                    && content_type as u8 == ContentType::ChangeCipherSpec as u8)
                && !(handshake_active
                    && content_type as u8 != ContentType::Handshake as u8)
                && !(content_type as u8 == ContentType::Handshake as u8
                    && content_len == 0)
                && !(content_len == 0 && state.consecutive_empty_fragments >= 32)
            ==> result == (InboundCompleteStep {
                state: InboundRecordCore {
                    has_decrypted: state.has_decrypted
                        || kind as u8 == InboundRecordKind::Protected as u8,
                    consecutive_empty_fragments: if content_len == 0 {
                        (state.consecutive_empty_fragments + 1) as u8
                    } else {
                        0
                    },
                    ..state
                },
                result: Ok::<(), Error>(()),
            }),
))]
pub fn inbound_complete_record(
    mut state: InboundRecordCore,
    kind: InboundRecordKind,
    content_type: ContentType,
    content_len: usize,
    handshake_active: bool,
) -> InboundCompleteStep {
    if state.terminal {
        return InboundCompleteStep {
            state,
            result: Err(Error::InvalidState),
        };
    }
    let protected = kind as u8 == InboundRecordKind::Protected as u8;
    let invalid = (protected && content_type as u8 == ContentType::ChangeCipherSpec as u8)
        || (handshake_active && content_type as u8 != ContentType::Handshake as u8)
        || (content_type as u8 == ContentType::Handshake as u8 && content_len == 0)
        || (content_len == 0 && state.consecutive_empty_fragments >= 32);
    if invalid {
        state.terminal = true;
        return InboundCompleteStep {
            state,
            result: Err(Error::UnexpectedMessage),
        };
    }
    if content_len == 0 {
        state.consecutive_empty_fragments = state.consecutive_empty_fragments + 1;
    } else {
        state.consecutive_empty_fragments = 0;
    }
    if protected {
        state.has_decrypted = true;
    }
    InboundCompleteStep {
        state,
        result: Ok(()),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.protection_active,
        result.has_decrypted == state.has_decrypted,
        result.consecutive_empty_fragments == state.consecutive_empty_fragments,
        result.terminal == state.terminal,
))]
pub fn inbound_activate_protection(mut state: InboundRecordCore) -> InboundRecordCore {
    state.protection_active = true;
    state
}

#[cfg_attr(verus_keep_ghost, verus_spec(result => ensures result.terminal))]
pub fn inbound_fail(mut state: InboundRecordCore) -> InboundRecordCore {
    state.terminal = true;
    state
}

/// Choose the next nonempty sender fragment without exceeding an inner
/// plaintext limit. `inner_limit` includes the content-type octet.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        remaining == 0 || max_content == 0
            ==> result == Err::<usize, Error>(Error::DecodeError),
        remaining > 0 && max_content > 0
            ==> result == Ok::<usize, Error>(if remaining <= max_content {
                remaining
            } else {
                max_content
            }),
        result.is_ok() ==> 0 < result.unwrap(),
        result.is_ok() ==> result.unwrap() <= remaining,
        result.is_ok() ==> result.unwrap() <= max_content,
))]
pub fn next_bounded_fragment_len(remaining: usize, max_content: usize) -> Result<usize, Error> {
    if remaining == 0 || max_content == 0 {
        return Err(Error::DecodeError);
    }
    if remaining <= max_content {
        Ok(remaining)
    } else {
        Ok(max_content)
    }
}

/// Convert rustls's configured maximum wire fragment size into a TLS content
/// cap. The five-byte TLSPlaintext/TLSCiphertext header is transport framing,
/// not content.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_ok() <==> 32 <= wire_limit && wire_limit <= MAX_PLAINTEXT + HEADER_LEN,
        result.is_ok() ==> result.unwrap() + HEADER_LEN == wire_limit,
        result.is_ok() ==> 27 <= result.unwrap() && result.unwrap() <= MAX_PLAINTEXT,
        result.is_err() ==> result == Err::<usize, Error>(Error::IllegalParameter),
))]
pub fn transport_fragment_content_limit(wire_limit: usize) -> Result<usize, Error> {
    if wire_limit < 32 || wire_limit > MAX_PLAINTEXT + HEADER_LEN {
        return Err(Error::IllegalParameter);
    }
    Ok(wire_limit - HEADER_LEN)
}

/// RFC 8449 limits cover the complete TLSInnerPlaintext, so the content cap
/// reserves exactly one octet for the inner content type.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires
        64 <= limit_value_spec(limit) as usize,
        limit_value_spec(limit) as usize <= MAX_INNER_PLAINTEXT,
    ensures
        result + 1 == limit_value_spec(limit) as usize,
        63 <= result && result <= MAX_PLAINTEXT,
))]
pub fn inner_fragment_content_limit(limit: Limit) -> usize {
    limit.0 as usize - 1
}

/// Choose the next nonempty TLS 1.3 fragment under an inner-plaintext limit.
/// `inner_limit` includes the content-type octet.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        remaining == 0 ==> result == Err::<usize, Error>(Error::DecodeError),
        remaining > 0 && limit_value_spec(inner_limit) as usize <= 1
            ==> result == Err::<usize, Error>(Error::IllegalParameter),
        result.is_ok() ==> 0 < result.unwrap(),
        result.is_ok() ==> result.unwrap() <= remaining,
        result.is_ok() ==> result.unwrap() + 1 <= limit_value_spec(inner_limit) as usize,
        result.is_ok() ==> result.unwrap() + 1 <= MAX_INNER_PLAINTEXT,
))]
pub fn next_fragment_len(remaining: usize, inner_limit: Limit) -> Result<usize, Error> {
    if remaining == 0 {
        return Err(Error::DecodeError);
    }
    let limit = if inner_limit.0 as usize <= MAX_INNER_PLAINTEXT {
        inner_limit.0 as usize
    } else {
        MAX_INNER_PLAINTEXT
    };
    if limit <= 1 {
        return Err(Error::IllegalParameter);
    }
    let content_limit = limit - 1;
    next_bounded_fragment_len(remaining, content_limit)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limit(u16);

impl Limit {
    pub fn new(value: usize) -> Result<Self, Error> {
        validate_limit(value).map(Self)
    }

    pub const fn rfc8446() -> Self {
        Self(MAX_INNER_PLAINTEXT as u16)
    }

    pub const fn get(self) -> u16 {
        limit_value(self)
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec(limit_value_spec)))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == limit_value_spec(limit),
))]
pub const fn limit_value(limit: Limit) -> u16 {
    limit.0
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_ok() <==> 64 <= value && value <= MAX_INNER_PLAINTEXT,
        result.is_ok() ==> result.unwrap() as usize == value,
))]
pub(crate) fn validate_limit(value: usize) -> Result<u16, Error> {
    if 64 <= value && value <= MAX_INNER_PLAINTEXT {
        proof! {
            assert(value <= 65_535);
        }
        Ok(value as u16)
    } else {
        Err(Error::IllegalParameter)
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedInner {
    pub content_type: ContentType,
    pub content_len: usize,
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        plaintext.len() > limit_value_spec(receive_limit) as usize
            ==> result == Err::<DecodedInner, Error>(Error::RecordOverflow),
        plaintext.len() == 0
            ==> result == Err::<DecodedInner, Error>(Error::UnexpectedMessage),
        result.is_ok() ==> plaintext.len() <= limit_value_spec(receive_limit) as usize,
        result.is_ok() ==> result.unwrap().content_len < plaintext.len(),
        result.is_ok() ==> plaintext[result.unwrap().content_len as int]
            == result.unwrap().content_type as u8,
        result.is_ok() ==> forall|i: int|
            result.unwrap().content_len < i && i < plaintext.len()
                ==> plaintext[i] == 0,
        result.is_ok() && result.unwrap().content_len == 0
            ==> result.unwrap().content_type as u8 == ContentType::ApplicationData as u8,
))]
pub(crate) fn decode_inner(plaintext: &[u8], receive_limit: Limit) -> Result<DecodedInner, Error> {
    if plaintext.len() > receive_limit.0 as usize {
        return Err(Error::RecordOverflow);
    }
    if plaintext.is_empty() {
        return Err(Error::UnexpectedMessage);
    }
    let mut index = plaintext.len();
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            index <= plaintext.len(),
            forall|i: int| index <= i && i < plaintext.len() ==> plaintext[i] == 0,
        decreases index,
    ))]
    while index > 0 && plaintext[index - 1] == 0 {
        index -= 1;
    }
    if index == 0 {
        return Err(Error::UnexpectedMessage);
    }
    let content_index = index - 1;
    let content_type =
        content_type_from_wire(plaintext[content_index]).ok_or(Error::UnexpectedMessage)?;
    if content_index == 0 && content_type as u8 != ContentType::ApplicationData as u8 {
        return Err(Error::UnexpectedMessage);
    }
    Ok(DecodedInner {
        content_type,
        content_len: content_index,
    })
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result.is_ok() ==> result.unwrap() == content_len + 1 + padding_len,
        result.is_ok() ==> result.unwrap() <= send_limit.0 as usize,
))]
pub(crate) fn checked_inner_len(
    content_len: usize,
    padding_len: usize,
    send_limit: Limit,
) -> Result<usize, Error> {
    let limit = if send_limit.0 as usize <= MAX_INNER_PLAINTEXT {
        send_limit.0 as usize
    } else {
        MAX_INNER_PLAINTEXT
    };
    if content_len >= limit {
        return Err(Error::RecordOverflow);
    }
    let with_type = content_len + 1;
    if padding_len > limit - with_type {
        return Err(Error::RecordOverflow);
    }
    let inner_len = with_type + padding_len;
    Ok(inner_len)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result[0] == iv[0],
        result[1] == iv[1],
        result[2] == iv[2],
        result[3] == iv[3],
        result[4] == iv[4] ^ (sequence >> 56) as u8,
        result[5] == iv[5] ^ (sequence >> 48) as u8,
        result[6] == iv[6] ^ (sequence >> 40) as u8,
        result[7] == iv[7] ^ (sequence >> 32) as u8,
        result[8] == iv[8] ^ (sequence >> 24) as u8,
        result[9] == iv[9] ^ (sequence >> 16) as u8,
        result[10] == iv[10] ^ (sequence >> 8) as u8,
        result[11] == iv[11] ^ sequence as u8,
))]
pub fn make_nonce(iv: &[u8; NONCE_LEN], sequence: u64) -> [u8; NONCE_LEN] {
    [
        iv[0],
        iv[1],
        iv[2],
        iv[3],
        iv[4] ^ (sequence >> 56) as u8,
        iv[5] ^ (sequence >> 48) as u8,
        iv[6] ^ (sequence >> 40) as u8,
        iv[7] ^ (sequence >> 32) as u8,
        iv[8] ^ (sequence >> 24) as u8,
        iv[9] ^ (sequence >> 16) as u8,
        iv[10] ^ (sequence >> 8) as u8,
        iv[11] ^ sequence as u8,
    ]
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsageLimits {
    pub max_records: u64,
    pub max_bytes: u64,
    pub max_failed_opens: u64,
}

impl UsageLimits {
    pub const fn new(max_records: u64, max_bytes: u64, max_failed_opens: u64) -> Self {
        Self {
            max_records,
            max_bytes,
            max_failed_opens,
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub sequence: u64,
    pub records: u64,
    pub bytes: u64,
    pub failed_opens: u64,
}

impl Usage {
    pub fn permits(self, bytes: usize, limits: UsageLimits) -> bool {
        usage_permits(self, bytes, limits)
    }

    pub fn record_success(self, bytes: usize, limits: UsageLimits) -> Self {
        usage_record_success(self, bytes, limits)
    }

    pub fn record_failed_open(self) -> Option<Self> {
        usage_record_failed_open(self)
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec(usage_permits_spec)))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        result == usage_permits_spec(usage, bytes, limits),
        result ==> usage.sequence < u64::MAX,
        result ==> usage.records < limits.max_records,
        result ==> usage.bytes <= limits.max_bytes,
))]
pub fn usage_permits(usage: Usage, bytes: usize, limits: UsageLimits) -> bool {
    usage.sequence < u64::MAX
        && usage.records < limits.max_records
        && usage.bytes <= limits.max_bytes
        && (bytes as u64) <= limits.max_bytes - usage.bytes
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires usage_permits_spec(usage, bytes, _limits),
    ensures
        result.sequence == usage.sequence + 1,
        result.records == usage.records + 1,
        result.bytes == usage.bytes + bytes as u64,
        result.failed_opens == usage.failed_opens,
))]
pub fn usage_record_success(usage: Usage, bytes: usize, _limits: UsageLimits) -> Usage {
    Usage {
        sequence: usage.sequence + 1,
        records: usage.records + 1,
        bytes: usage.bytes + bytes as u64,
        failed_opens: usage.failed_opens,
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures
        usage.failed_opens == u64::MAX ==> result.is_none(),
        usage.failed_opens < u64::MAX ==> result.is_some(),
        result.is_some() ==> result.unwrap().sequence == usage.sequence,
        result.is_some() ==> result.unwrap().records == usage.records,
        result.is_some() ==> result.unwrap().bytes == usage.bytes,
        result.is_some() ==> result.unwrap().failed_opens == usage.failed_opens + 1,
))]
pub fn usage_record_failed_open(usage: Usage) -> Option<Usage> {
    Some(Usage {
        failed_opens: usage.failed_opens.checked_add(1)?,
        ..usage
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_versions_and_limits_are_canonical() {
        assert_eq!(
            plaintext_header(ContentType::Handshake, 4, true)
                .unwrap()
                .legacy_version,
            0x0301
        );
        assert_eq!(
            plaintext_header(ContentType::Alert, 2, false)
                .unwrap()
                .legacy_version,
            0x0303
        );
        assert_eq!(
            plaintext_header(ContentType::Handshake, 0, false),
            Err(Error::DecodeError)
        );
        assert_eq!(
            plaintext_header(ContentType::ApplicationData, MAX_PLAINTEXT + 1, false),
            Err(Error::RecordOverflow)
        );
    }

    #[test]
    fn outbound_scheduler_never_skips_committed_or_control_records() {
        assert_eq!(
            select_next_outbound_record(true, true, true),
            NextOutboundRecord::FinishCommittedApplication
        );
        assert_eq!(
            select_next_outbound_record(false, true, true),
            NextOutboundRecord::Control
        );
        assert_eq!(
            select_next_outbound_record(false, false, true),
            NextOutboundRecord::SealPendingApplication
        );
        assert_eq!(
            select_next_outbound_record(false, false, false),
            NextOutboundRecord::Idle
        );
    }

    #[test]
    fn plaintext_version_is_ignored_but_protected_version_is_aad() {
        let plaintext = RecordHeader {
            content_type: ContentType::Handshake as u8,
            legacy_version: 0xffff,
            length: 4,
        };
        assert_eq!(
            validate_plaintext_header(plaintext),
            Ok(ContentType::Handshake)
        );

        let protected = RecordHeader {
            content_type: ContentType::ApplicationData as u8,
            legacy_version: 0xffff,
            length: 16,
        };
        assert_eq!(validate_protected_header(protected), Ok(()));
        assert_eq!(protected.encode()[1..3], [0xff, 0xff]);
    }

    #[test]
    fn directional_inner_limit_controls_fragment_content() {
        let limit = Limit::new(64).unwrap();
        assert_eq!(next_fragment_len(100, limit), Ok(63));
        assert_eq!(next_fragment_len(63, limit), Ok(63));
        assert_eq!(next_fragment_len(0, limit), Err(Error::DecodeError));
        assert_eq!(next_bounded_fragment_len(70, 27), Ok(27));
    }

    #[test]
    fn only_application_data_may_have_empty_inner_content() {
        assert_eq!(
            decode_inner(&[ContentType::Handshake as u8], Limit::rfc8446()),
            Err(Error::UnexpectedMessage)
        );
        assert_eq!(
            decode_inner(&[ContentType::ApplicationData as u8], Limit::rfc8446()),
            Ok(DecodedInner {
                content_type: ContentType::ApplicationData,
                content_len: 0,
            })
        );
    }

    #[test]
    fn pending_receive_limit_spans_fragmented_messages() {
        let offered = Limit::new(64).unwrap();
        let pending = PendingReceiveLimit::new(offered)
            .observe(65)
            .observe(40);
        assert_eq!(pending.max_inner_seen, 65);
        assert_eq!(pending.resolve(true), Err(Error::RecordOverflow));
        assert_eq!(pending.resolve(false), Ok(None));

        let exact = PendingReceiveLimit::new(offered).observe(64);
        assert_eq!(exact.resolve(true), Ok(Some(offered)));
    }
}
