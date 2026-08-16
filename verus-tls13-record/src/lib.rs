#![no_std]
#![cfg_attr(verus_only, feature(proc_macro_hygiene))]

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(not(verus_only))]
pub const HEADER_LEN: usize = 5;
#[cfg(not(verus_only))]
pub const MAX_CIPHERTEXT_LEN: usize = (1 << 14) + 256;
#[cfg(not(verus_only))]
pub const MAX_WIRE_LEN: usize = HEADER_LEN + MAX_CIPHERTEXT_LEN;
#[cfg(not(verus_only))]
pub const MAX_CONTENT_LEN: usize = 1 << 14;
#[cfg(not(verus_only))]
pub const MAX_INNER_LEN: usize = MAX_CONTENT_LEN + 1;
#[cfg(not(verus_only))]
pub const NONCE_LEN: usize = 12;
#[cfg(not(verus_only))]
pub const MIN_RECORD_SIZE_LIMIT: usize = 64;
#[cfg(not(verus_only))]
pub const MAX_RECORD_SIZE_LIMIT: usize = MAX_INNER_LEN;
#[cfg(not(verus_only))]
pub const TLS13_AEAD_EXPANSION: usize = 16;

#[cfg(verus_only)]
verus! {
pub const HEADER_LEN: usize = 5;
pub const MAX_CIPHERTEXT_LEN: usize = 16640;
pub const MAX_WIRE_LEN: usize = 16645;
pub const MAX_CONTENT_LEN: usize = 16384;
pub const MAX_INNER_LEN: usize = 16385;
pub const NONCE_LEN: usize = 12;
pub const MIN_RECORD_SIZE_LIMIT: usize = 64;
pub const MAX_RECORD_SIZE_LIMIT: usize = MAX_INNER_LEN;
pub const TLS13_AEAD_EXPANSION: usize = 16;
}
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
pub const LEGACY_VERSION_INITIAL_CLIENT_HELLO: u16 = 0x0301;
pub const LEGACY_VERSION_TLS13: u16 = 0x0303;
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_TYPE_END_OF_EARLY_DATA: u8 = 5;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
pub const TRAFFIC_UPDATE_LABEL: &[u8] = b"traffic upd";
pub const TRAFFIC_KEY_LABEL: &[u8] = b"key";
pub const TRAFFIC_IV_LABEL: &[u8] = b"iv";
pub const MAX_HKDF_LABEL_LEN: usize = 514;

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidContentType,
    UnknownProtocolVersion,
    InvalidEmptyPayload,
    MessageTooLarge,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub content_type: u8,
    pub version: u16,
    pub payload_len: usize,
    pub frame_len: usize,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStatus {
    NeedMore { required: usize },
    Invalid(FrameError),
    Complete(Frame),
}

#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                FrameStatus::NeedMore { required } =>
                    required > input@.len() && required <= 16645,
                FrameStatus::Complete(frame) =>
                    frame.frame_len == frame.payload_len + 5
                        && frame.frame_len <= input@.len()
                        && frame.frame_len <= 16645,
                FrameStatus::Invalid(_) => true,
            }
    )
)]
pub fn classify_frame(input: &[u8]) -> FrameStatus {
    if input.len() < 5 {
        return FrameStatus::NeedMore { required: 5 };
    }

    let content_type = input[0];
    if !is_content_type(content_type) {
        return FrameStatus::Invalid(FrameError::InvalidContentType);
    }

    // RFC 8446 section 5.1 requires receivers to ignore this field.  Keeping
    // the uninterpreted value lets a protected record authenticate the exact
    // received header rather than a reconstructed preferred version.
    let version = ((input[1] as u16) << 8) | input[2] as u16;

    let payload_len = ((input[3] as usize) << 8) | input[4] as usize;
    if content_type != 0x17 && payload_len == 0 {
        return FrameStatus::Invalid(FrameError::InvalidEmptyPayload);
    }
    if payload_len > 16640 {
        return FrameStatus::Invalid(FrameError::MessageTooLarge);
    }

    let frame_len = 5 + payload_len;
    if input.len() < frame_len {
        return FrameStatus::NeedMore {
            required: frame_len,
        };
    }

    FrameStatus::Complete(Frame {
        content_type,
        version,
        payload_len,
        frame_len,
    })
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerError {
    Empty,
    InvalidContentType,
    MessageTooLarge,
    OutputTooShort,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedInner {
    pub content_type: u8,
    pub content_len: usize,
    pub encoded_len: usize,
}

#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                Ok(encoded_len) =>
                    encoded_len == content_len + 1
                        && encoded_len <= 16385
                        && encoded_len <= output@.len(),
                Err(_) => true,
            }
    )
)]
pub fn encode_inner(
    output: &mut [u8],
    content_len: usize,
    content_type: u8,
) -> Result<usize, InnerError> {
    encode_inner_padded(output, content_len, content_type, 0, MAX_RECORD_SIZE_LIMIT)
}

/// Encode the TLSInnerPlaintext trailer and zero padding in caller-owned storage.
#[cfg_attr(verus_only, verus_verify)]
#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                Ok(encoded_len) =>
                    encoded_len == content_len + 1 + padding_len
                        && encoded_len <= inner_limit
                        && encoded_len <= 16385
                        && encoded_len <= output@.len(),
                Err(_) => true,
            }
    )
)]
pub fn encode_inner_padded(
    output: &mut [u8],
    content_len: usize,
    content_type: u8,
    padding_len: usize,
    inner_limit: usize,
) -> Result<usize, InnerError> {
    if content_len > MAX_CONTENT_LEN {
        return Err(InnerError::MessageTooLarge);
    }
    if !is_inner_content_type(content_type) {
        return Err(InnerError::InvalidContentType);
    }
    if !(MIN_RECORD_SIZE_LIMIT..=MAX_RECORD_SIZE_LIMIT).contains(&inner_limit) {
        return Err(InnerError::MessageTooLarge);
    }
    let Some(content_and_type_len) = content_len.checked_add(1) else {
        return Err(InnerError::MessageTooLarge);
    };
    let Some(encoded_len) = content_and_type_len.checked_add(padding_len) else {
        return Err(InnerError::MessageTooLarge);
    };
    if encoded_len > inner_limit || encoded_len > MAX_INNER_LEN {
        return Err(InnerError::MessageTooLarge);
    }
    if output.len() < encoded_len || content_len >= encoded_len {
        return Err(InnerError::OutputTooShort);
    }
    output[content_len] = content_type;
    let mut index = content_len + 1;
    #[cfg_attr(
        verus_only,
        verus_spec(
            invariant
                content_len + 1 <= index,
                index <= encoded_len,
                encoded_len <= output@.len(),
            decreases encoded_len - index,
        )
    )]
    while index < encoded_len {
        output[index] = 0;
        index += 1;
    }
    Ok(encoded_len)
}

#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                Ok(decoded) =>
                    decoded.content_len < input@.len()
                        && decoded.encoded_len == input@.len()
                        && decoded.encoded_len <= 16385,
                Err(_) => true,
            }
    )
)]
pub fn decode_inner(input: &[u8]) -> Result<DecodedInner, InnerError> {
    decode_inner_with_limit(input, MAX_RECORD_SIZE_LIMIT)
}

#[cfg_attr(verus_only, verus_verify)]
#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                Ok(decoded) =>
                    decoded.content_len < input@.len()
                        && decoded.encoded_len == input@.len()
                        && decoded.encoded_len <= inner_limit
                        && decoded.encoded_len <= 16385,
                Err(_) => true,
            }
    )
)]
pub fn decode_inner_with_limit(
    input: &[u8],
    inner_limit: usize,
) -> Result<DecodedInner, InnerError> {
    if input.is_empty() {
        return Err(InnerError::Empty);
    }
    if !(MIN_RECORD_SIZE_LIMIT..=MAX_RECORD_SIZE_LIMIT).contains(&inner_limit)
        || input.len() > inner_limit
        || input.len() > MAX_INNER_LEN
    {
        return Err(InnerError::MessageTooLarge);
    }

    let mut end = input.len();
    #[cfg_attr(
        verus_only,
        verus_spec(
            invariant
                end <= input@.len(),
            decreases end,
        )
    )]
    while end > 0 && input[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(InnerError::Empty);
    }

    let content_type = input[end - 1];
    if !is_inner_content_type(content_type) {
        return Err(InnerError::InvalidContentType);
    }

    Ok(DecodedInner {
        content_type,
        content_len: end - 1,
        encoded_len: input.len(),
    })
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sequence {
    next: u64,
}

#[cfg_attr(verus_only, verus_spec(result => ensures result.current() == 0))]
pub fn new_sequence() -> Sequence {
    Sequence { next: 0 }
}

impl Sequence {
    #[cfg_attr(verus_only, verus_verify(dual_spec))]
    #[cfg_attr(verus_only, verus_spec(returns self.current()))]
    pub fn current(&self) -> u64 {
        self.next
    }

    #[cfg_attr(
        verus_only,
        verus_spec(result =>
            ensures
                match result {
                    Some((value, next)) =>
                        value == self.current()
                            && self.current() < u64::MAX
                            && next.current() == self.current() + 1,
                    None => self.current() == u64::MAX,
                }
        )
    )]
    pub fn advance(self) -> Option<(u64, Self)> {
        if self.next == u64::MAX {
            return None;
        }
        let current = self.next;
        Some((current, Self { next: current + 1 }))
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    PayloadTooLarge,
    UnexpectedOuterType,
}

/// Serialize a record header without interpreting the legacy version field.
#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            match result {
                Ok(header) =>
                    header@[0] == content_type
                        && header@[1] == (version >> 8) as u8
                        && header@[2] == version as u8
                        && header@[3] == (payload_len >> 8) as u8
                        && header@[4] == payload_len as u8,
                Err(_) => payload_len > 65535,
            }
    )
)]
pub fn record_header(
    content_type: u8,
    version: u16,
    payload_len: usize,
) -> Result<[u8; HEADER_LEN], HeaderError> {
    if payload_len > u16::MAX as usize {
        return Err(HeaderError::PayloadTooLarge);
    }
    Ok([
        content_type,
        (version >> 8) as u8,
        version as u8,
        (payload_len >> 8) as u8,
        payload_len as u8,
    ])
}

/// Construct the canonical header used by a protected record sender.
pub fn protected_header(payload_len: usize) -> Result<[u8; HEADER_LEN], HeaderError> {
    record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_VERSION_TLS13,
        payload_len,
    )
}

/// Return the exact received protected header for use as AEAD additional data.
///
/// The outer content type is rejected before a provider call.  The version is
/// deliberately not validated or normalized.
pub fn received_protected_header(
    content_type: u8,
    version: u16,
    payload_len: usize,
) -> Result<[u8; HEADER_LEN], HeaderError> {
    if content_type != CONTENT_TYPE_APPLICATION_DATA {
        return Err(HeaderError::UnexpectedOuterType);
    }
    record_header(content_type, version, payload_len)
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSizeLimit {
    value: u16,
}

impl RecordSizeLimit {
    #[cfg_attr(verus_only, verus_verify)]
    pub fn new(value: usize) -> Option<Self> {
        if !(MIN_RECORD_SIZE_LIMIT..=MAX_RECORD_SIZE_LIMIT).contains(&value) {
            return None;
        }
        Some(Self {
            value: value as u16,
        })
    }

    #[cfg_attr(verus_only, verus_verify(dual_spec))]
    pub fn get(self) -> usize {
        self.value as usize
    }
}

impl Default for RecordSizeLimit {
    fn default() -> Self {
        Self {
            value: MAX_RECORD_SIZE_LIMIT as u16,
        }
    }
}

/// RFC 8449 limits are directional: the peer's value limits sends and the
/// local value limits receives.
#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectionalLimits {
    pub send_inner_limit: RecordSizeLimit,
    pub receive_inner_limit: RecordSizeLimit,
}

impl DirectionalLimits {
    pub fn negotiated(
        peer_advertised: Option<usize>,
        local_advertised: Option<usize>,
    ) -> Option<Self> {
        let send_inner_limit = match peer_advertised {
            Some(value) => RecordSizeLimit::new(value)?,
            None => RecordSizeLimit::default(),
        };
        let receive_inner_limit = match local_advertised {
            Some(value) => RecordSizeLimit::new(value)?,
            None => RecordSizeLimit::default(),
        };
        Some(Self {
            send_inner_limit,
            receive_inner_limit,
        })
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsLcSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLimits {
    pub max_records: u64,
    pub max_bytes: u64,
    pub max_failed_opens: u64,
    pub expansion: usize,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLimitError {
    ZeroLimit,
    LooserOverride,
    ExpansionChanged,
}

impl ProviderLimits {
    /// Conservative AWS-LC TLS 1.3 usage contracts for the named suites.
    pub fn aws_lc(suite: AwsLcSuite) -> Self {
        let max_records = match suite {
            AwsLcSuite::Aes128GcmSha256 | AwsLcSuite::Aes256GcmSha384 => 1 << 24,
            AwsLcSuite::Chacha20Poly1305Sha256 => u64::MAX - 1,
        };
        let max_bytes = match suite {
            AwsLcSuite::Aes128GcmSha256 | AwsLcSuite::Aes256GcmSha384 => {
                (1u64 << 24) * MAX_CIPHERTEXT_LEN as u64
            }
            AwsLcSuite::Chacha20Poly1305Sha256 => u64::MAX,
        };
        Self {
            max_records,
            max_bytes,
            max_failed_opens: 1 << 36,
            expansion: TLS13_AEAD_EXPANSION,
        }
    }

    pub fn legacy(max_records: u64, expansion: usize) -> Self {
        Self {
            max_records,
            max_bytes: u64::MAX,
            max_failed_opens: u64::MAX,
            expansion,
        }
    }

    /// Apply rustls's sequence ceiling to provider bounds.
    pub fn with_max_records(self, max_records: u64) -> Self {
        Self {
            max_records,
            ..self
        }
    }

    /// Caller policy can lower provider limits but cannot alter expansion.
    pub fn tighten(self, requested: Self) -> Result<Self, ProviderLimitError> {
        if requested.max_records == 0 || requested.max_bytes == 0 || requested.max_failed_opens == 0
        {
            return Err(ProviderLimitError::ZeroLimit);
        }
        if requested.expansion != self.expansion {
            return Err(ProviderLimitError::ExpansionChanged);
        }
        if requested.max_records > self.max_records
            || requested.max_bytes > self.max_bytes
            || requested.max_failed_opens > self.max_failed_opens
        {
            return Err(ProviderLimitError::LooserOverride);
        }
        Ok(requested)
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochState {
    Inactive,
    Prepared,
    Active,
    Terminal,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageError {
    InvalidState,
    RecordLimit,
    ByteLimit,
    FailedOpenLimit,
    SequenceExhausted,
    InvalidLength,
    DirectionalLimit,
    StalePermit,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenPermit {
    pub epoch: u64,
    pub sequence: u64,
    ciphertext_len: usize,
}

/// Provider-call eligibility and nonwrapping sequence state for one direction.
#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficEpoch {
    state: EpochState,
    epoch: u64,
    sequence: Sequence,
    records: u64,
    bytes: u64,
    failed_opens: u64,
    limits: ProviderLimits,
}

impl TrafficEpoch {
    pub fn new() -> Self {
        Self {
            state: EpochState::Inactive,
            epoch: 0,
            sequence: new_sequence(),
            records: 0,
            bytes: 0,
            failed_opens: 0,
            limits: ProviderLimits::legacy(u64::MAX - 1, 0),
        }
    }

    pub fn state(&self) -> EpochState {
        self.state
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sequence(&self) -> u64 {
        self.sequence.current()
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn max_records(&self) -> u64 {
        self.limits.max_records
    }

    pub fn failed_opens(&self) -> u64 {
        self.failed_opens
    }

    pub fn prepare(&mut self, limits: ProviderLimits) -> Result<(), UsageError> {
        if self.state == EpochState::Terminal {
            return Err(UsageError::InvalidState);
        }
        if limits.max_records == 0 || limits.max_bytes == 0 || limits.max_failed_opens == 0 {
            return Err(UsageError::InvalidLength);
        }
        if self.state != EpochState::Inactive {
            self.epoch = self
                .epoch
                .checked_add(1)
                .ok_or(UsageError::SequenceExhausted)?;
        }
        self.sequence = new_sequence();
        self.records = 0;
        self.bytes = 0;
        self.failed_opens = 0;
        self.limits = limits;
        self.state = EpochState::Prepared;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), UsageError> {
        if self.state != EpochState::Prepared {
            return Err(UsageError::InvalidState);
        }
        self.state = EpochState::Active;
        Ok(())
    }

    fn check_call(&self, ciphertext_len: usize) -> Result<(), UsageError> {
        if self.state != EpochState::Active {
            return Err(UsageError::InvalidState);
        }
        if self.records >= self.limits.max_records {
            return Err(UsageError::RecordLimit);
        }
        if self.failed_opens >= self.limits.max_failed_opens {
            return Err(UsageError::FailedOpenLimit);
        }
        if self.sequence.current() == u64::MAX {
            return Err(UsageError::SequenceExhausted);
        }
        let ciphertext_len = ciphertext_len as u64;
        if self
            .bytes
            .checked_add(ciphertext_len)
            .filter(|total| *total <= self.limits.max_bytes)
            .is_none()
        {
            return Err(UsageError::ByteLimit);
        }
        Ok(())
    }

    fn check_lengths(
        &self,
        inner_len: usize,
        ciphertext_len: usize,
        directional_limit: RecordSizeLimit,
    ) -> Result<(), UsageError> {
        if inner_len == 0
            || inner_len > MAX_INNER_LEN
            || ciphertext_len > MAX_CIPHERTEXT_LEN
            || ciphertext_len.checked_sub(inner_len) != Some(self.limits.expansion)
        {
            return Err(UsageError::InvalidLength);
        }
        if inner_len > directional_limit.get() {
            return Err(UsageError::DirectionalLimit);
        }
        Ok(())
    }

    /// Reserve and advance one seal call before invoking the provider.
    pub fn issue_seal(
        &mut self,
        inner_len: usize,
        ciphertext_len: usize,
        send_limit: RecordSizeLimit,
    ) -> Result<u64, UsageError> {
        self.check_lengths(inner_len, ciphertext_len, send_limit)?;
        self.check_call(ciphertext_len)?;
        let (sequence, next) = self
            .sequence
            .advance()
            .ok_or(UsageError::SequenceExhausted)?;
        self.sequence = next;
        self.records += 1;
        self.bytes += ciphertext_len as u64;
        Ok(sequence)
    }

    /// Sequence/accounting path for rustls profiles outside the selected TLS
    /// 1.3 record format.  It intentionally makes no TLS 1.3 length claim.
    pub fn issue_legacy_seal(&mut self, ciphertext_len: usize) -> Result<u64, UsageError> {
        if self.state != EpochState::Active {
            return Err(UsageError::InvalidState);
        }
        let (sequence, next) = self
            .sequence
            .advance()
            .ok_or(UsageError::SequenceExhausted)?;
        self.sequence = next;
        self.records += 1;
        self.bytes += ciphertext_len as u64;
        Ok(sequence)
    }

    /// Check one open call without advancing until authentication succeeds.
    pub fn permit_open(
        &self,
        ciphertext_len: usize,
        receive_limit: RecordSizeLimit,
    ) -> Result<OpenPermit, UsageError> {
        let inner_len = ciphertext_len
            .checked_sub(self.limits.expansion)
            .ok_or(UsageError::InvalidLength)?;
        self.check_lengths(inner_len, ciphertext_len, receive_limit)?;
        self.check_call(ciphertext_len)?;
        Ok(OpenPermit {
            epoch: self.epoch,
            sequence: self.sequence.current(),
            ciphertext_len,
        })
    }

    pub fn permit_legacy_open(&self, ciphertext_len: usize) -> Result<OpenPermit, UsageError> {
        self.check_call(ciphertext_len)?;
        Ok(OpenPermit {
            epoch: self.epoch,
            sequence: self.sequence.current(),
            ciphertext_len,
        })
    }

    pub fn commit_open(&mut self, permit: OpenPermit) -> Result<(), UsageError> {
        if self.state != EpochState::Active
            || permit.epoch != self.epoch
            || permit.sequence != self.sequence.current()
        {
            return Err(UsageError::StalePermit);
        }
        let (_, next) = self
            .sequence
            .advance()
            .ok_or(UsageError::SequenceExhausted)?;
        self.sequence = next;
        self.records += 1;
        self.bytes += permit.ciphertext_len as u64;
        Ok(())
    }

    pub fn fail_open(&mut self, permit: OpenPermit) -> Result<(), UsageError> {
        if self.state != EpochState::Active
            || permit.epoch != self.epoch
            || permit.sequence != self.sequence.current()
        {
            return Err(UsageError::StalePermit);
        }
        self.failed_opens = self
            .failed_opens
            .checked_add(1)
            .ok_or(UsageError::FailedOpenLimit)?;
        self.state = EpochState::Terminal;
        Ok(())
    }

    pub fn fail_seal(&mut self) {
        self.state = EpochState::Terminal;
    }

    pub fn terminate(&mut self) {
        self.state = EpochState::Terminal;
    }
}

impl Default for TrafficEpoch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedStatus {
    NeedMore { consumed: usize, required: usize },
    Record { consumed: usize, frame: Frame },
    Invalid { consumed: usize, error: FrameError },
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishStatus {
    Clean,
    Truncated { required: usize },
    RecordPending(Frame),
    Invalid(FrameError),
}

/// A fixed-capacity public stream framer.  Callers repeatedly call `feed`,
/// process `record`, and then call `discard_record` for coalesced input.
pub struct StreamFramer {
    buffer: [u8; MAX_WIRE_LEN],
    used: usize,
}

impl StreamFramer {
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_WIRE_LEN],
            used: 0,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.used
    }

    pub fn feed(&mut self, input: &[u8]) -> FeedStatus {
        let mut consumed = 0;
        loop {
            match classify_frame(&self.buffer[..self.used]) {
                FrameStatus::Complete(frame) => {
                    return FeedStatus::Record { consumed, frame };
                }
                FrameStatus::Invalid(error) => {
                    return FeedStatus::Invalid { consumed, error };
                }
                FrameStatus::NeedMore { required } => {
                    if consumed == input.len() {
                        return FeedStatus::NeedMore { consumed, required };
                    }
                    let take = core::cmp::min(required - self.used, input.len() - consumed);
                    self.buffer[self.used..self.used + take]
                        .copy_from_slice(&input[consumed..consumed + take]);
                    self.used += take;
                    consumed += take;
                }
            }
        }
    }

    pub fn record(&self) -> Option<&[u8]> {
        match classify_frame(&self.buffer[..self.used]) {
            FrameStatus::Complete(frame) => Some(&self.buffer[..frame.frame_len]),
            _ => None,
        }
    }

    pub fn discard_record(&mut self) -> bool {
        if self.record().is_none() {
            return false;
        }
        self.used = 0;
        true
    }

    pub fn finish(&self) -> FinishStatus {
        if self.used == 0 {
            return FinishStatus::Clean;
        }
        match classify_frame(&self.buffer[..self.used]) {
            FrameStatus::NeedMore { required } => FinishStatus::Truncated { required },
            FrameStatus::Invalid(error) => FinishStatus::Invalid(error),
            FrameStatus::Complete(frame) => FinishStatus::RecordPending(frame),
        }
    }
}

impl Default for StreamFramer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Milestone {
    ClientHello,
    ServerHello,
    Finished,
    KeyUpdate { request_update: bool },
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    Interleaved,
    EmptyOutboundFragment,
    ActivationNotAtRecordBoundary,
    InvalidKeyUpdateLength,
    InvalidKeyUpdateRequest,
}

/// Fixed handshake framing state.  The declared 24-bit body length is only a
/// counter; it never selects an allocation size.
#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeTracker {
    header: [u8; 4],
    header_len: usize,
    current_type: u8,
    remaining: u32,
    key_update_request: u8,
}

impl HandshakeTracker {
    pub const fn new() -> Self {
        Self {
            header: [0; 4],
            header_len: 0,
            current_type: 0,
            remaining: 0,
            key_update_request: 0,
        }
    }

    pub fn is_aligned(&self) -> bool {
        self.header_len == 0 && self.remaining == 0
    }

    fn completed_milestone(&self) -> Result<Option<Milestone>, HandshakeError> {
        match self.current_type {
            HANDSHAKE_TYPE_CLIENT_HELLO => Ok(Some(Milestone::ClientHello)),
            HANDSHAKE_TYPE_SERVER_HELLO => Ok(Some(Milestone::ServerHello)),
            HANDSHAKE_TYPE_FINISHED => Ok(Some(Milestone::Finished)),
            HANDSHAKE_TYPE_KEY_UPDATE => match self.key_update_request {
                0 => Ok(Some(Milestone::KeyUpdate {
                    request_update: false,
                })),
                1 => Ok(Some(Milestone::KeyUpdate {
                    request_update: true,
                })),
                _ => Err(HandshakeError::InvalidKeyUpdateRequest),
            },
            HANDSHAKE_TYPE_END_OF_EARLY_DATA => Ok(None),
            _ => Ok(None),
        }
    }

    /// Observe one complete content fragment.  Named activation milestones
    /// must complete on its final byte.
    pub fn observe_record(
        &mut self,
        content_type: u8,
        payload: &[u8],
        outbound: bool,
    ) -> Result<Option<Milestone>, HandshakeError> {
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return if self.is_aligned() {
                Ok(None)
            } else {
                Err(HandshakeError::Interleaved)
            };
        }
        if outbound && payload.is_empty() {
            return Err(HandshakeError::EmptyOutboundFragment);
        }

        let mut milestone = None;
        let mut index = 0;
        while index < payload.len() {
            if self.remaining > 0 {
                let available = payload.len() - index;
                let take = core::cmp::min(available, self.remaining as usize);
                if self.current_type == HANDSHAKE_TYPE_KEY_UPDATE && self.remaining == 1 {
                    self.key_update_request = payload[index];
                }
                self.remaining -= take as u32;
                index += take;
                if self.remaining == 0 {
                    milestone = self.completed_milestone()?;
                    if milestone.is_some() && index != payload.len() {
                        return Err(HandshakeError::ActivationNotAtRecordBoundary);
                    }
                }
                continue;
            }

            while self.header_len < self.header.len() && index < payload.len() {
                self.header[self.header_len] = payload[index];
                self.header_len += 1;
                index += 1;
            }
            if self.header_len < self.header.len() {
                break;
            }

            self.current_type = self.header[0];
            self.remaining = ((self.header[1] as u32) << 16)
                | ((self.header[2] as u32) << 8)
                | self.header[3] as u32;
            self.header_len = 0;
            self.key_update_request = 0;
            if self.current_type == HANDSHAKE_TYPE_KEY_UPDATE && self.remaining != 1 {
                return Err(HandshakeError::InvalidKeyUpdateLength);
            }
            if self.remaining == 0 {
                milestone = self.completed_milestone()?;
                if milestone.is_some() && index != payload.len() {
                    return Err(HandshakeError::ActivationNotAtRecordBoundary);
                }
            }
        }
        Ok(milestone)
    }
}

impl Default for HandshakeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    UnexpectedMessage,
    DecodeError,
    IllegalParameter,
    Closed,
    KeyUpdateBeforeFinished,
    KeyUpdateInProgress,
    PendingKeyUpdateResponse,
    EpochExhausted,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertAction {
    PeerClosed,
    UserCanceled,
    Fatal(u8),
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcsAction {
    Drop,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertSpec {
    pub level: u8,
    pub description: u8,
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertFlight {
    pub alerts: [AlertSpec; 2],
    pub len: usize,
}

/// Selected-profile lifecycle and key-update ordering state.
#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionControl {
    local_finished: bool,
    peer_finished: bool,
    read_closed: bool,
    write_closed: bool,
    fatal: bool,
    pending_response: bool,
    read_update_pending: bool,
    write_update_pending: bool,
    read_epoch: u64,
    write_epoch: u64,
}

impl ConnectionControl {
    pub const fn new() -> Self {
        Self {
            local_finished: false,
            peer_finished: false,
            read_closed: false,
            write_closed: false,
            fatal: false,
            pending_response: false,
            read_update_pending: false,
            write_update_pending: false,
            read_epoch: 0,
            write_epoch: 0,
        }
    }

    pub fn observe_milestone(&mut self, milestone: Milestone, outbound: bool) {
        match milestone {
            Milestone::Finished if outbound => self.local_finished = true,
            Milestone::Finished => self.peer_finished = true,
            _ => {}
        }
    }

    pub fn local_finished(&self) -> bool {
        self.local_finished
    }

    pub fn peer_finished(&self) -> bool {
        self.peer_finished
    }

    pub fn read_epoch(&self) -> u64 {
        self.read_epoch
    }

    pub fn write_epoch(&self) -> u64 {
        self.write_epoch
    }

    pub fn should_discard_inbound(&self) -> bool {
        self.read_closed || self.fatal
    }

    pub fn can_send_application_data(&self) -> Result<(), ConnectionError> {
        if self.fatal || self.write_closed {
            return Err(ConnectionError::Closed);
        }
        if self.pending_response {
            return Err(ConnectionError::PendingKeyUpdateResponse);
        }
        Ok(())
    }

    pub fn receive_ccs(
        &mut self,
        protected: bool,
        payload: &[u8],
    ) -> Result<CcsAction, ConnectionError> {
        if self.fatal || self.read_closed || protected || payload != [1] || self.peer_finished {
            self.enter_fatal();
            return Err(ConnectionError::UnexpectedMessage);
        }
        Ok(CcsAction::Drop)
    }

    pub fn receive_alert(&mut self, payload: &[u8]) -> Result<AlertAction, ConnectionError> {
        if self.fatal || self.read_closed {
            return Err(ConnectionError::Closed);
        }
        if payload.len() != 2 {
            self.enter_fatal();
            return Err(ConnectionError::DecodeError);
        }
        let level = payload[0];
        let description = payload[1];
        match (level, description) {
            (1, 0) => {
                self.read_closed = true;
                Ok(AlertAction::PeerClosed)
            }
            (1, 90) => Ok(AlertAction::UserCanceled),
            (1, _) => {
                self.enter_fatal();
                Err(ConnectionError::DecodeError)
            }
            (2, _) => {
                self.enter_fatal();
                Ok(AlertAction::Fatal(description))
            }
            _ => {
                self.enter_fatal();
                Err(ConnectionError::IllegalParameter)
            }
        }
    }

    pub fn send_close_notify(&mut self) -> Result<AlertSpec, ConnectionError> {
        if self.fatal || self.write_closed {
            return Err(ConnectionError::Closed);
        }
        self.write_closed = true;
        Ok(AlertSpec {
            level: 1,
            description: 0,
        })
    }

    pub fn send_user_canceled(&mut self) -> Result<AlertFlight, ConnectionError> {
        if self.fatal || self.write_closed {
            return Err(ConnectionError::Closed);
        }
        let user_canceled = AlertSpec {
            level: 1,
            description: 90,
        };
        let close_notify = AlertSpec {
            level: 1,
            description: 0,
        };
        self.write_closed = true;
        if self.local_finished && self.peer_finished {
            Ok(AlertFlight {
                alerts: [close_notify, close_notify],
                len: 1,
            })
        } else {
            Ok(AlertFlight {
                alerts: [user_canceled, close_notify],
                len: 2,
            })
        }
    }

    pub fn begin_inbound_key_update(
        &mut self,
        request_update: bool,
    ) -> Result<(), ConnectionError> {
        if self.fatal || self.read_closed {
            return Err(ConnectionError::Closed);
        }
        if !self.peer_finished {
            self.enter_fatal();
            return Err(ConnectionError::KeyUpdateBeforeFinished);
        }
        if self.read_update_pending {
            self.enter_fatal();
            return Err(ConnectionError::KeyUpdateInProgress);
        }
        self.read_update_pending = true;
        if request_update {
            self.pending_response = true;
        }
        Ok(())
    }

    pub fn commit_inbound_key_update(&mut self) -> Result<u64, ConnectionError> {
        if !self.read_update_pending {
            return Err(ConnectionError::KeyUpdateInProgress);
        }
        self.read_epoch = self
            .read_epoch
            .checked_add(1)
            .ok_or(ConnectionError::EpochExhausted)?;
        self.read_update_pending = false;
        Ok(self.read_epoch)
    }

    pub fn begin_outbound_key_update(
        &mut self,
        handshake_aligned: bool,
    ) -> Result<(), ConnectionError> {
        if self.fatal || self.write_closed {
            return Err(ConnectionError::Closed);
        }
        if !self.local_finished {
            return Err(ConnectionError::KeyUpdateBeforeFinished);
        }
        if !handshake_aligned || self.write_update_pending {
            return Err(ConnectionError::KeyUpdateInProgress);
        }
        self.write_update_pending = true;
        Ok(())
    }

    pub fn commit_outbound_key_update(&mut self) -> Result<u64, ConnectionError> {
        if !self.write_update_pending {
            return Err(ConnectionError::KeyUpdateInProgress);
        }
        self.write_epoch = self
            .write_epoch
            .checked_add(1)
            .ok_or(ConnectionError::EpochExhausted)?;
        self.write_update_pending = false;
        self.pending_response = false;
        Ok(self.write_epoch)
    }

    pub fn accepts_read_epoch(&self, epoch: u64) -> bool {
        !self.fatal && epoch == self.read_epoch
    }

    pub fn accepts_write_epoch(&self, epoch: u64) -> bool {
        !self.fatal && epoch == self.write_epoch
    }

    pub fn enter_fatal(&mut self) {
        self.fatal = true;
        self.read_closed = true;
        self.write_closed = true;
        self.pending_response = false;
        self.read_update_pending = false;
        self.write_update_pending = false;
    }
}

impl Default for ConnectionControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(verus_only, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HkdfLabelError {
    OutputLength,
    LabelLength,
    ContextLength,
    BufferTooShort,
}

/// Encode RFC 8446 `HkdfLabel` with the mandatory `tls13 ` prefix.
pub fn encode_hkdf_label(
    output: &mut [u8],
    output_len: usize,
    label: &[u8],
    context: &[u8],
) -> Result<usize, HkdfLabelError> {
    const PREFIX: &[u8] = b"tls13 ";
    if output_len > u16::MAX as usize {
        return Err(HkdfLabelError::OutputLength);
    }
    let full_label_len = PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(HkdfLabelError::LabelLength)?;
    if full_label_len > u8::MAX as usize {
        return Err(HkdfLabelError::LabelLength);
    }
    if context.len() > u8::MAX as usize {
        return Err(HkdfLabelError::ContextLength);
    }
    let encoded_len = 2 + 1 + full_label_len + 1 + context.len();
    if output.len() < encoded_len {
        return Err(HkdfLabelError::BufferTooShort);
    }

    output[..2].copy_from_slice(&(output_len as u16).to_be_bytes());
    output[2] = full_label_len as u8;
    let mut cursor = 3;
    output[cursor..cursor + PREFIX.len()].copy_from_slice(PREFIX);
    cursor += PREFIX.len();
    output[cursor..cursor + label.len()].copy_from_slice(label);
    cursor += label.len();
    output[cursor] = context.len() as u8;
    cursor += 1;
    output[cursor..cursor + context.len()].copy_from_slice(context);
    Ok(encoded_len)
}

#[cfg_attr(
    verus_only,
    verus_spec(result =>
        ensures
            result@[0] == iv@[0],
            result@[1] == iv@[1],
            result@[2] == iv@[2],
            result@[3] == iv@[3],
            result@[4] == iv@[4] ^ (sequence >> 56) as u8,
            result@[5] == iv@[5] ^ (sequence >> 48) as u8,
            result@[6] == iv@[6] ^ (sequence >> 40) as u8,
            result@[7] == iv@[7] ^ (sequence >> 32) as u8,
            result@[8] == iv@[8] ^ (sequence >> 24) as u8,
            result@[9] == iv@[9] ^ (sequence >> 16) as u8,
            result@[10] == iv@[10] ^ (sequence >> 8) as u8,
            result@[11] == iv@[11] ^ sequence as u8,
    )
)]
pub fn nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
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

#[cfg(verus_only)]
verus! {
#[verifier::bit_vector]
proof fn nonce_suffix_is_injective(
    iv4: u8,
    iv5: u8,
    iv6: u8,
    iv7: u8,
    iv8: u8,
    iv9: u8,
    iv10: u8,
    iv11: u8,
    first: u64,
    second: u64,
) by(bit_vector)
    ensures
        first == second
            || iv4 ^ (first >> 56) as u8 != iv4 ^ (second >> 56) as u8
            || iv5 ^ (first >> 48) as u8 != iv5 ^ (second >> 48) as u8
            || iv6 ^ (first >> 40) as u8 != iv6 ^ (second >> 40) as u8
            || iv7 ^ (first >> 32) as u8 != iv7 ^ (second >> 32) as u8
            || iv8 ^ (first >> 24) as u8 != iv8 ^ (second >> 24) as u8
            || iv9 ^ (first >> 16) as u8 != iv9 ^ (second >> 16) as u8
            || iv10 ^ (first >> 8) as u8 != iv10 ^ (second >> 8) as u8
            || iv11 ^ first as u8 != iv11 ^ second as u8,
{
}
}

#[cfg_attr(verus_only, verus_verify(dual_spec))]
#[cfg_attr(verus_only, verus_spec(returns is_content_type(value)))]
fn is_content_type(value: u8) -> bool {
    matches!(value, 0x14..=0x18)
}

#[cfg_attr(verus_only, verus_verify(dual_spec))]
fn is_inner_content_type(value: u8) -> bool {
    matches!(value, 0x14..=0x17)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_incremental_and_bounded() {
        assert_eq!(
            classify_frame(&[0x16, 0x03]),
            FrameStatus::NeedMore { required: 5 }
        );
        assert_eq!(
            classify_frame(&[0x16, 0x03, 0x03, 0x00, 0x01]),
            FrameStatus::NeedMore { required: 6 }
        );
        assert!(matches!(
            classify_frame(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x01]),
            FrameStatus::Complete(Frame { frame_len: 6, .. })
        ));
        assert_eq!(
            classify_frame(&[0x17, 0x03, 0x03, 0x41, 0x01]),
            FrameStatus::Invalid(FrameError::MessageTooLarge)
        );
        assert!(matches!(
            classify_frame(&[0x17, 0xaa, 0x55, 0x00, 0x01, 0x00]),
            FrameStatus::Complete(Frame {
                version: 0xaa55,
                ..
            })
        ));
    }

    #[test]
    fn inner_codec_handles_zero_padding() {
        let mut encoded = [1, 2, 0];
        assert_eq!(encode_inner(&mut encoded, 2, 0x16), Ok(3));
        assert_eq!(
            decode_inner(&[1, 2, 0x16, 0, 0]),
            Ok(DecodedInner {
                content_type: 0x16,
                content_len: 2,
                encoded_len: 5,
            })
        );

        let mut padded = [0xff; 8];
        assert_eq!(
            encode_inner_padded(&mut padded, 2, CONTENT_TYPE_ALERT, 3, 64),
            Ok(6)
        );
        assert_eq!(&padded[..6], &[0xff, 0xff, CONTENT_TYPE_ALERT, 0, 0, 0]);
        assert_eq!(
            decode_inner_with_limit(&padded[..6], 64),
            Ok(DecodedInner {
                content_type: CONTENT_TYPE_ALERT,
                content_len: 2,
                encoded_len: 6,
            })
        );
    }

    #[test]
    fn sequence_refuses_wrap() {
        let mut sequence = new_sequence();
        let (value, next) = sequence.advance().unwrap();
        sequence = next;
        assert_eq!(value, 0);
        assert_eq!(sequence.current(), 1);
        sequence.next = u64::MAX;
        assert_eq!(sequence.advance(), None);
        assert_eq!(sequence.current(), u64::MAX);
    }

    #[test]
    fn nonce_uses_big_endian_sequence() {
        let iv = [0x55; NONCE_LEN];
        assert_eq!(
            nonce(iv, 0x0102_0304_0506_0708),
            [
                0x55, 0x55, 0x55, 0x55, 0x54, 0x57, 0x56, 0x51, 0x50, 0x53, 0x52, 0x5d
            ]
        );
        assert_ne!(nonce(iv, 7), nonce(iv, 8));
    }

    #[test]
    fn stream_feed_and_finish_cover_splits_and_coalescing() {
        let records = [
            0x16, 0x03, 0x01, 0x00, 0x01, 0xaa, 0x17, 0x03, 0x03, 0x00, 0x01, 0xbb,
        ];
        for split in 0..=HEADER_LEN {
            let mut framer = StreamFramer::new();
            let first = framer.feed(&records[..split]);
            assert!(matches!(first, FeedStatus::NeedMore { .. }));
            let second = framer.feed(&records[split..]);
            let consumed = match second {
                FeedStatus::Record { consumed, frame } => {
                    assert_eq!(frame.frame_len, 6);
                    consumed
                }
                other => panic!("unexpected status: {other:?}"),
            };
            assert_eq!(framer.record(), Some(&records[..6] as &[u8]));
            assert!(framer.discard_record());
            assert!(matches!(
                framer.feed(&records[split + consumed..]),
                FeedStatus::Record { .. }
            ));
            assert_eq!(framer.record(), Some(&records[6..] as &[u8]));
        }

        let mut truncated = StreamFramer::new();
        assert!(matches!(
            truncated.feed(&records[..4]),
            FeedStatus::NeedMore { required: 5, .. }
        ));
        assert_eq!(truncated.finish(), FinishStatus::Truncated { required: 5 });
        assert_eq!(StreamFramer::new().finish(), FinishStatus::Clean);
    }

    #[test]
    fn directional_limits_do_not_swap() {
        let limits = DirectionalLimits::negotiated(Some(64), Some(16_385)).unwrap();
        assert_eq!(limits.send_inner_limit.get(), 64);
        assert_eq!(limits.receive_inner_limit.get(), 16_385);
        assert!(RecordSizeLimit::new(63).is_none());
        assert!(RecordSizeLimit::new(64).is_some());
        assert!(RecordSizeLimit::new(16_385).is_some());
        assert!(RecordSizeLimit::new(16_386).is_none());
    }

    #[test]
    fn provider_usage_is_bounded_and_failed_open_is_terminal() {
        let mut write = TrafficEpoch::new();
        let provider = ProviderLimits {
            max_records: 2,
            max_bytes: 34,
            max_failed_opens: 1,
            expansion: 16,
        };
        write.prepare(provider).unwrap();
        write.activate().unwrap();
        assert_eq!(write.issue_seal(1, 17, RecordSizeLimit::default()), Ok(0));
        assert_eq!(write.issue_seal(1, 17, RecordSizeLimit::default()), Ok(1));
        assert_eq!(
            write.issue_seal(1, 17, RecordSizeLimit::default()),
            Err(UsageError::RecordLimit)
        );

        let mut read = TrafficEpoch::new();
        read.prepare(provider).unwrap();
        read.activate().unwrap();
        let permit = read
            .permit_open(17, RecordSizeLimit::default())
            .unwrap();
        assert_eq!(permit.sequence, 0);
        read.fail_open(permit).unwrap();
        assert_eq!(read.state(), EpochState::Terminal);
        assert_eq!(
            read.permit_open(17, RecordSizeLimit::default()),
            Err(UsageError::InvalidState)
        );
    }

    #[test]
    fn handshake_tracker_streams_lengths_and_enforces_boundaries() {
        let mut tracker = HandshakeTracker::new();
        assert_eq!(
            tracker.observe_record(
                CONTENT_TYPE_HANDSHAKE,
                &[HANDSHAKE_TYPE_KEY_UPDATE, 0],
                false
            ),
            Ok(None)
        );
        assert_eq!(
            tracker.observe_record(CONTENT_TYPE_HANDSHAKE, &[0, 1, 1], false),
            Ok(Some(Milestone::KeyUpdate {
                request_update: true
            }))
        );
        assert!(tracker.is_aligned());

        let mut trailing = HandshakeTracker::new();
        assert_eq!(
            trailing.observe_record(
                CONTENT_TYPE_HANDSHAKE,
                &[HANDSHAKE_TYPE_FINISHED, 0, 0, 1, 7, 0],
                false,
            ),
            Err(HandshakeError::ActivationNotAtRecordBoundary)
        );

        let mut huge = HandshakeTracker::new();
        assert_eq!(
            huge.observe_record(CONTENT_TYPE_HANDSHAKE, &[11, 0xff, 0xff, 0xff, 1], false),
            Ok(None)
        );
        assert!(!huge.is_aligned());
    }

    #[test]
    fn ccs_alert_and_key_update_lifecycle_is_directional() {
        let mut control = ConnectionControl::new();
        assert_eq!(control.receive_ccs(false, &[1]), Ok(CcsAction::Drop));
        control.observe_milestone(Milestone::Finished, false);
        assert_eq!(
            control.receive_ccs(false, &[1]),
            Err(ConnectionError::UnexpectedMessage)
        );

        let mut control = ConnectionControl::new();
        control.observe_milestone(Milestone::Finished, true);
        control.observe_milestone(Milestone::Finished, false);
        control
            .begin_inbound_key_update(true)
            .unwrap();
        assert_eq!(control.commit_inbound_key_update(), Ok(1));
        assert_eq!(
            control.can_send_application_data(),
            Err(ConnectionError::PendingKeyUpdateResponse)
        );
        control
            .begin_outbound_key_update(true)
            .unwrap();
        assert_eq!(control.commit_outbound_key_update(), Ok(1));
        assert_eq!(control.can_send_application_data(), Ok(()));

        assert_eq!(
            control.receive_alert(&[1, 90]),
            Ok(AlertAction::UserCanceled)
        );
        assert_eq!(control.receive_alert(&[1, 0]), Ok(AlertAction::PeerClosed));
        assert!(control.should_discard_inbound());
        assert_eq!(control.can_send_application_data(), Ok(()));
    }

    #[test]
    fn hkdf_label_is_exact() {
        let mut encoded = [0u8; MAX_HKDF_LABEL_LEN];
        let len = encode_hkdf_label(&mut encoded, 32, TRAFFIC_UPDATE_LABEL, &[]).unwrap();
        assert_eq!(
            &encoded[..len],
            &[
                0, 32, 17, b't', b'l', b's', b'1', b'3', b' ', b't', b'r', b'a', b'f', b'f', b'i',
                b'c', b' ', b'u', b'p', b'd', 0,
            ]
        );
        assert_eq!(
            protected_header(17).unwrap(),
            [CONTENT_TYPE_APPLICATION_DATA, 3, 3, 0, 17]
        );
        assert_eq!(
            received_protected_header(CONTENT_TYPE_APPLICATION_DATA, 0x1234, 17).unwrap(),
            [CONTENT_TYPE_APPLICATION_DATA, 0x12, 0x34, 0, 17]
        );
    }
}
