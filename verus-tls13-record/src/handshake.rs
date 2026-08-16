use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::Error;

pub const HANDSHAKE_HEADER_LEN: usize = 4;
pub const MAX_HANDSHAKE_BODY: usize = 0xffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
}

impl KeyUpdateRequest {
    pub fn from_wire(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::UpdateNotRequested),
            1 => Ok(Self::UpdateRequested),
            _ => Err(Error::IllegalParameter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMilestone {
    ClientHello,
    ServerHello,
    Finished,
    KeyUpdate(KeyUpdateRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeObservation {
    pub milestone: Option<HandshakeMilestone>,
    pub aligned: bool,
}

/// Fixed-size handshake framing state. The declared 24-bit body length is
/// counted but never used to reserve or allocate storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTracker {
    header: [u8; HANDSHAKE_HEADER_LEN],
    header_used: usize,
    current_type: u8,
    remaining: u32,
    key_update_request: u8,
    last_boundary: Option<HandshakeMilestone>,
}

impl Default for HandshakeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeTracker {
    pub const fn new() -> Self {
        Self {
            header: [0; HANDSHAKE_HEADER_LEN],
            header_used: 0,
            current_type: 0,
            remaining: 0,
            key_update_request: 0,
            last_boundary: None,
        }
    }

    pub fn is_aligned(&self) -> bool {
        self.header_used == 0 && self.remaining == 0
    }

    pub fn declared_remaining(&self) -> u32 {
        self.remaining
    }

    pub fn header_bytes_held(&self) -> usize {
        self.header_used
    }

    /// Observe exactly one Handshake record fragment. Named milestones may
    /// complete only on the record boundary; a following byte is rejected.
    pub fn observe_record(&mut self, fragment: &[u8]) -> Result<HandshakeObservation, Error> {
        self.last_boundary = None;
        let mut offset = 0usize;
        let mut milestone = None;

        while offset < fragment.len() {
            if self.header_used < HANDSHAKE_HEADER_LEN {
                let needed = HANDSHAKE_HEADER_LEN - self.header_used;
                let available = fragment.len() - offset;
                let copied = core::cmp::min(needed, available);
                let end = self.header_used + copied;
                self.header[self.header_used..end]
                    .copy_from_slice(&fragment[offset..offset + copied]);
                self.header_used = end;
                offset += copied;
                if self.header_used < HANDSHAKE_HEADER_LEN {
                    break;
                }

                self.current_type = self.header[0];
                self.remaining = ((self.header[1] as u32) << 16)
                    | ((self.header[2] as u32) << 8)
                    | self.header[3] as u32;
                self.key_update_request = 0;
                validate_declared_handshake(self.current_type, self.remaining)?;

                if self.remaining == 0 {
                    self.header_used = 0;
                    self.current_type = 0;
                    continue;
                }
            }

            let available = fragment.len() - offset;
            let consumed = core::cmp::min(available as u32, self.remaining) as usize;
            if self.current_type == 24 && self.remaining == 1 && consumed == 1 {
                self.key_update_request = fragment[offset];
            }
            offset += consumed;
            self.remaining -= consumed as u32;

            if self.remaining == 0 {
                let completed = classify_milestone(self.current_type, self.key_update_request)?;
                self.header_used = 0;
                self.current_type = 0;
                self.key_update_request = 0;
                if let Some(completed) = completed {
                    if offset != fragment.len() {
                        return Err(Error::UnexpectedMessage);
                    }
                    milestone = Some(completed);
                }
            }
        }

        self.last_boundary = milestone;
        Ok(HandshakeObservation {
            milestone,
            aligned: self.is_aligned(),
        })
    }

    /// Consume the immediately preceding named boundary when authenticated
    /// handshake code activates a key. It cannot be reused after activation.
    pub fn activate_after(&mut self, expected: HandshakeMilestone) -> Result<(), Error> {
        if !self.is_aligned() || self.last_boundary != Some(expected) {
            return Err(Error::InvalidState);
        }
        self.last_boundary = None;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedHandshakeMessage {
    legacy_version: u16,
    payload: Vec<u8>,
}

impl OwnedHandshakeMessage {
    pub fn legacy_version(&self) -> u16 {
        self.legacy_version
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Selected-profile semantic handshake sink. Framing, declared-length
/// validation, milestone recognition, and record-boundary alignment are all
/// decided here; consumers receive only complete, already-framed messages.
/// Allocation grows solely with bytes actually received and is capped by the
/// selected rustls semantic-message policy, never by an unchecked 24-bit
/// declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeReassembler {
    partial: Vec<u8>,
    expected_total: Option<usize>,
    partial_version: u16,
    ready: VecDeque<OwnedHandshakeMessage>,
    last_boundary: Option<HandshakeMilestone>,
}

impl Default for HandshakeReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeReassembler {
    pub const fn new() -> Self {
        Self {
            partial: Vec::new(),
            expected_total: None,
            partial_version: 0,
            ready: VecDeque::new(),
            last_boundary: None,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.partial.is_empty()
    }

    pub fn is_aligned(&self) -> bool {
        self.partial.is_empty()
    }

    pub fn has_message_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    pub fn take_message(&mut self) -> Option<OwnedHandshakeMessage> {
        self.ready.pop_front()
    }

    pub fn observe_record(
        &mut self,
        legacy_version: u16,
        fragment: &[u8],
    ) -> Result<HandshakeObservation, Error> {
        self.last_boundary = None;
        let mut offset = 0usize;
        let mut milestone = None;

        while offset < fragment.len() {
            if self.partial.is_empty() {
                self.partial_version = legacy_version;
            }

            if self.partial.len() < HANDSHAKE_HEADER_LEN {
                let needed = HANDSHAKE_HEADER_LEN - self.partial.len();
                let available = fragment.len() - offset;
                let copied = core::cmp::min(needed, available);
                self.partial
                    .extend_from_slice(&fragment[offset..offset + copied]);
                offset += copied;
                if self.partial.len() < HANDSHAKE_HEADER_LEN {
                    break;
                }

                let typ = self.partial[0];
                let body_len = ((self.partial[1] as u32) << 16)
                    | ((self.partial[2] as u32) << 8)
                    | self.partial[3] as u32;
                validate_declared_handshake(typ, body_len)?;
                if body_len as usize > MAX_HANDSHAKE_BODY {
                    return Err(Error::DecodeError);
                }
                self.expected_total = Some(HANDSHAKE_HEADER_LEN + body_len as usize);
            }

            let expected = self.expected_total.ok_or(Error::InvalidState)?;
            let needed = expected - self.partial.len();
            let available = fragment.len() - offset;
            let copied = core::cmp::min(needed, available);
            self.partial
                .extend_from_slice(&fragment[offset..offset + copied]);
            offset += copied;

            if self.partial.len() != expected {
                continue;
            }

            let typ = self.partial[0];
            let key_update_request = if typ == 24 { self.partial[4] } else { 0 };
            let completed = classify_milestone(typ, key_update_request)?;
            let payload = core::mem::take(&mut self.partial);
            self.expected_total = None;
            self.ready.push_back(OwnedHandshakeMessage {
                legacy_version: self.partial_version,
                payload,
            });
            if let Some(completed) = completed {
                if offset != fragment.len() {
                    return Err(Error::UnexpectedMessage);
                }
                milestone = Some(completed);
            }
        }

        self.last_boundary = milestone;
        Ok(HandshakeObservation {
            milestone,
            aligned: self.is_aligned(),
        })
    }

    pub fn activate_after(&mut self, expected: HandshakeMilestone) -> Result<(), Error> {
        if !self.is_aligned() || self.last_boundary != Some(expected) {
            return Err(Error::InvalidState);
        }
        self.last_boundary = None;
        Ok(())
    }
}

fn validate_declared_handshake(typ: u8, length: u32) -> Result<(), Error> {
    match typ {
        // EndOfEarlyData is outside the selected no-0-RTT profile.
        5 => Err(Error::UnexpectedMessage),
        // ClientHello, ServerHello, and Finished cannot be empty.
        1 | 2 | 20 if length == 0 => Err(Error::DecodeError),
        // KeyUpdate is exactly one enum octet.
        24 if length != 1 => Err(Error::DecodeError),
        _ => Ok(()),
    }
}

fn classify_milestone(
    typ: u8,
    key_update_request: u8,
) -> Result<Option<HandshakeMilestone>, Error> {
    match typ {
        1 => Ok(Some(HandshakeMilestone::ClientHello)),
        2 => Ok(Some(HandshakeMilestone::ServerHello)),
        20 => Ok(Some(HandshakeMilestone::Finished)),
        24 => Ok(Some(HandshakeMilestone::KeyUpdate(
            KeyUpdateRequest::from_wire(key_update_request)?,
        ))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_declared_length_without_allocating_it() {
        let mut tracker = HandshakeTracker::new();
        let observation = tracker.observe_record(&[11, 0xff, 0xff, 0xff]).unwrap();
        assert!(!observation.aligned);
        assert_eq!(tracker.declared_remaining(), 0x00ff_ffff);
        assert_eq!(tracker.header_bytes_held(), HANDSHAKE_HEADER_LEN);
        assert!(core::mem::size_of::<HandshakeTracker>() <= 32);
    }

    #[test]
    fn milestone_requires_the_record_boundary() {
        let mut tracker = HandshakeTracker::new();
        assert_eq!(
            tracker.observe_record(&[24, 0, 0, 1, 1]).unwrap().milestone,
            Some(HandshakeMilestone::KeyUpdate(
                KeyUpdateRequest::UpdateRequested
            ))
        );
        assert_eq!(
            tracker.observe_record(&[24, 0, 0, 1, 0, 0]),
            Err(Error::UnexpectedMessage)
        );
    }

    #[test]
    fn fragmented_key_update_uses_fixed_state() {
        let mut tracker = HandshakeTracker::new();
        assert!(!tracker.observe_record(&[24, 0]).unwrap().aligned);
        assert!(!tracker.observe_record(&[0, 1]).unwrap().aligned);
        let observation = tracker.observe_record(&[0]).unwrap();
        assert_eq!(
            observation.milestone,
            Some(HandshakeMilestone::KeyUpdate(
                KeyUpdateRequest::UpdateNotRequested
            ))
        );
        tracker.activate_after(observation.milestone.unwrap()).unwrap();
        assert_eq!(
            tracker.activate_after(observation.milestone.unwrap()),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn rejects_disabled_or_malformed_control_messages() {
        let mut tracker = HandshakeTracker::new();
        assert_eq!(
            tracker.observe_record(&[5, 0, 0, 0]),
            Err(Error::UnexpectedMessage)
        );
        let mut tracker = HandshakeTracker::new();
        assert_eq!(
            tracker.observe_record(&[24, 0, 0, 2, 0, 0]),
            Err(Error::DecodeError)
        );
        let mut tracker = HandshakeTracker::new();
        assert_eq!(
            tracker.observe_record(&[24, 0, 0, 1, 2]),
            Err(Error::IllegalParameter)
        );
    }

    #[test]
    fn reassembler_owns_framing_and_never_reserves_declared_length() {
        let mut reassembler = HandshakeReassembler::new();
        assert_eq!(
            reassembler.observe_record(0x0303, &[11, 0, 0]).unwrap(),
            HandshakeObservation {
                milestone: None,
                aligned: false,
            }
        );
        assert_eq!(reassembler.partial.capacity(), 8);
        reassembler.observe_record(0x0303, &[2, 7]).unwrap();
        assert!(!reassembler.has_message_ready());
        reassembler.observe_record(0x0303, &[8]).unwrap();
        let message = reassembler.take_message().unwrap();
        assert_eq!(message.legacy_version(), 0x0303);
        assert_eq!(message.payload(), &[11, 0, 0, 2, 7, 8]);
    }

    #[test]
    fn reassembler_enforces_named_record_boundary_and_activation() {
        let mut reassembler = HandshakeReassembler::new();
        let observation = reassembler
            .observe_record(0x0303, &[24, 0, 0, 1, 1])
            .unwrap();
        assert_eq!(
            observation.milestone,
            Some(HandshakeMilestone::KeyUpdate(KeyUpdateRequest::UpdateRequested))
        );
        reassembler
            .activate_after(observation.milestone.unwrap())
            .unwrap();
        assert_eq!(
            reassembler.activate_after(observation.milestone.unwrap()),
            Err(Error::InvalidState)
        );

        let mut trailing = HandshakeReassembler::new();
        assert_eq!(
            trailing.observe_record(0x0303, &[24, 0, 0, 1, 0, 0]),
            Err(Error::UnexpectedMessage)
        );
    }
}
