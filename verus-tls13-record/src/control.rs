use crate::{
    ControlCore, ControlMilestone, Error, HandshakeMilestone, KeyUpdateRequest, control_fail,
    control_may_write_application_data, control_observe_local, control_observe_peer,
    control_permit_inbound_key_update, control_permit_outbound_key_update, control_plan_cancel,
    control_plan_close, control_receive_alert, control_receive_disposition, control_validate_ccs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    Process,
    DiscardAfterClose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertEvent {
    CloseNotify,
    UserCanceled,
    FatalOrUnknown(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundAlertPlan {
    pub first: [u8; 2],
    pub second: Option<[u8; 2]>,
}

/// Verified record/control lifecycle state for one connection endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlState {
    core: ControlCore,
}

impl ControlState {
    pub const fn new() -> Self {
        Self {
            core: ControlCore {
                first_client_hello: false,
                local_finished: false,
                peer_finished: false,
                read_closed: false,
                write_closed: false,
                fatal: false,
                pending_key_update_response: false,
                read_generation: 0,
                write_generation: 0,
            },
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.core.fatal
    }

    pub fn read_closed(&self) -> bool {
        self.core.read_closed
    }

    pub fn write_closed(&self) -> bool {
        self.core.write_closed
    }

    pub fn read_generation(&self) -> u64 {
        self.core.read_generation
    }

    pub fn write_generation(&self) -> u64 {
        self.core.write_generation
    }

    pub fn pending_key_update_response(&self) -> bool {
        self.core.pending_key_update_response
    }

    pub fn receive_disposition(&self) -> Result<ReceiveDisposition, Error> {
        match control_receive_disposition(self.core)? {
            0 => Ok(ReceiveDisposition::Process),
            1 => Ok(ReceiveDisposition::DiscardAfterClose),
            _ => Err(Error::ProviderContract),
        }
    }

    pub fn may_write_application_data(&self) -> bool {
        control_may_write_application_data(self.core)
    }

    pub fn observe_local_milestone(
        &mut self,
        milestone: HandshakeMilestone,
    ) -> Result<(), Error> {
        let step = control_observe_local(self.core, core_milestone(milestone));
        self.core = step.state;
        step.result
    }

    pub fn observe_peer_milestone(
        &mut self,
        milestone: HandshakeMilestone,
    ) -> Result<(), Error> {
        let step = control_observe_peer(self.core, core_milestone(milestone));
        self.core = step.state;
        step.result
    }

    pub fn validate_ccs(&mut self, protected: bool, payload: &[u8]) -> Result<(), Error> {
        let step = control_validate_ccs(self.core, protected, payload == [1]);
        self.core = step.state;
        step.result
    }

    pub fn receive_alert(&mut self, payload: &[u8]) -> Result<AlertEvent, Error> {
        let (level, description) = match payload {
            [level, description] => (*level, *description),
            _ => (0, 0),
        };
        let step = control_receive_alert(self.core, payload.len(), level, description);
        self.core = step.state;
        match step.event? {
            0 => Ok(AlertEvent::CloseNotify),
            1 => Ok(AlertEvent::UserCanceled),
            2 => Ok(AlertEvent::FatalOrUnknown(description)),
            _ => Err(Error::ProviderContract),
        }
    }

    pub fn plan_local_cancel(&mut self) -> Result<OutboundAlertPlan, Error> {
        let step = control_plan_cancel(self.core);
        self.core = step.state;
        step.result?;
        Ok(OutboundAlertPlan {
            first: [1, step.first_description],
            second: step.second_description.map(|description| [1, description]),
        })
    }

    pub fn plan_close_notify(&mut self) -> Result<[u8; 2], Error> {
        let step = control_plan_close(self.core);
        self.core = step.state;
        step.result?;
        Ok([1, 0])
    }

    pub fn fail(&mut self, error: Error) -> Error {
        self.core = control_fail(self.core);
        error
    }

    pub fn permit_outbound_key_update(&self) -> Result<(), Error> {
        control_permit_outbound_key_update(self.core)
    }

    pub fn permit_inbound_key_update(&self) -> Result<(), Error> {
        control_permit_inbound_key_update(self.core)
    }
}

fn core_milestone(milestone: HandshakeMilestone) -> ControlMilestone {
    match milestone {
        HandshakeMilestone::ClientHello => ControlMilestone::ClientHello,
        HandshakeMilestone::ServerHello => ControlMilestone::ServerHello,
        HandshakeMilestone::Finished => ControlMilestone::Finished,
        HandshakeMilestone::KeyUpdate(KeyUpdateRequest::UpdateNotRequested) => {
            ControlMilestone::KeyUpdateNotRequested
        }
        HandshakeMilestone::KeyUpdate(KeyUpdateRequest::UpdateRequested) => {
            ControlMilestone::KeyUpdateRequested
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccs_window_is_exact_and_failure_is_terminal() {
        let mut state = ControlState::new();
        assert_eq!(state.validate_ccs(false, &[1]), Err(Error::UnexpectedMessage));
        assert!(state.is_fatal());

        let mut state = ControlState::new();
        state
            .observe_local_milestone(HandshakeMilestone::ClientHello)
            .unwrap();
        assert_eq!(state.validate_ccs(false, &[1]), Ok(()));
        assert_eq!(state.validate_ccs(true, &[1]), Err(Error::UnexpectedMessage));
    }

    #[test]
    fn close_notify_half_closes_only_read_direction() {
        let mut state = ControlState::new();
        assert_eq!(
            state.receive_alert(&[1, 0]),
            Ok(AlertEvent::CloseNotify)
        );
        assert_eq!(
            state.receive_disposition(),
            Ok(ReceiveDisposition::DiscardAfterClose)
        );
        assert!(state.may_write_application_data());

        let mut fatal_close = ControlState::new();
        assert_eq!(
            fatal_close.receive_alert(&[2, 0]),
            Ok(AlertEvent::FatalOrUnknown(0))
        );
        assert!(fatal_close.is_fatal());
    }

    #[test]
    fn requested_update_blocks_application_until_response() {
        let mut state = ControlState::new();
        state
            .observe_peer_milestone(HandshakeMilestone::Finished)
            .unwrap();
        state
            .observe_local_milestone(HandshakeMilestone::Finished)
            .unwrap();
        state
            .observe_peer_milestone(HandshakeMilestone::KeyUpdate(
                KeyUpdateRequest::UpdateRequested,
            ))
            .unwrap();
        assert!(!state.may_write_application_data());
        state
            .observe_local_milestone(HandshakeMilestone::KeyUpdate(
                KeyUpdateRequest::UpdateNotRequested,
            ))
            .unwrap();
        assert!(state.may_write_application_data());
        assert_eq!(state.read_generation(), 1);
        assert_eq!(state.write_generation(), 1);
    }

    #[test]
    fn cancel_plan_uses_two_separate_pre_handshake_alerts() {
        let mut state = ControlState::new();
        assert_eq!(
            state.plan_local_cancel().unwrap(),
            OutboundAlertPlan {
                first: [1, 90],
                second: Some([1, 0])
            }
        );
    }

    #[test]
    fn requested_update_after_local_close_advances_read_without_response() {
        let mut state = ControlState::new();
        state
            .observe_peer_milestone(HandshakeMilestone::Finished)
            .unwrap();
        state
            .observe_local_milestone(HandshakeMilestone::Finished)
            .unwrap();
        state.plan_close_notify().unwrap();
        state
            .observe_peer_milestone(HandshakeMilestone::KeyUpdate(
                KeyUpdateRequest::UpdateRequested,
            ))
            .unwrap();
        assert_eq!(state.read_generation(), 1);
        assert!(!state.pending_key_update_response());
        assert!(state.write_closed());
    }
}
