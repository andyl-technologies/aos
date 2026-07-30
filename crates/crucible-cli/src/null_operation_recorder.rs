//! No-op CLI decomposition recorder used by normal dispatch.

use super::*;

impl CliOperationRecorder for NullOperationRecorder {
    fn record_session_command(&mut self, _command: SessionCommandKind) {}

    fn record_api_call(&mut self, _call: CliApiCall) {}

    fn record_driver(&mut self, _driver: CliDelegatedDriver) {}

    fn record_state_reference(&mut self, _reference: CliStateReferenceKind) {}
}
