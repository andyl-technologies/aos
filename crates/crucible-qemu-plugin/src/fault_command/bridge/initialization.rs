//! Initialization-stage error attribution for the live fault bridge.

use super::FaultCommandBridgeError;

pub(super) fn initialization_stage<T>(
    stage: &'static str,
    result: Result<T, FaultCommandBridgeError>,
) -> Result<T, FaultCommandBridgeError> {
    result.map_err(|source| FaultCommandBridgeError::InitializationStage {
        stage,
        source: Box::new(source),
    })
}
