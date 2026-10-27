//! Retains every typed cache variant through later read or allocation failure.

use super::*;

pub(super) struct HistoricalResultCache17(pub(super) MethodResult);
impl HistoricalType for HistoricalResultCache17 {
    fn read(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_result(input, l, build).map(|v| v.map(Self))
    }
}
pub(super) enum ResultCache17Child {
    Hello(<HelloResult as Native17Build>::Attempt),
    Discover(<DiscoverResult as Native17Build>::Attempt),
    Realize(<RealizeResult as Native17Build>::Attempt),
    Admit(<AdmitResult as Native17Build>::Attempt),
    Activate(<ActivateResult as Native17Build>::Attempt),
    Input(<InputResult as Native17Build>::Attempt),
    Observe(<ObserveResult as Native17Build>::Attempt),
    Poll(<PollResult as Native17Build>::Attempt),
    Cancel(<CancelResult as Native17Build>::Attempt),
    QuantumClose(<QuantumCloseResult as Native17Build>::Attempt),
    WorldActivate(<WorldActivateResult as Native17Build>::Attempt),
    Abort(<AbortResult as Native17Build>::Attempt),
    Retire(<RetireResult as Native17Build>::Attempt),
    BlobBegin(<BlobBeginResult as Native17Build>::Attempt),
    BlobChunk(<BlobChunkResult as Native17Build>::Attempt),
    BlobFinish(<BlobFinishResult as Native17Build>::Attempt),
    Release(<ReleaseResult as Native17Build>::Attempt),
    BeginAccepted(<BeginAccepted as Native17Build>::Attempt),
    ExactRun(<ExactRunResult as Native17Build>::Attempt),
    BoundarySettle(<ExactRunResult as Native17Build>::Attempt),
    QuantumBegin(<QuantumBeginResult as Native17Build>::Attempt),
    Pause(<PauseResult as Native17Build>::Attempt),
    Capture(<CaptureResult as Native17Build>::Attempt),
    PrepareRestore(<PrepareRestoreResult as Native17Build>::Attempt),
    Shutdown(<ShutdownResult as Native17Build>::Attempt),
}

#[derive(Default)]
pub(super) struct ResultCache17ReadAttempt {
    pub(super) child: Option<ResultCache17Child>,
    pub(super) failed: bool,
    completed: Option<HistoricalResultCache17>,
}

impl Native17Build for HistoricalResultCache17 {
    type Attempt = ResultCache17ReadAttempt;
    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut f = Fields::array(input)?;
        let kind = plain_string(next(&mut f)?)?;
        let raw = next(&mut f)?;
        f.finish()?;
        match kind {
            "Hello" => <HelloResult as Native17Build>::preflight_data(raw, l),
            "Discover" => <DiscoverResult as Native17Build>::preflight_data(raw, l),
            "Realize" => <RealizeResult as Native17Build>::preflight_data(raw, l),
            "Admit" => <AdmitResult as Native17Build>::preflight_data(raw, l),
            "Activate" => <ActivateResult as Native17Build>::preflight_data(raw, l),
            "Input" => <InputResult as Native17Build>::preflight_data(raw, l),
            "Observe" => <ObserveResult as Native17Build>::preflight_data(raw, l),
            "Poll" => <PollResult as Native17Build>::preflight_data(raw, l),
            "Cancel" => <CancelResult as Native17Build>::preflight_data(raw, l),
            "QuantumClose" => <QuantumCloseResult as Native17Build>::preflight_data(raw, l),
            "WorldActivate" => <WorldActivateResult as Native17Build>::preflight_data(raw, l),
            "Abort" => <AbortResult as Native17Build>::preflight_data(raw, l),
            "Retire" => <RetireResult as Native17Build>::preflight_data(raw, l),
            "BlobBegin" => <BlobBeginResult as Native17Build>::preflight_data(raw, l),
            "BlobChunk" => <BlobChunkResult as Native17Build>::preflight_data(raw, l),
            "BlobFinish" => <BlobFinishResult as Native17Build>::preflight_data(raw, l),
            "Release" => <ReleaseResult as Native17Build>::preflight_data(raw, l),
            "BeginAccepted" => <BeginAccepted as Native17Build>::preflight_data(raw, l),
            "ExactRun" => <ExactRunResult as Native17Build>::preflight_data(raw, l),
            "BoundarySettle" => <ExactRunResult as Native17Build>::preflight_data(raw, l),
            "QuantumBegin" => <QuantumBeginResult as Native17Build>::preflight_data(raw, l),
            "Pause" => <PauseResult as Native17Build>::preflight_data(raw, l),
            "Capture" => <CaptureResult as Native17Build>::preflight_data(raw, l),
            "PrepareRestore" => <PrepareRestoreResult as Native17Build>::preflight_data(raw, l),
            "Shutdown" => <ShutdownResult as Native17Build>::preflight_data(raw, l),
            _ => Err(invalid()),
        }
    }
    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.child.is_some() || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            let mut f = Fields::array(input)?;
            let kind = plain_string(next(&mut f)?)?;
            let raw = next(&mut f)?;
            f.finish()?;
            a.child = Some(match kind {
                "Hello" => ResultCache17Child::Hello(Default::default()),
                "Discover" => ResultCache17Child::Discover(Default::default()),
                "Realize" => ResultCache17Child::Realize(Default::default()),
                "Admit" => ResultCache17Child::Admit(Default::default()),
                "Activate" => ResultCache17Child::Activate(Default::default()),
                "Input" => ResultCache17Child::Input(Default::default()),
                "Observe" => ResultCache17Child::Observe(Default::default()),
                "Poll" => ResultCache17Child::Poll(Default::default()),
                "Cancel" => ResultCache17Child::Cancel(Default::default()),
                "QuantumClose" => ResultCache17Child::QuantumClose(Default::default()),
                "WorldActivate" => ResultCache17Child::WorldActivate(Default::default()),
                "Abort" => ResultCache17Child::Abort(Default::default()),
                "Retire" => ResultCache17Child::Retire(Default::default()),
                "BlobBegin" => ResultCache17Child::BlobBegin(Default::default()),
                "BlobChunk" => ResultCache17Child::BlobChunk(Default::default()),
                "BlobFinish" => ResultCache17Child::BlobFinish(Default::default()),
                "Release" => ResultCache17Child::Release(Default::default()),
                "BeginAccepted" => ResultCache17Child::BeginAccepted(Default::default()),
                "ExactRun" => ResultCache17Child::ExactRun(Default::default()),
                "BoundarySettle" => ResultCache17Child::BoundarySettle(Default::default()),
                "QuantumBegin" => ResultCache17Child::QuantumBegin(Default::default()),
                "Pause" => ResultCache17Child::Pause(Default::default()),
                "Capture" => ResultCache17Child::Capture(Default::default()),
                "PrepareRestore" => ResultCache17Child::PrepareRestore(Default::default()),
                "Shutdown" => ResultCache17Child::Shutdown(Default::default()),
                _ => return Err(invalid()),
            });
            let value = match a.child.as_mut().ok_or_else(invalid)? {
                ResultCache17Child::Hello(child) => {
                    <HelloResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Hello(
                        <HelloResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Discover(child) => {
                    <DiscoverResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Discover(
                        <DiscoverResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Realize(child) => {
                    <RealizeResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Realize(
                        <RealizeResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Admit(child) => {
                    <AdmitResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Admit(
                        <AdmitResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Activate(child) => {
                    <ActivateResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Activate(
                        <ActivateResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Input(child) => {
                    <InputResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Input(
                        <InputResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Observe(child) => {
                    <ObserveResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Observe(
                        <ObserveResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Poll(child) => {
                    <PollResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Poll(
                        <PollResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Cancel(child) => {
                    <CancelResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Cancel(
                        <CancelResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::QuantumClose(child) => {
                    <QuantumCloseResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::QuantumClose(
                        <QuantumCloseResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::WorldActivate(child) => {
                    <WorldActivateResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::WorldActivate(
                        <WorldActivateResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Abort(child) => {
                    <AbortResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Abort(
                        <AbortResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Retire(child) => {
                    <RetireResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Retire(
                        <RetireResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::BlobBegin(child) => {
                    <BlobBeginResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::BlobBegin(
                        <BlobBeginResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::BlobChunk(child) => {
                    <BlobChunkResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::BlobChunk(
                        <BlobChunkResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::BlobFinish(child) => {
                    <BlobFinishResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::BlobFinish(
                        <BlobFinishResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Release(child) => {
                    <ReleaseResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Release(
                        <ReleaseResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::BeginAccepted(child) => {
                    <BeginAccepted as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::BeginAccepted(
                        <BeginAccepted as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::ExactRun(child) => {
                    <ExactRunResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::ExactRun(
                        <ExactRunResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::BoundarySettle(child) => {
                    <ExactRunResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::BoundarySettle(
                        <ExactRunResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::QuantumBegin(child) => {
                    <QuantumBeginResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::QuantumBegin(
                        <QuantumBeginResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Pause(child) => {
                    <PauseResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Pause(
                        <PauseResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Capture(child) => {
                    <CaptureResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Capture(
                        <CaptureResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::PrepareRestore(child) => {
                    <PrepareRestoreResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::PrepareRestore(
                        <PrepareRestoreResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                ResultCache17Child::Shutdown(child) => {
                    <ShutdownResult as Native17Build>::read_into_data(raw, l, child)?;
                    MethodResult::Shutdown(
                        <ShutdownResult as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
            };
            a.completed = Some(Self(value));
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }
    fn output_data(a: &Self::Attempt) -> Option<&Self> {
        a.completed.as_ref()
    }
    fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
        a.completed.take()
    }
    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(child) = &a.child {
            match child {
                ResultCache17Child::Hello(a) => {
                    <HelloResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Discover(a) => {
                    <DiscoverResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Realize(a) => {
                    <RealizeResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Admit(a) => {
                    <AdmitResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Activate(a) => {
                    <ActivateResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Input(a) => {
                    <InputResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Observe(a) => {
                    <ObserveResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Poll(a) => {
                    <PollResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Cancel(a) => {
                    <CancelResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::QuantumClose(a) => {
                    <QuantumCloseResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::WorldActivate(a) => {
                    <WorldActivateResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Abort(a) => {
                    <AbortResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Retire(a) => {
                    <RetireResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::BlobBegin(a) => {
                    <BlobBeginResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::BlobChunk(a) => {
                    <BlobChunkResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::BlobFinish(a) => {
                    <BlobFinishResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Release(a) => {
                    <ReleaseResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::BeginAccepted(a) => {
                    <BeginAccepted as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::ExactRun(a) => {
                    <ExactRunResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::BoundarySettle(a) => {
                    <ExactRunResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::QuantumBegin(a) => {
                    <QuantumBeginResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Pause(a) => {
                    <PauseResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Capture(a) => {
                    <CaptureResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::PrepareRestore(a) => {
                    <PrepareRestoreResult as Native17Build>::observe_attempt_data(a, o)?
                }
                ResultCache17Child::Shutdown(a) => {
                    <ShutdownResult as Native17Build>::observe_attempt_data(a, o)?
                }
            }
        }
        if let Some(v) = &a.completed {
            Self::observe_output_data(v, o)?;
        }
        Ok(())
    }
    fn observe_output_data(v: &Self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match &v.0 {
            MethodResult::Hello(v) => <HelloResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Discover(v) => {
                <DiscoverResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Realize(v) => <RealizeResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Admit(v) => <AdmitResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Activate(v) => {
                <ActivateResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Input(v) => <InputResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Observe(v) => <ObserveResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Poll(v) => <PollResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Cancel(v) => <CancelResult as Native17Build>::observe_output_data(v, o),
            MethodResult::QuantumClose(v) => {
                <QuantumCloseResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::WorldActivate(v) => {
                <WorldActivateResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Abort(v) => <AbortResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Retire(v) => <RetireResult as Native17Build>::observe_output_data(v, o),
            MethodResult::BlobBegin(v) => {
                <BlobBeginResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::BlobChunk(v) => {
                <BlobChunkResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::BlobFinish(v) => {
                <BlobFinishResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Release(v) => <ReleaseResult as Native17Build>::observe_output_data(v, o),
            MethodResult::BeginAccepted(v) => {
                <BeginAccepted as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::ExactRun(v) => {
                <ExactRunResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::BoundarySettle(v) => {
                <ExactRunResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::QuantumBegin(v) => {
                <QuantumBeginResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Pause(v) => <PauseResult as Native17Build>::observe_output_data(v, o),
            MethodResult::Capture(v) => <CaptureResult as Native17Build>::observe_output_data(v, o),
            MethodResult::PrepareRestore(v) => {
                <PrepareRestoreResult as Native17Build>::observe_output_data(v, o)
            }
            MethodResult::Shutdown(v) => {
                <ShutdownResult as Native17Build>::observe_output_data(v, o)
            }
        }
    }
}
