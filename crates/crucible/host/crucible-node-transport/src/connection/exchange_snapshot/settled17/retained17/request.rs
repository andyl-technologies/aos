//! Retains every typed cache variant through later read or allocation failure.

use super::*;

pub(super) struct HistoricalRequestCache17(pub(super) RequestBody);
impl HistoricalType for HistoricalRequestCache17 {
    fn read(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_request(input, l, build).map(|v| v.map(Self))
    }
}
pub(super) enum RequestCache17Child {
    Hello(<HelloRequest as Native17Build>::Attempt),
    Discover(<DiscoverRequest as Native17Build>::Attempt),
    Realize(<RealizeRequest as Native17Build>::Attempt),
    Admit(<AdmitRequest as Native17Build>::Attempt),
    Activate(<ActivateRequest as Native17Build>::Attempt),
    Input(<InputRequest as Native17Build>::Attempt),
    Observe(<ObserveRequest as Native17Build>::Attempt),
    Begin(<BeginRequest as Native17Build>::Attempt),
    Poll(<PollRequest as Native17Build>::Attempt),
    Cancel(<CancelRequest as Native17Build>::Attempt),
    QuantumClose(<QuantumCloseRequest as Native17Build>::Attempt),
    WorldActivate(<WorldActivateRequest as Native17Build>::Attempt),
    Abort(<AbortRequest as Native17Build>::Attempt),
    Retire(<RetireRequest as Native17Build>::Attempt),
    BlobBegin(<BlobBeginRequest as Native17Build>::Attempt),
    BlobChunk(<BlobChunkRequest as Native17Build>::Attempt),
    BlobFinish(<BlobFinishRequest as Native17Build>::Attempt),
    Release(<ReleaseRequest as Native17Build>::Attempt),
}
pub(super) struct RequestCache17ReadAttempt {
    pub(super) child: Option<RequestCache17Child>,
    pub(super) failed: bool,
    completed: Option<HistoricalRequestCache17>,
}
impl Default for RequestCache17ReadAttempt {
    fn default() -> Self {
        Self {
            child: None,
            failed: false,
            completed: None,
        }
    }
}
impl Native17Build for HistoricalRequestCache17 {
    type Attempt = RequestCache17ReadAttempt;
    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut f = Fields::array(input)?;
        let kind = plain_string(next(&mut f)?)?;
        let raw = next(&mut f)?;
        f.finish()?;
        match kind {
            "Hello" => <HelloRequest as Native17Build>::preflight_data(raw, l),
            "Discover" => <DiscoverRequest as Native17Build>::preflight_data(raw, l),
            "Realize" => <RealizeRequest as Native17Build>::preflight_data(raw, l),
            "Admit" => <AdmitRequest as Native17Build>::preflight_data(raw, l),
            "Activate" => <ActivateRequest as Native17Build>::preflight_data(raw, l),
            "Input" => <InputRequest as Native17Build>::preflight_data(raw, l),
            "Observe" => <ObserveRequest as Native17Build>::preflight_data(raw, l),
            "Begin" => <BeginRequest as Native17Build>::preflight_data(raw, l),
            "Poll" => <PollRequest as Native17Build>::preflight_data(raw, l),
            "Cancel" => <CancelRequest as Native17Build>::preflight_data(raw, l),
            "QuantumClose" => <QuantumCloseRequest as Native17Build>::preflight_data(raw, l),
            "WorldActivate" => <WorldActivateRequest as Native17Build>::preflight_data(raw, l),
            "Abort" => <AbortRequest as Native17Build>::preflight_data(raw, l),
            "Retire" => <RetireRequest as Native17Build>::preflight_data(raw, l),
            "BlobBegin" => <BlobBeginRequest as Native17Build>::preflight_data(raw, l),
            "BlobChunk" => <BlobChunkRequest as Native17Build>::preflight_data(raw, l),
            "BlobFinish" => <BlobFinishRequest as Native17Build>::preflight_data(raw, l),
            "Release" => <ReleaseRequest as Native17Build>::preflight_data(raw, l),
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
                "Hello" => RequestCache17Child::Hello(Default::default()),
                "Discover" => RequestCache17Child::Discover(Default::default()),
                "Realize" => RequestCache17Child::Realize(Default::default()),
                "Admit" => RequestCache17Child::Admit(Default::default()),
                "Activate" => RequestCache17Child::Activate(Default::default()),
                "Input" => RequestCache17Child::Input(Default::default()),
                "Observe" => RequestCache17Child::Observe(Default::default()),
                "Begin" => RequestCache17Child::Begin(Default::default()),
                "Poll" => RequestCache17Child::Poll(Default::default()),
                "Cancel" => RequestCache17Child::Cancel(Default::default()),
                "QuantumClose" => RequestCache17Child::QuantumClose(Default::default()),
                "WorldActivate" => RequestCache17Child::WorldActivate(Default::default()),
                "Abort" => RequestCache17Child::Abort(Default::default()),
                "Retire" => RequestCache17Child::Retire(Default::default()),
                "BlobBegin" => RequestCache17Child::BlobBegin(Default::default()),
                "BlobChunk" => RequestCache17Child::BlobChunk(Default::default()),
                "BlobFinish" => RequestCache17Child::BlobFinish(Default::default()),
                "Release" => RequestCache17Child::Release(Default::default()),
                _ => return Err(invalid()),
            });
            let value = match a.child.as_mut().ok_or_else(invalid)? {
                RequestCache17Child::Hello(child) => {
                    <HelloRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Hello(
                        <HelloRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Discover(child) => {
                    <DiscoverRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Discover(
                        <DiscoverRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Realize(child) => {
                    <RealizeRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Realize(
                        <RealizeRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Admit(child) => {
                    <AdmitRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Admit(
                        <AdmitRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Activate(child) => {
                    <ActivateRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Activate(
                        <ActivateRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Input(child) => {
                    <InputRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Input(
                        <InputRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Observe(child) => {
                    <ObserveRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Observe(
                        <ObserveRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Begin(child) => {
                    <BeginRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Begin(
                        <BeginRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Poll(child) => {
                    <PollRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Poll(
                        <PollRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Cancel(child) => {
                    <CancelRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Cancel(
                        <CancelRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::QuantumClose(child) => {
                    <QuantumCloseRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::QuantumClose(
                        <QuantumCloseRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::WorldActivate(child) => {
                    <WorldActivateRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::WorldActivate(
                        <WorldActivateRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Abort(child) => {
                    <AbortRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Abort(
                        <AbortRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Retire(child) => {
                    <RetireRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Retire(
                        <RetireRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::BlobBegin(child) => {
                    <BlobBeginRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::BlobBegin(
                        <BlobBeginRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::BlobChunk(child) => {
                    <BlobChunkRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::BlobChunk(
                        <BlobChunkRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::BlobFinish(child) => {
                    <BlobFinishRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::BlobFinish(
                        <BlobFinishRequest as Native17Build>::take_output_data(child)
                            .ok_or_else(invalid)?,
                    )
                }
                RequestCache17Child::Release(child) => {
                    <ReleaseRequest as Native17Build>::read_into_data(raw, l, child)?;
                    RequestBody::Release(
                        <ReleaseRequest as Native17Build>::take_output_data(child)
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
                RequestCache17Child::Hello(a) => {
                    <HelloRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Discover(a) => {
                    <DiscoverRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Realize(a) => {
                    <RealizeRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Admit(a) => {
                    <AdmitRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Activate(a) => {
                    <ActivateRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Input(a) => {
                    <InputRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Observe(a) => {
                    <ObserveRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Begin(a) => {
                    <BeginRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Poll(a) => {
                    <PollRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Cancel(a) => {
                    <CancelRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::QuantumClose(a) => {
                    <QuantumCloseRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::WorldActivate(a) => {
                    <WorldActivateRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Abort(a) => {
                    <AbortRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Retire(a) => {
                    <RetireRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::BlobBegin(a) => {
                    <BlobBeginRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::BlobChunk(a) => {
                    <BlobChunkRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::BlobFinish(a) => {
                    <BlobFinishRequest as Native17Build>::observe_attempt_data(a, o)?
                }
                RequestCache17Child::Release(a) => {
                    <ReleaseRequest as Native17Build>::observe_attempt_data(a, o)?
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
            RequestBody::Hello(v) => <HelloRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Discover(v) => {
                <DiscoverRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::Realize(v) => <RealizeRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Admit(v) => <AdmitRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Activate(v) => {
                <ActivateRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::Input(v) => <InputRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Observe(v) => <ObserveRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Begin(v) => <BeginRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Poll(v) => <PollRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Cancel(v) => <CancelRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::QuantumClose(v) => {
                <QuantumCloseRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::WorldActivate(v) => {
                <WorldActivateRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::Abort(v) => <AbortRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::Retire(v) => <RetireRequest as Native17Build>::observe_output_data(v, o),
            RequestBody::BlobBegin(v) => {
                <BlobBeginRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::BlobChunk(v) => {
                <BlobChunkRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::BlobFinish(v) => {
                <BlobFinishRequest as Native17Build>::observe_output_data(v, o)
            }
            RequestBody::Release(v) => <ReleaseRequest as Native17Build>::observe_output_data(v, o),
        }
    }
}
