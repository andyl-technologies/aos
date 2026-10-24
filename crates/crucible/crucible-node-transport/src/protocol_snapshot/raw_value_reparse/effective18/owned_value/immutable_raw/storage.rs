//! Quotes the actual raw custody, independent Rc constructor and fixed controls.

use super::*;

// Layout witness for the exact pinned alloc/src/rc.rs RcInner definition. It is
// never instantiated and exposes no Rc allocation or recovery surface.
#[repr(C, align(2))]
struct RcInnerLayoutData {
    strong: std::cell::Cell<usize>,
    weak: std::cell::Cell<usize>,
    value: RawData,
}

/// Reports this same transfer's prospective immutable-backing demand.
///
/// The actual privately owned frame remains rooted while this numeric row is
/// stored. It is not a detached content identity, quota or native authorization.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18ImmutableRawConstructionData {
    pub(super) maximum: usize,
    pub(super) population: usize,
    pub(super) retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeImport18ImmutableRawConstructionData {
    pub(super) fn quote_data(frame: &RetainedFrame, maximum: usize) -> Result<Self, ProviderError> {
        let mut observer = MetadataObserver::new();
        // RawData is repr(transparent) over this actual frame. This prospective
        // placement adds its independently priced payload/header to the same
        // observed capacities; it claims no already-existing Rc allocation.
        observer.shared_value(frame)?;
        let population = observe::frame_data(frame, &mut observer)?;
        let retained = observe::requested_data(
            size_of::<Option<NativeImport18ImmutableRawCustodyData>>(),
            observer.finish(),
            maximum,
        )?;
        let allocation = sum(&[
            size_of::<RawData>(),
            shared_header_storage_data(1, align_of::<RawData>())?,
        ])?;
        // Rc::new constructs an RcInner initializer and passes it by value to
        // Box::new while the independent heap allocation is being constructed.
        let rc_initializer = size_of::<RcInnerLayoutData>();
        let box_argument = size_of::<RcInnerLayoutData>();
        let transient = sum(&[
            allocation,
            rc_initializer,
            box_argument,
            size_of::<RawData>() * 2,
            size_of::<RetainedFrame>(),
            size_of::<Option<RetainedFrame>>(),
            size_of::<Rc<RawData>>(),
            size_of::<NativeImport18ImmutableRawBankData>(),
            size_of::<Option<NativeImport18ImmutableRawBankData>>(),
        ])?;
        let scratch = Self::counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            maximum,
            population,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn dominates_data(&self, current: &Self) -> bool {
        self.maximum == current.maximum
            && self.population == current.population
            && self.retained >= current.retained
            && self.transient >= current.transient
            && self.scratch >= current.scratch
    }

    #[cfg(test)]
    pub(super) fn shorten_axis_data(&mut self, axis: usize) {
        match axis {
            0 => self.retained -= 1,
            1 => self.transient -= 1,
            _ => self.scratch -= 1,
        }
    }

    /// Returns independently admitted frozen R, Rc constructor T and fixed S.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual transfer, quote, Rc, observation and return control headers.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Option<Self>>()
            + size_of::<&Self>() * 3
            + size_of::<NativeImport18ImmutableRawCustodyData>()
            + size_of::<Option<NativeImport18ImmutableRawCustodyData>>()
            + size_of::<&mut Option<NativeImport18ImmutableRawCustodyData>>()
            + size_of::<&mut NativeImport18ImmutableRawCustodyData>() * 2
            + size_of::<&NativeImport18ImmutableRawCustodyData>() * 2
            + size_of::<RetainedFrame>()
            + size_of::<Option<RetainedFrame>>()
            + size_of::<&mut Option<RetainedFrame>>()
            + size_of::<&RetainedFrame>() * 3
            + size_of::<Option<&RetainedFrame>>()
            + size_of::<Result<&RetainedFrame, ProviderError>>()
            + size_of::<RawData>()
            + size_of::<std::cell::Cell<usize>>() * 2
            + size_of::<std::ptr::NonNull<RcInnerLayoutData>>()
            + size_of::<Box<RcInnerLayoutData>>()
            + size_of::<&mut RcInnerLayoutData>()
            + size_of::<Rc<RawData>>()
            + size_of::<&Rc<RawData>>()
            + size_of::<&RawData>()
            + size_of::<NativeImport18ImmutableRawBankData>()
            + size_of::<Option<NativeImport18ImmutableRawBankData>>()
            + size_of::<&NativeImport18ImmutableRawBankData>()
            + size_of::<Result<&NativeImport18ImmutableRawBankData, ProviderError>>()
            + size_of::<Stage>()
            + size_of::<NativeImport18ImmutableRawCensusData>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<Option<bool>>()
            + size_of::<[usize; 2]>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 10]>()
            + size_of::<&[usize]>() * 3
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
            + size_of::<usize>() * 14
            + observe::counter_scratch_data()
    }
}
