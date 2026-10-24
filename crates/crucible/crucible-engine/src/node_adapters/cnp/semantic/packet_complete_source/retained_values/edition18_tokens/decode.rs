//! Constructs guarded literal Values and retains their iterative teardown bank.

use super::*;

#[path = "decode/retirement.rs"]
mod retirement;

/// Owns one open array/object and any still-unconsumed object key.
pub(super) enum Frame {
    Array(Vec<Value>),
    Object {
        values: Map<String, Value>,
        key: Option<String>,
    },
}

/// Keeps all failed/incomplete literal assembly under iterative destruction.
///
/// The original constructor reserves retirement workspace before any owned
/// Value appears. No owning Value is extracted; all partial/completed trees
/// remain covered by this same preadmitted bank until they are destroyed.
pub(crate) struct LiteralValue18DecodeAttempt {
    started: bool,
    failed: bool,
    complete: bool,
    frames: Vec<Frame>,
    // This separately admitted bank exists before any owning Value is built.
    // Its capacity bounds every partial/completed tree frontier at retirement.
    retirement: Vec<Value>,
    pending: Option<Value>,
    value: Option<Value>,
}

impl LiteralValue18DecodeAttempt {
    /// Creates empty inline output custody before any decoder allocation.
    pub(crate) const fn new() -> Self {
        Self {
            started: false,
            failed: false,
            complete: false,
            frames: Vec::new(),
            retirement: Vec::new(),
            pending: None,
            value: None,
        }
    }

    /// Returns the actual attempted, failed and complete DATA-construction flags.
    pub(crate) fn state_data(&self) -> (bool, bool, bool) {
        (self.started, self.failed, self.complete)
    }

    /// Borrows assembled literal DATA while its iterative destruction owner lives.
    ///
    /// This reference does not authorize an ordinary deep clone, equality walk,
    /// serde conversion or transfer into an unguarded Value owner. Consumers use
    /// flat tokens or independently bounded shallow preflight, or must supply
    /// separately funded iterative operations retaining this same owner guard.
    ///
    /// # Errors
    /// Refuses failed or incomplete assembly.
    pub(crate) fn value(&self) -> Result<&Value, RuntimeError> {
        if !self.complete || self.failed {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.value.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Names the constant controls of the allocation-free retirement walk.
    ///
    /// The constructor independently reserves its actual owning workspace in R.
    /// Enclosing disposal must retain these fixed controls; no T allocation or
    /// unbounded recursive Value destructor is hidden in retirement.
    pub(crate) fn retirement_counter_scratch_data() -> usize {
        retirement::counter_scratch_data()
    }

    /// Counts actual partial children under a separately funded traversal bank.
    ///
    /// The caller admits retained_decode_prewalk_data(observed_nodes) first. Every
    /// child walk has its own disposable bank at a distinct time; their storage
    /// sums retain all simultaneous constructed owners, not only the largest.
    ///
    /// # Errors
    /// Refuses insufficient actual population, layout overflow or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        observed_nodes: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut bytes = checked_sum(
            [
                size_of::<Self>(),
                self.frames
                    .capacity()
                    .checked_mul(size_of::<Frame>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                self.retirement
                    .capacity()
                    .checked_mul(size_of::<Value>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        for frame in &self.frames {
            match frame {
                Frame::Array(values) => {
                    bytes = checked_sum(
                        [
                            bytes,
                            values
                                .capacity()
                                .checked_mul(size_of::<Value>())
                                .ok_or(RuntimeError::ResourceLimit)?,
                        ],
                        maximum,
                    )?;
                    for value in values {
                        bytes = checked_sum(
                            [
                                bytes,
                                geometry::value_backing(value, observed_nodes, maximum)?,
                            ],
                            maximum,
                        )?;
                    }
                }
                Frame::Object { values, key } => {
                    bytes = checked_sum(
                        [
                            bytes,
                            map_storage(values.len(), maximum)?,
                            key.as_ref().map_or(0, String::capacity),
                        ],
                        maximum,
                    )?;
                    for (key, value) in values {
                        bytes = checked_sum(
                            [
                                bytes,
                                key.capacity(),
                                geometry::value_backing(value, observed_nodes, maximum)?,
                            ],
                            maximum,
                        )?;
                    }
                }
            }
        }
        for value in self.pending.iter().chain(self.value.iter()) {
            bytes = checked_sum(
                [
                    bytes,
                    geometry::value_backing(value, observed_nodes, maximum)?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }

    fn begin(&mut self) -> Result<(), RuntimeError> {
        if self.started
            || self.failed
            || self.complete
            || !self.frames.is_empty()
            || self.retirement.capacity() != 0
            || self.pending.is_some()
            || self.value.is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.started = true;
        self.failed = true;
        Ok(())
    }

    fn accepts_value(&self) -> Result<(), RuntimeError> {
        if self.pending.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        match self.frames.last() {
            Some(Frame::Array(values)) if values.len() < values.capacity() => Ok(()),
            Some(Frame::Object { key: Some(_), .. }) => Ok(()),
            None if self.value.is_none() => Ok(()),
            _ => Err(RuntimeError::UnsupportedFacet),
        }
    }

    fn attach_pending(&mut self) -> Result<(), RuntimeError> {
        match self.frames.last_mut() {
            Some(Frame::Array(values)) => {
                if values.len() == values.capacity() {
                    return Err(RuntimeError::ResourceLimit);
                }
                values.push(self.pending.take().ok_or(RuntimeError::OwnerUnavailable)?);
            }
            Some(Frame::Object { values, key }) => {
                let actual_key = key.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
                if values.contains_key(actual_key) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let value = self.pending.take().ok_or(RuntimeError::OwnerUnavailable)?;
                values.insert(key.take().ok_or(RuntimeError::OwnerUnavailable)?, value);
            }
            None => {
                if self.value.is_some() {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                self.value = self.pending.take();
            }
        }
        Ok(())
    }
}

/// Keeps an exact flat-token decoder row without issuing an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiteralValue18DecodeQuote {
    tokens: usize,
    value_nodes: usize,
    depth: usize,
    storage: LiteralValue18Storage,
}

impl LiteralValue18DecodeQuote {
    /// Returns the independently counted actual Value-node population.
    pub(crate) fn literal_population_bound_data(self) -> usize {
        self.value_nodes
    }

    /// Returns the independently admitted decoder constructor row.
    pub(crate) fn requested_storage_data(self) -> (usize, usize, usize) {
        self.storage.requested_storage_data()
    }
}

/// Quotes the independent transient bank and complete fixed S for a census.
///
/// The population is the actual retained Value population, or the actual
/// Value-node population returned by this decoder's quote.
///
/// # Errors
/// Refuses checked layout overflow or the independent prewalk ceiling.
pub(crate) fn retained_decode_prewalk_data(
    observed_nodes: usize,
    maximum: usize,
) -> Result<LiteralValue18Storage, RuntimeError> {
    LiteralValue18Storage::new(
        0,
        observed_nodes
            .checked_mul(size_of::<walk::Frame<'_>>())
            .ok_or(RuntimeError::ResourceLimit)?,
        geometry::decode_counter_scratch_data(),
        maximum,
    )
}

/// Quotes actual frame, array, map and string constructors before decoding.
///
/// This flat scan creates no Value, parser, serializer or borrowed heap stack.
/// It charges every actual start/key/string occurrence even if later grammar
/// validation refuses. Child counts come from the private index constructed
/// from these exact tokens before their owning attempt can complete.
///
/// # Errors
/// Refuses unbalanced extents, invalid numbers, arithmetic or storage bounds.
pub(crate) fn quote_decode_data(
    data: &LiteralValue18Data,
    maximum: usize,
) -> Result<LiteralValue18DecodeQuote, RuntimeError> {
    let count = data.token_count()?;
    if data.container_children.len() != count {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let mut value_nodes = 0usize;
    let mut depth = 0usize;
    let mut maximum_depth = 0usize;
    let mut arrays = 0usize;
    let mut trees = 0usize;
    let mut strings = 0usize;
    for index in 0..count {
        let token = data.token(index)?;
        if !matches!(
            token,
            LiteralToken18::Key(_) | LiteralToken18::ArrayEnd | LiteralToken18::ObjectEnd
        ) {
            value_nodes = value_nodes
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        match token {
            LiteralToken18::ArrayStart => {
                let child_count = *data
                    .container_children
                    .get(index)
                    .ok_or(RuntimeError::UnsupportedFacet)?;
                arrays = checked_sum(
                    [
                        arrays,
                        child_count
                            .checked_mul(size_of::<Value>())
                            .ok_or(RuntimeError::ResourceLimit)?,
                    ],
                    maximum,
                )?;
                depth = depth.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                maximum_depth = maximum_depth.max(depth);
            }
            LiteralToken18::ObjectStart => {
                trees = checked_sum(
                    [
                        trees,
                        map_storage(
                            *data
                                .container_children
                                .get(index)
                                .ok_or(RuntimeError::UnsupportedFacet)?,
                            maximum,
                        )?,
                    ],
                    maximum,
                )?;
                depth = depth.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                maximum_depth = maximum_depth.max(depth);
            }
            LiteralToken18::ArrayEnd | LiteralToken18::ObjectEnd => {
                depth = depth.checked_sub(1).ok_or(RuntimeError::UnsupportedFacet)?
            }
            LiteralToken18::String(text) | LiteralToken18::Key(text) => {
                strings = checked_sum([strings, text.len()], maximum)?
            }
            LiteralToken18::Signed(bits) if i64::from_ne_bytes(bits.get().to_ne_bytes()) >= 0 => {
                return Err(RuntimeError::UnsupportedFacet);
            }
            LiteralToken18::FloatBits(bits) if !f64::from_bits(bits.get()).is_finite() => {
                return Err(RuntimeError::UnsupportedFacet);
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let frames = maximum_depth
        .checked_mul(size_of::<Frame>())
        .ok_or(RuntimeError::ResourceLimit)?;
    let retirement = value_nodes
        .checked_mul(size_of::<Value>())
        .ok_or(RuntimeError::ResourceLimit)?;
    let retained = checked_sum(
        [
            size_of::<LiteralValue18DecodeAttempt>(),
            frames,
            retirement,
            arrays,
            trees,
            strings,
        ],
        maximum,
    )?;
    // Independent tree constructor T covers the same actual pinned node classes
    // during insertion/splits, rather than borrowing their future retained R.
    let storage = LiteralValue18Storage::new(
        retained,
        trees,
        geometry::decode_counter_scratch_data(),
        maximum,
    )?;
    Ok(LiteralValue18DecodeQuote {
        tokens: count,
        value_nodes,
        depth: maximum_depth,
        storage,
    })
}

/// Constructs the literal Value in the caller's once-started retained attempt.
///
/// # Errors
/// Refuses reuse, changed geometry, invalid chronology/duplicate keys, a wrong
/// close kind, allocation failure or any independent construction bound.
/// Failed frames, keys, Values and all spare banks remain in `output`.
pub(crate) fn decode_into_data(
    data: &LiteralValue18Data,
    quote: LiteralValue18DecodeQuote,
    output: &mut LiteralValue18DecodeAttempt,
    maximum: usize,
) -> Result<(), RuntimeError> {
    output.begin()?;
    if quote_decode_data(data, maximum)? != quote {
        return Err(RuntimeError::ForeignAuthority);
    }
    // No owning Value exists before this retirement reservation succeeds.
    // Each start/leaf token creates one node; all partial roots and open frame
    // children partition those same nodes. A frontier can never exceed their
    // independently counted total, even when construction later fails.
    output
        .retirement
        .try_reserve_exact(quote.value_nodes)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    output
        .frames
        .try_reserve_exact(quote.depth)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    for index in 0..quote.tokens {
        match data.token(index)? {
            LiteralToken18::ArrayStart => {
                output.accepts_value()?;
                if output.frames.len() == output.frames.capacity() {
                    return Err(RuntimeError::ResourceLimit);
                }
                output.frames.push(Frame::Array(Vec::new()));
                let Some(Frame::Array(values)) = output.frames.last_mut() else {
                    return Err(RuntimeError::OwnerUnavailable);
                };
                values
                    .try_reserve_exact(
                        *data
                            .container_children
                            .get(index)
                            .ok_or(RuntimeError::UnsupportedFacet)?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            LiteralToken18::ObjectStart => {
                output.accepts_value()?;
                if output.frames.len() == output.frames.capacity() {
                    return Err(RuntimeError::ResourceLimit);
                }
                output.frames.push(Frame::Object {
                    values: Map::new(),
                    key: None,
                });
            }
            LiteralToken18::Key(input) => {
                let Some(Frame::Object { values, key }) = output.frames.last_mut() else {
                    return Err(RuntimeError::UnsupportedFacet);
                };
                if key.is_some() || values.contains_key(input) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                *key = Some(String::new());
                let key = key.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
                key.try_reserve_exact(input.len())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                key.push_str(input);
            }
            LiteralToken18::ArrayEnd => {
                if !matches!(output.frames.last(), Some(Frame::Array(_))) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let Some(Frame::Array(values)) = output.frames.pop() else {
                    return Err(RuntimeError::OwnerUnavailable);
                };
                output.pending = Some(Value::Array(values));
                output.attach_pending()?;
            }
            LiteralToken18::ObjectEnd => {
                if !matches!(output.frames.last(), Some(Frame::Object { key: None, .. })) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let Some(Frame::Object { values, .. }) = output.frames.pop() else {
                    return Err(RuntimeError::OwnerUnavailable);
                };
                output.pending = Some(Value::Object(values));
                output.attach_pending()?;
            }
            token => {
                output.accepts_value()?;
                output.pending = Some(match token {
                    LiteralToken18::Null => Value::Null,
                    LiteralToken18::Bool(value) => Value::Bool(*value),
                    LiteralToken18::Unsigned(value) => Value::from(value.get()),
                    LiteralToken18::Signed(value) => {
                        Value::from(i64::from_ne_bytes(value.get().to_ne_bytes()))
                    }
                    LiteralToken18::FloatBits(value) => Value::Number(
                        serde_json::Number::from_f64(f64::from_bits(value.get()))
                            .ok_or(RuntimeError::UnsupportedFacet)?,
                    ),
                    LiteralToken18::String(_) => Value::String(String::new()),
                    _ => return Err(RuntimeError::UnsupportedFacet),
                });
                if let LiteralToken18::String(input) = token {
                    let Some(Value::String(value)) = &mut output.pending else {
                        return Err(RuntimeError::OwnerUnavailable);
                    };
                    value
                        .try_reserve_exact(input.len())
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                    value.push_str(input);
                }
                output.attach_pending()?;
            }
        }
    }
    if !output.frames.is_empty() || output.pending.is_some() || output.value.is_none() {
        return Err(RuntimeError::UnsupportedFacet);
    }
    output.complete = true;
    output.failed = false;
    Ok(())
}
