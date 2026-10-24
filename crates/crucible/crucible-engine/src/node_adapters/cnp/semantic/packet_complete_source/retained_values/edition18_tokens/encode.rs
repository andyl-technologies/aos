//! Quotes and retains flat tokens from one synchronous immutable Value loan.

use super::*;

/// Keeps exact numeric output geometry without retaining a Source/SDK loan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiteralValue18EncodeQuote {
    population: usize,
    tokens: usize,
    containers: usize,
    string_bytes: usize,
    storage: LiteralValue18Storage,
}

impl LiteralValue18EncodeQuote {
    /// Returns the independently admitted constructor row.
    pub(crate) fn requested_storage_data(self) -> (usize, usize, usize) {
        self.storage.requested_storage_data()
    }
}

/// Quotes the disposable borrowed traversal bank before a Value loan begins.
///
/// `observed_nodes` is an actual already-funded retained population, such as the
/// same SDK owner's RetainedProtocolMetadataFacts, rather than a negotiated cap.
/// Its bound includes the visited Value nodes; each open container is one node.
/// The bank is transient and all references die before the quote returns.
///
/// # Errors
/// Refuses checked layout overflow or any independent construction ceiling.
pub(crate) fn traversal_prewalk_data(
    observed_nodes: usize,
    maximum: usize,
) -> Result<LiteralValue18Storage, RuntimeError> {
    LiteralValue18Storage::new(
        0,
        observed_nodes
            .checked_mul(size_of::<walk::Frame<'_>>())
            .ok_or(RuntimeError::ResourceLimit)?,
        geometry::encode_counter_scratch_data(),
        maximum,
    )
}

/// Quotes exact token owners under a separately admitted traversal prewalk.
///
/// The caller first admits traversal_prewalk_data for the actual population.
/// Only this numeric row survives the synchronous immutable Value loan.
///
/// # Errors
/// Refuses insufficient actual population, unsupported numeric representation,
/// portable chunk overflow or any independent requested-storage bound.
pub(crate) fn quote_encode_data(
    value: &Value,
    observed_nodes: usize,
    maximum: usize,
) -> Result<LiteralValue18EncodeQuote, RuntimeError> {
    traversal_prewalk_data(observed_nodes, maximum)?;
    let mut walker = walk::Walker::new(value, observed_nodes)?;
    let mut tokens = 0usize;
    let mut containers = 0usize;
    let mut string_bytes = 0usize;
    while let Some(token) = walker.next_token()? {
        tokens = tokens.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        if matches!(
            token,
            walk::BorrowedToken18::ArrayStart | walk::BorrowedToken18::ObjectStart
        ) {
            containers = containers
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let walk::BorrowedToken18::String(value) | walk::BorrowedToken18::Key(value) = token {
            string_bytes = checked_sum([string_bytes, value.len()], maximum)?;
        }
    }
    let storage = geometry::token_storage(
        tokens,
        string_bytes,
        observed_nodes
            .checked_mul(size_of::<walk::Frame<'_>>())
            .ok_or(RuntimeError::ResourceLimit)?
            .max(
                containers
                    .checked_mul(size_of::<index::Frame<'_>>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ),
        geometry::encode_counter_scratch_data(),
        maximum,
    )?;
    Ok(LiteralValue18EncodeQuote {
        population: observed_nodes,
        tokens,
        containers,
        string_bytes,
        storage,
    })
}

/// Constructs tokens in the caller's once-started retained output attempt.
///
/// The caller independently admits the complete quote before entering. Exact
/// geometry is rechecked under a fresh synchronous Value loan before growth;
/// numeric equality never supplies Source identity or native authority.
///
/// # Errors
/// Refuses reuse, changed demand, actual allocation failure or invalid input.
/// Every constructed bank remains in the same failed attempt on refusal.
pub(crate) fn encode_into_data(
    value: &Value,
    quote: LiteralValue18EncodeQuote,
    output: &mut LiteralValue18TokenAttempt,
    maximum: usize,
) -> Result<(), RuntimeError> {
    output.begin()?;
    if quote_encode_data(value, quote.population, maximum)? != quote {
        return Err(RuntimeError::ForeignAuthority);
    }
    // The first disposable bank was dropped by quote_encode_data. This second
    // bank uses the same independent T at a distinct, nonoverlapping time.
    let mut walker = walk::Walker::new(value, quote.population)?;
    output.prepare_chunks(quote.tokens)?;
    let mut index = 0usize;
    while let Some(token) = walker.next_token()? {
        output.push(index, token)?;
        index = index.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    }
    if index != quote.tokens {
        return Err(RuntimeError::ForeignAuthority);
    }
    drop(walker);
    index::finish(&mut output.data, quote.containers)?;
    output.finish();
    Ok(())
}
