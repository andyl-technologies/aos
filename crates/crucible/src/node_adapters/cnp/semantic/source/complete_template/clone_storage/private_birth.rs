//! Prices the concrete private-Birth ContentRef and Id Clone constructors.
//!
//! The actual Birth row separately prices requested clone backing and retained
//! Option assignments. This supplier reuses the closed installation leaf and
//! byte-copy machinery for these exact types; it does not walk JSON or maps.

use super::*;

/// Quotes the actual host-reference and private-Id Clone return/control windows.
///
/// The caller admits the fixed counter before this borrowed walk. The returned
/// transient and scratch axes supplement the actual retained string requests;
/// they create no clone, File, source authority or allocation permission.
///
/// # Errors
/// Refuses unsupported locked sequence geometry, overflow or excessive demand.
pub(in crate::node_adapters::cnp::semantic) fn private_birth_clone_construction_data(
    host: &ContentRef,
    private_launch: &Id,
    maximum: usize,
) -> Result<(usize, usize), RuntimeError> {
    let mut quote = CloneQuote {
        transient: 0,
        scratch: 0,
        maximum,
    };
    host.clone_storage(&mut quote)?;
    private_launch.clone_storage(&mut quote)?;
    Ok((quote.transient, quote.scratch))
}

/// Names fixed controls before the concrete borrowed clone quote.
///
/// The ContentRef and nested HashRef record loans coexist. Their String leaves
/// and the later Id leaf use the same closed byte-copy sequence producer; every
/// reached Clone return and receiver is added independently by the actual walk.
pub(in crate::node_adapters::cnp::semantic) fn private_birth_clone_counter_scratch_data() -> usize {
    NodeRuntime::capture_installation_sequence_clone_counter_scratch_data()
        + size_of::<&ContentRef>()
        + size_of::<&Id>()
        + size_of::<usize>() // public maximum argument
        + size_of::<CloneQuote>() // initializer
        + size_of::<CloneQuote>() // quote local
        + size_of::<&mut CloneQuote>() // leaf visitor argument
        + size_of::<&mut CloneQuote>() // nested output receiver
        + size_of::<&mut CloneQuote>() // nested add receiver
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>() // host leaf result
        + size_of::<Result<(), RuntimeError>>() // Id leaf result
        + size_of::<Result<(), RuntimeError>>() // output result
        + size_of::<Result<(), RuntimeError>>() // sequence result
        + size_of::<Result<(), RuntimeError>>() // add result
        + size_of::<Option<usize>>() // checked-add result
        + size_of::<[usize; 3]>() // add arguments and checked total
        + size_of::<[usize; 2]>() // counter accumulator and record fields argument
        + size_of::<bool>() // the audited u8 TrivialClone branch argument
        + size_of::<&str>() // actual Id::as_str result
        + record_counter::<ContentRef>(
            size_of::<&HashRef>() + size_of::<&U64>() + size_of::<&String>(),
        )
        + record_counter::<HashRef>(
            size_of::<&String>() + size_of::<&String>() + size_of::<&String>(),
        )
        + record_counter::<String>(0)
        + record_counter::<Id>(size_of::<&String>())
        + record_counter::<U64>(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> (ContentRef, Id) {
        let mut host = ContentRef {
            hash: HashRef {
                algorithm: "blake3-256".to_owned(),
                domain: "cnp.blob.v1".to_owned(),
                digest: "0".repeat(64),
            },
            length: U64::new(1),
            media_type: "application/octet-stream".to_owned(),
        };
        host.hash.algorithm.reserve_exact(128);
        host.hash.domain.reserve_exact(256);
        host.hash.digest.reserve_exact(512);
        host.media_type.reserve_exact(1024);
        (host, Id::new("private-birth-clone-operand").unwrap())
    }

    #[test]
    fn real_leaf_clone_outputs_preserve_operands_and_ignore_original_spare_capacity() {
        let (host, private_launch) = operands();
        let quoted = private_birth_clone_construction_data(&host, &private_launch, usize::MAX)
            .unwrap();
        let host_clone = host.clone();
        let id_clone = private_launch.clone();

        assert_eq!(host_clone, host);
        assert_eq!(id_clone, private_launch);
        assert_ne!(host_clone.hash.algorithm.as_ptr(), host.hash.algorithm.as_ptr());
        assert_ne!(id_clone.as_str().as_ptr(), private_launch.as_str().as_ptr());
        assert_eq!(
            private_birth_clone_construction_data(&host_clone, &id_clone, usize::MAX).unwrap(),
            quoted
        );
        assert!(host.hash.algorithm.capacity() > host_clone.hash.algorithm.capacity());
        let mut returns = size_of::<ContentRef>()
            + size_of::<HashRef>()
            + size_of::<U64>()
            + size_of::<Id>()
            + size_of::<String>() * 5;
        let mut controls = size_of::<&ContentRef>()
            + size_of::<&HashRef>()
            + size_of::<&U64>()
            + size_of::<&Id>()
            + size_of::<&String>() * 5;
        for text in [
            host.hash.algorithm.as_str(),
            host.hash.domain.as_str(),
            host.hash.digest.as_str(),
            host.media_type.as_str(),
            private_launch.as_str(),
        ] {
            let (returned, scratch) =
                NodeRuntime::capture_installation_sequence_clone_storage_data::<u8>(
                    text.len(), true, usize::MAX,
                )
                .unwrap();
            returns += returned;
            controls += scratch;
        }
        // These are the actual nested Clone outputs/receivers, not an outer
        // ContentRef-sized donation for its String/Vec/RawVec constructor chain.
        assert_eq!(quoted, (returns, controls));
    }

    #[test]
    fn actual_nested_leaf_return_row_accepts_exact_and_refuses_one_short() {
        let (host, private_launch) = operands();
        let (transient, scratch) =
            private_birth_clone_construction_data(&host, &private_launch, usize::MAX).unwrap();
        let exact = transient.checked_add(scratch).unwrap();

        assert_eq!(
            private_birth_clone_construction_data(&host, &private_launch, exact).unwrap(),
            (transient, scratch)
        );
        assert!(matches!(
            private_birth_clone_construction_data(&host, &private_launch, exact - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(private_launch.as_str(), "private-birth-clone-operand");
        assert_eq!(host.hash.digest, "0".repeat(64));
    }
}
