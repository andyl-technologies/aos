//! Deduplicates only proven common owners in the joint private/native census.
//!
//! Standalone wire rows remain complete. These non-wire facts bind the same
//! original inputs and full rows; they neither reduce a guard nor issue rights.
//! The private canonical bank retains its full spare after the duplicated
//! native length is removed once. Independent NativeAckBoot copies stay charged.

use super::*;

/// Binds one joint-only retained intersection to its actual defining inputs.
///
/// Fields are private and no default or wire conversion exists. Each Source
/// authenticates these facts against its original inputs before copying them
/// into its own Core quote; different Source quotes are never deduplicated.
#[derive(Clone, Copy)]
pub struct PacketNativeBirthRetainedOverlapData {
    process: u32,
    thread: std::thread::ThreadId,
    launch: *const PacketNative5SourceLaunch,
    private_launch: *const crucible_node_format::Id,
    inputs: blake3::Hash,
    input_lengths: [usize; 3],
    private_retained: usize,
    native_retained: usize,
    overlap: usize,
}

impl PacketNativeBirthRetainedOverlapData {
    pub(super) fn new(
        input: &PacketNativeBirthStartupInputs<'_>,
        private_owners: [usize; 3],
        native_owners: [usize; 3],
        private_retained: usize,
        native_retained: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let overlap = intersection(private_owners, native_owners, maximum)?;
        if overlap > private_retained || overlap > native_retained {
            return Err(refused());
        }
        Ok(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch: input.launch,
            private_launch: input.private_launch,
            inputs: input_fingerprint(input),
            input_lengths: [
                input.encoded_launch.len(),
                input.source_birth.len(),
                input.host_registration.len(),
            ],
            private_retained,
            native_retained,
            overlap,
        })
    }

    pub(super) fn authenticate_inputs_data(
        &self,
        input: &PacketNativeBirthStartupInputs<'_>,
    ) -> Result<(), ProviderError> {
        self.origin()?;
        let lengths = [
            input.encoded_launch.len(),
            input.source_birth.len(),
            input.host_registration.len(),
        ];
        if self.input_lengths != lengths {
            return Err(refused());
        }
        self.authenticate_input_parts(
            input.launch,
            input.private_launch,
            lengths,
            input_fingerprint(input),
        )
    }

    fn authenticate_input_parts(
        &self,
        launch: *const PacketNative5SourceLaunch,
        private_launch: *const crucible_node_format::Id,
        lengths: [usize; 3],
        digest: blake3::Hash,
    ) -> Result<(), ProviderError> {
        self.origin()?;
        if self.launch != launch
            || self.private_launch != private_launch
            || self.input_lengths != lengths
            || self.inputs != digest
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Returns only the native retained contribution additional to private.
    ///
    /// # Errors
    /// Refuses a different process/thread or complete row pair, invalid
    /// intersection or checked subtraction. Standalone row values are unchanged.
    pub fn additional_native_retained_requested_bytes_data(
        &self,
        private_retained: usize,
        native_retained: usize,
    ) -> Result<usize, ProviderError> {
        self.origin()?;
        if private_retained != self.private_retained
            || native_retained != self.native_retained
            || self.overlap > private_retained
        {
            return Err(refused());
        }
        native_retained
            .checked_sub(self.overlap)
            .ok_or_else(refused)
    }

    /// Preserves the baseline intersection while adding independent row owners.
    ///
    /// Invocation15 additions remain wholly additive on both standalone rows.
    /// This DATA helper cannot introduce another overlap or reduce a contribution.
    ///
    /// # Errors
    /// Refuses a different process/thread or checked full-row overflow.
    pub fn with_additional_retained_requested_bytes_data(
        self,
        private_added: usize,
        native_added: usize,
    ) -> Result<Self, ProviderError> {
        self.origin()?;
        Ok(Self {
            private_retained: self
                .private_retained
                .checked_add(private_added)
                .ok_or_else(refused)?,
            native_retained: self
                .native_retained
                .checked_add(native_added)
                .ok_or_else(refused)?,
            ..self
        })
    }

    fn origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

fn intersection(
    private: [usize; 3],
    native: [usize; 3],
    maximum: usize,
) -> Result<usize, ProviderError> {
    // The positions name exactly launch_bytes, boot.source_birth, registration.
    // In particular min(4*n+256,n) is n: the canonical spare is not removed.
    sum(
        &[
            private[0].min(native[0]),
            private[1].min(native[1]),
            private[2].min(native[2]),
        ],
        maximum,
    )
}

fn input_fingerprint(input: &PacketNativeBirthStartupInputs<'_>) -> blake3::Hash {
    let mut hash =
        blake3::Hasher::new_derive_key("source-owned.native-birth-retained-intersection/1");
    for bytes in [
        input.private_launch.as_str().as_bytes(),
        input.encoded_launch,
        input.source_birth,
        input.host_registration,
    ] {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize()
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<PacketNativeBirthRetainedOverlapData>()
        + size_of::<Result<PacketNativeBirthRetainedOverlapData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<decoded::DecodedStorage>()
        + size_of::<Result<decoded::DecodedStorage, ProviderError>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 8]>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[&[u8]; 4]>()
        + size_of::<std::array::IntoIter<&'static [u8], 4>>()
        + size_of::<&PacketNativeBirthStartupInputs<'static>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inert_rows() -> PacketNativeBirthRetainedOverlapData {
        // This private DATA fixture has no genuine input witness and cannot
        // authenticate a Source or native member. It tests row arithmetic only.
        PacketNativeBirthRetainedOverlapData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch: std::ptr::null(),
            private_launch: std::ptr::null(),
            inputs: blake3::hash(b"inert row arithmetic"),
            input_lengths: [0; 3],
            private_retained: 1000,
            native_retained: 800,
            overlap: 300,
        }
    }

    #[test]
    fn actual_joint_row_authentication_refuses_foreign_rows_and_keeps_invocation_additive() {
        let rows = inert_rows();
        assert_eq!(
            rows.additional_native_retained_requested_bytes_data(1000, 800)
                .unwrap(),
            500
        );
        rows.authenticate_input_parts(
            rows.launch,
            rows.private_launch,
            rows.input_lengths,
            rows.inputs,
        )
        .unwrap();
        assert!(
            rows.authenticate_input_parts(rows.launch, rows.private_launch, [1, 0, 0], rows.inputs)
                .is_err()
        );
        assert!(
            rows.authenticate_input_parts(
                rows.launch,
                rows.private_launch,
                rows.input_lengths,
                blake3::hash(b"foreign original")
            )
            .is_err()
        );
        let foreign_cookie = 1u8;
        assert!(
            rows.authenticate_input_parts(
                std::ptr::from_ref(&foreign_cookie).cast(),
                rows.private_launch,
                rows.input_lengths,
                rows.inputs
            )
            .is_err()
        );
        assert!(
            rows.additional_native_retained_requested_bytes_data(999, 800)
                .is_err()
        );
        assert!(
            rows.additional_native_retained_requested_bytes_data(1000, 799)
                .is_err()
        );
        let added = rows
            .with_additional_retained_requested_bytes_data(41, 59)
            .unwrap();
        assert_eq!(
            added
                .additional_native_retained_requested_bytes_data(1041, 859)
                .unwrap(),
            559
        );
        assert!(
            added
                .additional_native_retained_requested_bytes_data(1000, 800)
                .is_err()
        );
        assert_eq!(added.overlap, rows.overlap);
        assert!(
            rows.with_additional_retained_requested_bytes_data(usize::MAX, 0)
                .is_err()
        );
        let mut foreign = rows;
        foreign.process ^= 1;
        assert!(
            foreign
                .additional_native_retained_requested_bytes_data(1000, 800)
                .is_err()
        );
    }

    #[test]
    fn joint_intersection_preserves_private_spare_and_independent_native_copies() {
        let length = 100usize;
        let private_launch = 4 * length + 256;
        let source = 240usize;
        let registration = 120usize;
        let common = intersection(
            [private_launch, source, registration],
            [length, source, registration],
            usize::MAX,
        )
        .unwrap();
        assert_eq!(common, length + source + registration);
        let private = private_launch + source + registration + 17;
        let independent_native = length + 2 * source + 2 * registration + 31;
        let native = common + independent_native;
        let union = private + native - common;
        assert_eq!(union, private + independent_native);
        assert!(union >= private && union >= native);
        assert!(
            intersection(
                [private_launch, source, registration],
                [length, source, registration],
                common
            )
            .is_ok()
        );
        assert!(
            intersection(
                [private_launch, source, registration],
                [length, source, registration],
                common - 1
            )
            .is_err()
        );
    }
}

#[path = "retained_overlap/settled17.rs"]
mod settled17;
