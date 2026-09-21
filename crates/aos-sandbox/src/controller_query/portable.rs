//! Checked portable descriptor and feature values shared by inert clients.

use aos_proto::aos::sandbox::v1::{Feature, ObjectDescriptor};
use buffa::Message as _;

use super::model::{ClientStateItem, MAXIMUM_PUBLIC_RESOURCE_BYTES};
use super::registry::{validate_descriptor, validate_descriptor_media, validate_features};
use super::resource::InvalidPublicResource;

/// Stores one deeply checked established public object descriptor.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedObjectDescriptorV1(ObjectDescriptor);

impl TryFrom<ObjectDescriptor> for CheckedObjectDescriptorV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: ObjectDescriptor) -> Result<Self, Self::Error> {
        if value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PUBLIC_RESOURCE_BYTES
        {
            return Err(InvalidPublicResource::ResourceTooLarge);
        }
        validate_descriptor(&value)?;
        Ok(Self(value))
    }
}

impl CheckedObjectDescriptorV1 {
    /// Returns the established checked descriptor.
    #[must_use]
    pub const fn as_proto(&self) -> &ObjectDescriptor {
        &self.0
    }
}

impl super::client_state_sealed::Sealed for CheckedObjectDescriptorV1 {}

impl ClientStateItem for CheckedObjectDescriptorV1 {
    fn encoded_byte_cost(&self) -> usize {
        self.0.compute_size(&mut buffa::SizeCache::new()) as usize
    }
}

macro_rules! checked_descriptor_role {
    ($name:ident, $summary:literal, $media_type:literal) => {
        #[doc = $summary]
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(ObjectDescriptor);

        impl TryFrom<ObjectDescriptor> for $name {
            type Error = InvalidPublicResource;

            fn try_from(value: ObjectDescriptor) -> Result<Self, Self::Error> {
                if value.compute_size(&mut buffa::SizeCache::new()) as usize
                    > MAXIMUM_PUBLIC_RESOURCE_BYTES
                {
                    return Err(InvalidPublicResource::ResourceTooLarge);
                }
                validate_descriptor_media(&value, $media_type)?;
                Ok(Self(value))
            }
        }

        impl $name {
            /// Returns the role-checked established descriptor.
            #[must_use]
            pub const fn as_proto(&self) -> &ObjectDescriptor {
                &self.0
            }
        }
    };
}

checked_descriptor_role!(
    CheckedSandboxSpecificationV1,
    "Stores a descriptor restricted to the portable sandbox-spec media type.",
    "application/vnd.aos.sandbox.spec.v1+cbor"
);
checked_descriptor_role!(
    CheckedPolicyDescriptorV1,
    "Stores a descriptor restricted to the normalized policy media type.",
    "application/vnd.aos.sandbox.policy.v1+cbor"
);
checked_descriptor_role!(
    CheckedFilesystemViewDescriptorV1,
    "Stores a descriptor restricted to the immutable filesystem-view media type.",
    "application/vnd.aos.sandbox.view.v1+cbor"
);

/// Stores one bounded canonical set of registered base-v1 features.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedFeatureSetV1(Vec<Feature>);

impl TryFrom<Vec<Feature>> for CheckedFeatureSetV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: Vec<Feature>) -> Result<Self, Self::Error> {
        validate_features(&value)?;
        Ok(Self(value))
    }
}

impl CheckedFeatureSetV1 {
    /// Returns canonical registered features.
    #[must_use]
    pub fn as_slice(&self) -> &[Feature] {
        &self.0
    }
}
