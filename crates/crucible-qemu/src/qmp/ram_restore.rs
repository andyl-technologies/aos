//! Binds bounded canonical RAM metadata to an independently retained lazy source.
//!
//! ```text
//! restore = identity + root-fdname + logical-root + topology + source-binding
//!           + device-fdname + device-content + device-bound + cancellation
//! ```

use crucible::ContentHash;
use crucible_protocol::ram_page::RamPageBinding;
use crucible_ram::{RootRecord, Scope};
use serde_json::{Value, json};

use super::{QmpCheckpointIdentity, QmpCommandKind, QmpDescriptorName, QmpError};

/// Names the three independently imported restore descriptors.
pub(crate) struct QmpCheckpointRestoreDescriptorNames {
    /// Names bounded sealed RAM metadata.
    pub(crate) root: QmpDescriptorName,
    /// Names authenticated non-RAM device state.
    pub(crate) device: QmpDescriptorName,
    /// Names the cancellation notification endpoint.
    pub(crate) cancellation: QmpDescriptorName,
}

/// A sealed bounded root record and lazy page source selected for exact restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointRestoreRequest {
    root_record: RootRecord,
    binding: RamPageBinding,
    root_descriptor: QmpDescriptorName,
    device_descriptor: QmpDescriptorName,
    device_content: ContentHash,
    cancellation_descriptor: QmpDescriptorName,
    identity: QmpCheckpointIdentity,
    maximum_device_bytes: u64,
}

impl QmpCheckpointRestoreRequest {
    /// Admits immutable metadata and distinct descriptors for one lazy restore.
    ///
    /// # Errors
    ///
    /// Returns an error for nonexact roots, excessive metadata, empty bindings,
    /// root mismatch, zero device bounds, or aliased descriptors.
    pub(crate) fn new_paged(
        root_record: &RootRecord,
        binding: RamPageBinding,
        descriptors: QmpCheckpointRestoreDescriptorNames,
        device_content: ContentHash,
        identity: QmpCheckpointIdentity,
        maximum_device_bytes: u64,
    ) -> Result<Self, QmpError> {
        let QmpCheckpointRestoreDescriptorNames {
            root: root_descriptor,
            device: device_descriptor,
            cancellation: cancellation_descriptor,
        } = descriptors;
        if root_record.scope() != Scope::Exact
            || root_record.encoded_len() > crucible_ram::Limits::default().max_record_bytes
            || binding.validate().is_err()
            || binding.root_digest != *root_record.digest().as_bytes()
            || maximum_device_bytes == 0
            || root_descriptor == device_descriptor
            || root_descriptor == cancellation_descriptor
            || device_descriptor == cancellation_descriptor
        {
            return Err(QmpError::InvalidBound {
                operation: "admit an authenticated lazy RAM restore",
            });
        }
        Ok(Self {
            root_record: root_record.clone(),
            binding,
            root_descriptor,
            device_descriptor,
            device_content,
            cancellation_descriptor,
            identity,
            maximum_device_bytes,
        })
    }

    pub(crate) const fn identity(&self) -> QmpCheckpointIdentity {
        self.identity
    }

    pub(crate) fn root_record(&self) -> &RootRecord {
        &self.root_record
    }

    pub(crate) const fn binding(&self) -> RamPageBinding {
        self.binding
    }

    pub(crate) fn topology(&self) -> ContentHash {
        ContentHash {
            bytes: *self.root_record.topology().digest().as_bytes(),
        }
    }

    pub(crate) const fn root_descriptor(&self) -> &QmpDescriptorName {
        &self.root_descriptor
    }

    pub(crate) const fn device_descriptor(&self) -> &QmpDescriptorName {
        &self.device_descriptor
    }

    pub(crate) const fn cancellation_descriptor(&self) -> &QmpDescriptorName {
        &self.cancellation_descriptor
    }

    pub(super) fn wire_value(&self) -> Value {
        json!({
            "checkpoint-sha256": self.identity.checkpoint().to_hex(),
            "target-sha256": self.identity.target().to_hex(),
            "frontier-sha256": self.identity.frontier().to_hex(),
            "ram-root-fdname": self.root_descriptor.as_str(),
            "ram-root-blake3": self.root_record.digest().to_string(),
            "topology-blake3": self.root_record.topology().digest().to_string(),
            "source-session": hex(&self.binding.session),
            "source-owner": hex(&self.binding.owner_incarnation),
            "source-generation": self.binding.source_generation,
            "device-fdname": self.device_descriptor.as_str(),
            "device-sha256": self.device_content.to_hex(),
            "cancellation-fdname": self.cancellation_descriptor.as_str(),
            "maximum-device-bytes": self.maximum_device_bytes,
        })
    }
}

/// The acknowledged lazy source installation and non-RAM reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointRestore {
    topology: ContentHash,
}

impl QmpCheckpointRestore {
    pub(crate) const fn topology(self) -> ContentHash {
        self.topology
    }
}

pub(super) fn parse_checkpoint_restore(
    value: &Value,
    request: &QmpCheckpointRestoreRequest,
) -> Result<QmpCheckpointRestore, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::CheckpointRestore,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let expected = request.wire_value();
    let expected = expected.as_object().ok_or_else(&malformed)?;
    let bindings = [
        "checkpoint-sha256",
        "target-sha256",
        "frontier-sha256",
        "ram-root-blake3",
        "topology-blake3",
        "source-session",
        "source-owner",
        "source-generation",
    ];
    if object.len() != bindings.len() + 3
        || object.get("schema-version").and_then(Value::as_u64) != Some(3)
        || bindings
            .iter()
            .any(|key| object.get(*key) != expected.get(*key))
        || object.get("ram-bytes").and_then(Value::as_u64) != Some(0)
        || object
            .get("device-bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes == 0 || bytes > request.maximum_device_bytes)
    {
        return Err(malformed());
    }
    Ok(QmpCheckpointRestore {
        topology: request.topology(),
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(test)]
pub(crate) fn fixture_source()
-> Result<crate::QemuPagedRamRestoreSource, Box<dyn std::error::Error>> {
    struct Backing(RootRecord);
    impl crate::ram_source::QemuRamBacking for Backing {
        fn root_object_id(&self) -> &str {
            "fixture-root"
        }
        fn root_record(&self) -> &RootRecord {
            &self.0
        }
        fn read_page_with_proof(
            &self,
            _: &str,
            _: u64,
            _: &mut dyn FnMut() -> Result<(), crate::ram_source::QemuRamSourceError>,
        ) -> Result<(Vec<u8>, crucible_ram::PageProof), crate::ram_source::QemuRamSourceError>
        {
            Err(crate::ram_source::QemuRamSourceError::Backing(
                "unexpected fixture page read".to_owned(),
            ))
        }
    }
    let topology = crucible_ram::Topology::new(
        vec![crucible_ram::RegionDescriptor::new(
            "ram",
            crucible_ram::RegionClass::MutableMain,
            4096,
        )?],
        crucible_ram::Limits::default(),
    )?;
    let tree = crucible_ram::RegionTree::zeroed(4096, &crucible_ram::MetadataBudget::new(65536))?;
    let record = RootRecord::new(topology, Scope::Exact, vec![tree.digest()])?;
    Ok(crate::QemuPagedRamRestoreSource::new(std::sync::Arc::new(
        Backing(record),
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Result<QmpCheckpointRestoreRequest, Box<dyn std::error::Error>> {
        let source = fixture_source()?;
        Ok(QmpCheckpointRestoreRequest::new_paged(
            source.root_record(),
            source.binding(),
            QmpCheckpointRestoreDescriptorNames {
                root: QmpDescriptorName::new("root")?,
                device: QmpDescriptorName::new("device")?,
                cancellation: QmpDescriptorName::new("cancel")?,
            },
            ContentHash::from_bytes(b"device"),
            QmpCheckpointIdentity::new(
                ContentHash::from_bytes(b"checkpoint"),
                ContentHash::from_bytes(b"target"),
                ContentHash::from_bytes(b"frontier"),
            ),
            4096,
        )?)
    }

    fn response(request: &QmpCheckpointRestoreRequest) -> Value {
        let mut value = request.wire_value();
        let object = value
            .as_object_mut()
            .unwrap_or_else(|| panic!("fixture response is an object"));
        for key in [
            "ram-root-fdname",
            "device-fdname",
            "device-sha256",
            "cancellation-fdname",
            "maximum-device-bytes",
        ] {
            object.remove(key);
        }
        object.insert("schema-version".to_owned(), Value::from(3));
        object.insert("ram-bytes".to_owned(), Value::from(0));
        object.insert("device-bytes".to_owned(), Value::from(128));
        value
    }

    #[test]
    fn lazy_restore_response_binds_root_namespace_and_no_eager_ram()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let response = response(&request);
        assert_eq!(
            parse_checkpoint_restore(&response, &request)?.topology(),
            request.topology()
        );
        for (field, value) in [
            ("schema-version", Value::from(2)),
            ("ram-root-blake3", Value::from("00".repeat(32))),
            ("topology-blake3", Value::from("00".repeat(32))),
            ("source-session", Value::from("00".repeat(16))),
            ("source-owner", Value::from("00".repeat(16))),
            ("source-generation", Value::from(2)),
            ("ram-bytes", Value::from(1)),
            ("device-bytes", Value::from(0)),
            ("device-bytes", Value::from(4097)),
        ] {
            let mut malformed = response.clone();
            malformed[field] = value;
            assert!(
                parse_checkpoint_restore(&malformed, &request).is_err(),
                "accepted {field}"
            );
        }
        let mut extra = response.clone();
        extra["ram-layers"] = Value::from(1);
        assert!(parse_checkpoint_restore(&extra, &request).is_err());
        for field in response
            .as_object()
            .unwrap_or_else(|| panic!("fixture response is an object"))
            .keys()
        {
            let mut truncated = response.clone();
            truncated
                .as_object_mut()
                .unwrap_or_else(|| panic!("fixture response is an object"))
                .remove(field);
            assert!(parse_checkpoint_restore(&truncated, &request).is_err());
        }
        Ok(())
    }

    #[test]
    fn lazy_restore_admission_rejects_alias_and_foreign_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = fixture_source()?;
        let request = request()?;
        let shared = QmpDescriptorName::new("shared")?;
        assert!(
            QmpCheckpointRestoreRequest::new_paged(
                source.root_record(),
                source.binding(),
                QmpCheckpointRestoreDescriptorNames {
                    root: shared.clone(),
                    device: shared,
                    cancellation: QmpDescriptorName::new("cancel")?,
                },
                ContentHash::from_bytes(b"device"),
                request.identity(),
                4096,
            )
            .is_err()
        );
        let mut binding = source.binding();
        binding.root_digest[0] ^= 1;
        assert!(
            QmpCheckpointRestoreRequest::new_paged(
                source.root_record(),
                binding,
                QmpCheckpointRestoreDescriptorNames {
                    root: QmpDescriptorName::new("root")?,
                    device: QmpDescriptorName::new("device")?,
                    cancellation: QmpDescriptorName::new("cancel")?,
                },
                ContentHash::from_bytes(b"device"),
                request.identity(),
                4096,
            )
            .is_err()
        );
        Ok(())
    }
}
