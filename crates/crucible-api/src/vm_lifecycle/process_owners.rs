//! Sorted, fallibly allocated process-ownership maps for durable run state.

use super::QemuProcessIdentity;
use serde::Deserialize as _;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap as _;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProductionLifecycleJournalPhase {
    Idle,
    Intent,
    Prepared,
    ExitsReaped,
    Committed,
    Quarantined,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductionLifecycleJournalNode {
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) node: String,
    #[serde(deserialize_with = "deserialize_process_identity")]
    pub(super) current_process: QemuProcessIdentity,
    #[serde(deserialize_with = "deserialize_optional_process_identity")]
    pub(super) replacement_process: Option<QemuProcessIdentity>,
    pub(super) current_generation: u64,
    pub(super) next_generation: u64,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) transition: String,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) action_sha256: String,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) evidence_sha256: String,
    pub(super) expected_exit_code: Option<i32>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductionLifecycleCompletedExit {
    pub(super) transaction: u64,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) node: String,
    #[serde(deserialize_with = "deserialize_process_identity")]
    pub(super) process: QemuProcessIdentity,
    pub(super) generation: u64,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) transition: String,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) action_sha256: String,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) evidence_sha256: String,
    pub(super) expected_exit_code: i32,
    pub(super) observed_exit_code: i32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductionLifecycleJournal {
    pub(super) version: u32,
    pub(super) transaction: u64,
    pub(super) phase: ProductionLifecycleJournalPhase,
    #[serde(deserialize_with = "deserialize_lifecycle_nodes")]
    pub(super) nodes: FallibleLifecycleRecords<ProductionLifecycleJournalNode>,
    #[serde(deserialize_with = "deserialize_completed_exits")]
    pub(super) completed_exits: FallibleLifecycleRecords<ProductionLifecycleCompletedExit>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductionRunManifest {
    pub(super) version: u32,
    #[serde(deserialize_with = "deserialize_string")]
    pub(super) scenario: String,
    #[serde(deserialize_with = "deserialize_process_identity")]
    pub(super) owner: QemuProcessIdentity,
    #[serde(deserialize_with = "deserialize_current_process_owners")]
    pub(super) processes: ProductionProcessOwners,
    #[serde(deserialize_with = "deserialize_staged_process_owners")]
    pub(super) staged_processes: ProductionProcessOwners,
    pub(super) clean_shutdown: bool,
    pub(super) recovered_after_host_exit: bool,
}

#[path = "process_owners/decode_budget.rs"]
mod decode_budget;
pub(super) use decode_budget::{
    DurableDecodeAllocation, enter_durable_decode_shape, take_durable_decode_allocation,
};
use decode_budget::{
    account_decode_usage, completed_exits_expected, current_processes_expected, decode_usage,
    lifecycle_nodes_expected, record_decode_allocation, staged_processes_expected,
};

struct FallibleOwnedString(String);

impl<'de> serde::Deserialize<'de> for FallibleOwnedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let borrowed: &'de str = serde::Deserialize::deserialize(deserializer)?;
        let mut owned = String::new();
        owned.try_reserve_exact(borrowed.len()).map_err(|_| {
            record_decode_allocation(
                "event_log_bytes",
                decode_usage("event_log_bytes"),
                borrowed.len(),
            );
            serde::de::Error::custom("durable string allocation")
        })?;
        owned.push_str(borrowed);
        account_decode_usage("event_log_bytes", borrowed.len());
        Ok(Self(owned))
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedProcessIdentity<'a> {
    process_id: u32,
    start_time_ticks: u64,
    #[serde(borrow)]
    executable: &'a str,
}

struct FallibleProcessIdentity(QemuProcessIdentity);

impl<'de> serde::Deserialize<'de> for FallibleProcessIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let borrowed = BorrowedProcessIdentity::deserialize(deserializer)?;
        let bytes = borrowed.executable.as_bytes();
        let mut executable = Vec::new();
        executable.try_reserve_exact(bytes.len()).map_err(|_| {
            record_decode_allocation(
                "event_log_bytes",
                decode_usage("event_log_bytes"),
                bytes.len(),
            );
            serde::de::Error::custom("process executable allocation")
        })?;
        executable.extend_from_slice(bytes);
        account_decode_usage("event_log_bytes", bytes.len());
        Ok(Self(QemuProcessIdentity {
            process_id: borrowed.process_id,
            start_time_ticks: borrowed.start_time_ticks,
            executable: std::path::PathBuf::from(OsString::from_vec(executable)),
        }))
    }
}

pub(super) fn deserialize_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    FallibleOwnedString::deserialize(deserializer).map(|owned| owned.0)
}

pub(super) fn deserialize_process_identity<'de, D>(
    deserializer: D,
) -> Result<QemuProcessIdentity, D::Error>
where
    D: serde::Deserializer<'de>,
{
    FallibleProcessIdentity::deserialize(deserializer).map(|owned| owned.0)
}

pub(super) fn deserialize_optional_process_identity<'de, D>(
    deserializer: D,
) -> Result<Option<QemuProcessIdentity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<FallibleProcessIdentity>::deserialize(deserializer)
        .map(|identity| identity.map(|owned| owned.0))
}

/// A sequence whose outer storage is reserved before each owned element decode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct FallibleLifecycleRecords<T>(Vec<T>);

impl<T> std::ops::Deref for FallibleLifecycleRecords<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for FallibleLifecycleRecords<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<Vec<T>> for FallibleLifecycleRecords<T> {
    fn from(records: Vec<T>) -> Self {
        Self(records)
    }
}

impl<'a, T> IntoIterator for &'a FallibleLifecycleRecords<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut FallibleLifecycleRecords<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<T: serde::Serialize> serde::Serialize for FallibleLifecycleRecords<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for FallibleLifecycleRecords<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_records(deserializer, None)
    }
}

fn deserialize_records<'de, D, T>(
    deserializer: D,
    expected: Option<usize>,
) -> Result<FallibleLifecycleRecords<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct RecordsVisitor<T> {
        expected: Option<usize>,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T: serde::Deserialize<'de>> Visitor<'de> for RecordsVisitor<T> {
        type Value = FallibleLifecycleRecords<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded lifecycle record sequence")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut records = Vec::new();
            if let Some(expected) = self.expected {
                records.try_reserve_exact(expected).map_err(|_| {
                    record_decode_allocation(
                        "event_records",
                        decode_usage("event_records"),
                        expected,
                    );
                    serde::de::Error::custom("lifecycle record allocation")
                })?;
            }
            loop {
                if self.expected.is_none() {
                    records.try_reserve(1).map_err(|_| {
                        record_decode_allocation("event_records", decode_usage("event_records"), 1);
                        serde::de::Error::custom("lifecycle record allocation")
                    })?;
                }
                let Some(record) = sequence.next_element()? else {
                    break;
                };
                if self
                    .expected
                    .is_some_and(|expected| records.len() == expected)
                {
                    return Err(serde::de::Error::custom(
                        "lifecycle record count exceeds admitted shape",
                    ));
                }
                records.push(record);
                account_decode_usage("event_records", 1);
            }
            if self
                .expected
                .is_some_and(|expected| records.len() != expected)
            {
                return Err(serde::de::Error::custom(
                    "lifecycle record count differs from admitted shape",
                ));
            }
            Ok(FallibleLifecycleRecords(records))
        }
    }

    deserializer.deserialize_seq(RecordsVisitor {
        expected,
        marker: std::marker::PhantomData,
    })
}

pub(super) fn deserialize_lifecycle_nodes<'de, D, T>(
    deserializer: D,
) -> Result<FallibleLifecycleRecords<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let expected = lifecycle_nodes_expected();
    deserialize_records(deserializer, expected)
}

pub(super) fn deserialize_completed_exits<'de, D, T>(
    deserializer: D,
) -> Result<FallibleLifecycleRecords<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let expected = completed_exits_expected();
    deserialize_records(deserializer, expected)
}

/// Canonically ordered process owners with explicit outer allocation failure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ProductionProcessOwners {
    entries: Vec<(String, QemuProcessIdentity)>,
}

impl ProductionProcessOwners {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &QemuProcessIdentity> {
        self.entries.iter().map(|(_, identity)| identity)
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(node, _)| node)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &QemuProcessIdentity)> {
        self.entries.iter().map(|(node, identity)| (node, identity))
    }

    pub(super) fn get(&self, node: &str) -> Option<&QemuProcessIdentity> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(node))
            .ok()
            .map(|index| &self.entries[index].1)
    }

    pub(super) fn get_mut(&mut self, node: &str) -> Option<&mut QemuProcessIdentity> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(node))
            .ok()
            .map(|index| &mut self.entries[index].1)
    }

    pub(super) fn contains_key(&self, node: &str) -> bool {
        self.get(node).is_some()
    }

    pub(super) fn try_reserve_exact(&mut self, additional: usize) -> Result<(), ()> {
        self.entries.try_reserve_exact(additional).map_err(|_| ())
    }

    pub(super) fn insert_reserved(
        &mut self,
        node: String,
        identity: QemuProcessIdentity,
    ) -> Result<Option<QemuProcessIdentity>, ()> {
        match self
            .entries
            .binary_search_by(|(candidate, _)| candidate.cmp(&node))
        {
            Ok(index) => Ok(Some(std::mem::replace(
                &mut self.entries[index].1,
                identity,
            ))),
            Err(index) => {
                if self.entries.len() == self.entries.capacity() {
                    return Err(());
                }
                self.entries.insert(index, (node, identity));
                Ok(None)
            }
        }
    }

    pub(super) fn remove(&mut self, node: &str) -> Option<QemuProcessIdentity> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(node))
            .ok()
            .map(|index| self.entries.remove(index).1)
    }
}

impl serde::Serialize for ProductionProcessOwners {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (node, identity) in &self.entries {
            map.serialize_entry(node, identity)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for ProductionProcessOwners {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_process_owners(deserializer, None)
    }
}

fn deserialize_process_owners<'de, D>(
    deserializer: D,
    expected: Option<usize>,
) -> Result<ProductionProcessOwners, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ProcessOwnersVisitor {
        expected: Option<usize>,
    }

    impl<'de> Visitor<'de> for ProcessOwnersVisitor {
        type Value = ProductionProcessOwners;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonically ordered process-ownership map")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut owners = ProductionProcessOwners::new();
            if let Some(expected) = self.expected {
                owners.entries.try_reserve_exact(expected).map_err(|_| {
                    record_decode_allocation("nodes", 0, expected);
                    serde::de::Error::custom("process ownership allocation")
                })?;
            }
            loop {
                if self.expected.is_none() {
                    owners.entries.try_reserve(1).map_err(|_| {
                        record_decode_allocation(
                            "nodes",
                            u64::try_from(owners.entries.len()).unwrap_or(u64::MAX),
                            1,
                        );
                        serde::de::Error::custom("process ownership allocation")
                    })?;
                }
                let Some(FallibleOwnedString(node)) = map.next_key()? else {
                    break;
                };
                let FallibleProcessIdentity(identity) = map.next_value()?;
                if owners
                    .insert_reserved(node, identity)
                    .map_err(|()| {
                        serde::de::Error::custom("process ownership count exceeds admitted shape")
                    })?
                    .is_some()
                {
                    return Err(serde::de::Error::custom("duplicate process ownership node"));
                }
            }
            if self
                .expected
                .is_some_and(|expected| owners.entries.len() != expected)
            {
                return Err(serde::de::Error::custom(
                    "process ownership count differs from admitted shape",
                ));
            }
            Ok(owners)
        }
    }

    deserializer.deserialize_map(ProcessOwnersVisitor { expected })
}

pub(super) fn deserialize_current_process_owners<'de, D>(
    deserializer: D,
) -> Result<ProductionProcessOwners, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let expected = current_processes_expected();
    deserialize_process_owners(deserializer, expected)
}

pub(super) fn deserialize_staged_process_owners<'de, D>(
    deserializer: D,
) -> Result<ProductionProcessOwners, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let expected = staged_processes_expected();
    deserialize_process_owners(deserializer, expected)
}

#[cfg(test)]
impl From<std::collections::BTreeMap<String, QemuProcessIdentity>> for ProductionProcessOwners {
    fn from(entries: std::collections::BTreeMap<String, QemuProcessIdentity>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}
