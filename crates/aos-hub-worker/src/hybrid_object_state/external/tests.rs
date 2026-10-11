//! Fault-injected journal contracts; these fixtures do not qualify a provider.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use super::*;

#[derive(Clone, Default)]
struct DurableState {
    scope: Option<ExternalObjectScope>,
    pending: Option<ExternalMutation>,
    receipts: BTreeMap<String, ExternalReceipt>,
}

#[derive(Clone, Default)]
struct Journal {
    durable: Rc<RefCell<DurableState>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_pending: bool,
    fail_receipt: bool,
    fail_clear: bool,
}

impl ExternalJournal for Journal {
    async fn scope(&mut self) -> Result<Option<ExternalObjectScope>> {
        Ok(self.durable.borrow().scope.clone())
    }

    async fn pin_scope(&mut self, scope: &ExternalObjectScope) -> Result<()> {
        self.durable.borrow_mut().scope = Some(scope.clone());
        Ok(())
    }

    async fn pending(&mut self) -> Result<Option<ExternalMutation>> {
        Ok(self.durable.borrow().pending.clone())
    }

    async fn receipt(&mut self, operation_id: &str) -> Result<Option<ExternalReceipt>> {
        Ok(self.durable.borrow().receipts.get(operation_id).cloned())
    }

    async fn write_pending(&mut self, mutation: &ExternalMutation) -> Result<()> {
        if self.fail_pending {
            bail!("pending storage unavailable");
        }
        ensure!(
            self.durable.borrow().pending.is_none(),
            "pending already exists"
        );
        self.durable.borrow_mut().pending = Some(mutation.clone());
        self.events.borrow_mut().push("durable pending");
        Ok(())
    }

    async fn write_receipt(&mut self, receipt: &ExternalReceipt) -> Result<()> {
        if self.fail_receipt {
            bail!("receipt storage unavailable");
        }
        self.durable
            .borrow_mut()
            .receipts
            .insert(receipt.mutation.operation_id.clone(), receipt.clone());
        self.events.borrow_mut().push("durable receipt");
        Ok(())
    }

    async fn clear_pending(&mut self, mutation: &ExternalMutation) -> Result<()> {
        if self.fail_clear {
            bail!("pending clear unavailable");
        }
        ensure!(
            self.durable.borrow().pending.as_ref() == Some(mutation),
            "pending changed"
        );
        self.durable.borrow_mut().pending = None;
        self.events.borrow_mut().push("clear pending");
        Ok(())
    }
}

fn address(origin: &str) -> ExternalCoordinates {
    ExternalCoordinates {
        origin: origin.into(),
        bucket: "approved-bucket".into(),
    }
}

fn approvals() -> ExternalAuthorityMap {
    ExternalAuthorityMap::from_verified_entries(vec![ApprovedExternalNamespace {
        authority_id: "00000000-0000-4000-8000-000000000001".into(),
        aliases: vec![
            address("https://store.example.test/"),
            address("https://approved-alias.example.test/"),
        ],
    }])
    .unwrap()
}

fn scope() -> ExternalObjectScope {
    approvals()
        .scope(
            &address("https://store.example.test/"),
            "binding",
            "placement",
            "metadata/info",
        )
        .unwrap()
}

#[test]
fn shared_scope_requires_the_actual_configured_namespace() {
    let shared = aos_hub_core::storage_authority::control::StorageAuthorityObjectScope {
        guard_namespace_id: "actual-object-namespace".into(),
        physical_authority_id: aos_hub_core::storage_authority::PhysicalStorageAuthorityId::parse(
            "00000000-0000-4000-8000-000000000001",
        )
        .unwrap(),
        full_key: "binding/placement/object".into(),
    };
    assert!(ExternalObjectScope::from_verified_scope(shared.clone(), "another-namespace").is_err());
    let scope = ExternalObjectScope::from_verified_scope(shared.clone(), "actual-object-namespace")
        .unwrap();
    assert_eq!(scope.guard_name().unwrap(), shared.guard_name().unwrap());
    assert_eq!(scope.namespace(), "actual-object-namespace");
}

fn put(id: &str) -> ExternalMutation {
    ExternalMutation::new(
        scope(),
        id,
        ExternalEffect::Put {
            sha256: "a".repeat(64),
            size: 42,
        },
    )
    .unwrap()
}

fn completion(id: &str) -> ExternalMutation {
    ExternalMutation::new(
        scope(),
        id,
        ExternalEffect::CompleteMultipart {
            upload_id: "exact-provider-upload".into(),
            parts_sha256: "b".repeat(64),
        },
    )
    .unwrap()
}

#[test]
fn approved_aliases_converge_across_logical_prefix_partitions() {
    let map = approvals();
    let original = map
        .scope(
            &address("https://store.example.test/"),
            "binding",
            "placement",
            "metadata/info",
        )
        .unwrap();
    let alias = map
        .scope(
            &address("https://approved-alias.example.test/"),
            "",
            "binding/placement",
            "metadata/info",
        )
        .unwrap();

    assert_eq!(original, alias);
    assert_eq!(original.guard_name().unwrap(), alias.guard_name().unwrap());
    let different_key = map
        .scope(
            &address("https://store.example.test/"),
            "binding",
            "other",
            "metadata/info",
        )
        .unwrap();
    assert_ne!(
        original.guard_name().unwrap(),
        different_key.guard_name().unwrap()
    );
}

#[test]
fn unapproved_aliases_and_conflicting_authorities_fail_closed() {
    assert!(approvals()
        .scope(&address("https://similar.example.test/"), "", "", "key")
        .is_err());
    let mut unapproved_bucket = address("https://store.example.test/");
    unapproved_bucket.bucket = "another-bucket".into();
    assert!(approvals()
        .scope(&unapproved_bucket, "", "", "key")
        .is_err());
    assert!(ExternalAuthorityMap::from_verified_entries(vec![
        ApprovedExternalNamespace {
            authority_id: "one".into(),
            aliases: vec![address("https://store.example.test/")]
        },
        ApprovedExternalNamespace {
            authority_id: "two".into(),
            aliases: vec![address("https://store.example.test/")]
        },
    ])
    .is_err());

    for origin in [
        "http://store.example.test/",
        "https://STORE.example.test/",
        "https://secret@store.example.test/",
        "https://store.example.test/path",
        "https://store.example.test/?secret=value",
    ] {
        assert!(
            ExternalAuthorityMap::from_verified_entries(vec![ApprovedExternalNamespace {
                authority_id: "one".into(),
                aliases: vec![address(origin)],
            }])
            .is_err(),
            "unexpected origin admission: {origin}"
        );
    }
    for path in ["../key", "/key", "a//key", "a/./key"] {
        assert!(approvals()
            .scope(&address("https://store.example.test/"), "", "", path)
            .is_err());
    }
}

#[tokio::test]
async fn pending_precedes_provider_and_receipt_precedes_unlock() {
    let mut journal = Journal::default();
    let events = Rc::clone(&journal.events);
    let mutation = put("stable-put");

    let result = mutate(&mut journal, &mutation, || async {
        events.borrow_mut().push("provider effect");
        Ok(ExternalOutcome::PutAcknowledged)
    })
    .await
    .unwrap();

    assert_eq!(result, ExternalOutcome::PutAcknowledged);
    assert_eq!(
        *events.borrow(),
        [
            "durable pending",
            "provider effect",
            "durable receipt",
            "clear pending"
        ]
    );
    assert!(journal.durable.borrow().pending.is_none());
    let replay = mutate(&mut journal, &mutation, || async {
        panic!("receipt replay dispatched provider")
    })
    .await
    .unwrap();
    assert_eq!(result, replay);
}

#[tokio::test]
async fn pending_persistence_failure_prevents_dispatch() {
    let mut journal = Journal {
        fail_pending: true,
        ..Journal::default()
    };
    let called = Cell::new(false);
    assert!(mutate(&mut journal, &put("stable-put"), || async {
        called.set(true);
        Ok(ExternalOutcome::PutAcknowledged)
    })
    .await
    .is_err());
    assert!(!called.get());
    assert!(journal.durable.borrow().receipts.is_empty());
}

#[tokio::test]
async fn lost_response_blocks_retry_head_and_other_visible_effects_after_restart() {
    let mut journal = Journal::default();
    let original = completion("complete:upload-one");
    assert!(mutate(&mut journal, &original, || async {
        bail!("provider response lost after dispatch")
    })
    .await
    .is_err());

    let mut restarted = journal.clone();
    assert!(mutate(&mut restarted, &original, || async {
        panic!("unknown completion redispatched")
    })
    .await
    .is_err());
    assert!(mutate(&mut restarted, &put("replacement-put"), || async {
        panic!("replacement bypassed fence")
    })
    .await
    .is_err());
    assert!(observe(&mut restarted, &scope(), || async {
        panic!("HEAD absence bypassed fence");
        #[allow(unreachable_code)]
        Ok(())
    })
    .await
    .is_err());
    let deletion = ExternalMutation::new(
        scope(),
        "reviewed-action",
        ExternalEffect::ConditionalDelete {
            action_fingerprint: "c".repeat(64),
            etag: "\"reviewed-etag\"".into(),
        },
    )
    .unwrap();
    assert!(mutate(&mut restarted, &deletion, || async {
        panic!("delete bypassed pending completion")
    })
    .await
    .is_err());
    assert_eq!(restarted.durable.borrow().pending.as_ref(), Some(&original));
}

#[tokio::test]
async fn provider_success_without_receipt_keeps_fence() {
    let mut journal = Journal {
        fail_receipt: true,
        ..Journal::default()
    };
    let original = put("stable-put");
    assert!(mutate(&mut journal, &original, || async {
        Ok(ExternalOutcome::PutAcknowledged)
    })
    .await
    .is_err());
    journal.fail_receipt = false;

    assert!(mutate(&mut journal, &original, || async {
        panic!("acknowledgement was not durably recorded")
    })
    .await
    .is_err());
    assert!(
        observe(&mut journal, &scope(), || async { Ok(None::<u64>) })
            .await
            .is_err()
    );
    assert_eq!(journal.durable.borrow().pending.as_ref(), Some(&original));
}

#[tokio::test]
async fn durable_receipt_recovers_failure_to_clear_matching_fence() {
    let mut journal = Journal {
        fail_clear: true,
        ..Journal::default()
    };
    let original = completion("complete:upload-one");
    assert!(mutate(&mut journal, &original, || async {
        Ok(ExternalOutcome::MultipartCompleted {
            etag: "\"provider-etag\"".into(),
        })
    })
    .await
    .is_err());
    journal.fail_clear = false;

    let result = mutate(&mut journal, &original, || async {
        panic!("settled completion redispatched")
    })
    .await
    .unwrap();
    assert_eq!(
        result,
        ExternalOutcome::MultipartCompleted {
            etag: "\"provider-etag\"".into()
        }
    );
    assert!(journal.durable.borrow().pending.is_none());
}

#[tokio::test]
async fn changed_payload_and_scope_never_replay_or_dispatch() {
    let mut journal = Journal::default();
    let original = put("stable-put");
    mutate(&mut journal, &original, || async {
        Ok(ExternalOutcome::PutAcknowledged)
    })
    .await
    .unwrap();
    let changed = ExternalMutation::new(
        scope(),
        "stable-put",
        ExternalEffect::Put {
            sha256: "d".repeat(64),
            size: 42,
        },
    )
    .unwrap();

    assert!(mutate(&mut journal, &changed, || async {
        panic!("changed payload dispatched")
    })
    .await
    .is_err());
    let different_scope = approvals()
        .scope(
            &address("https://store.example.test/"),
            "binding",
            "placement",
            "other",
        )
        .unwrap();
    assert!(observe(&mut journal, &different_scope, || async {
        panic!("different key observed");
        #[allow(unreachable_code)]
        Ok(())
    })
    .await
    .is_err());
}

#[tokio::test]
async fn incompatible_provider_outcome_never_unlocks() {
    let mut journal = Journal::default();
    assert!(mutate(&mut journal, &put("stable-put"), || async {
        Ok(ExternalOutcome::NotFound)
    })
    .await
    .is_err());
    assert!(journal.durable.borrow().pending.is_some());
    assert!(journal.durable.borrow().receipts.is_empty());
}

#[tokio::test]
async fn conclusive_provider_rejection_is_retained_and_replayed_without_effects() {
    let mut journal = Journal::default();
    let mutation = put("denied-put");
    let denied = ExternalOutcome::Rejected {
        class: ExternalRejection::AuthorizationDenied,
    };

    assert_eq!(
        mutate(&mut journal, &mutation, || async { Ok(denied.clone()) })
            .await
            .unwrap(),
        denied
    );
    assert!(journal.durable.borrow().pending.is_none());
    assert_eq!(
        mutate(&mut journal, &mutation, || async {
            panic!("denied operation repeated")
        })
        .await
        .unwrap(),
        denied
    );
}

#[tokio::test]
async fn conditional_delete_is_disabled_but_terminal_replay_needs_no_new_dispatch() {
    let mut journal = Journal::default();
    let deletion = ExternalMutation::new(
        scope(),
        "reviewed-action",
        ExternalEffect::ConditionalDelete {
            action_fingerprint: "c".repeat(64),
            etag: "\"reviewed-etag\"".into(),
        },
    )
    .unwrap();
    assert!(mutate(&mut journal, &deletion, || async {
        panic!("unqualified DELETE dispatched")
    })
    .await
    .is_err());
    assert!(journal.durable.borrow().pending.is_none());

    // Imported terminal evidence is a fixture for future migration/replay;
    // this module cannot create it through destructive provider execution.
    journal.durable.borrow_mut().receipts.insert(
        deletion.operation_id.clone(),
        ExternalReceipt {
            mutation: deletion.clone(),
            outcome: ExternalOutcome::NotFound,
        },
    );
    assert_eq!(
        mutate(&mut journal, &deletion, || async {
            panic!("terminal DELETE repeated")
        })
        .await
        .unwrap(),
        ExternalOutcome::NotFound
    );
    let changed = ExternalMutation::new(
        scope(),
        "reviewed-action",
        ExternalEffect::ConditionalDelete {
            action_fingerprint: "e".repeat(64),
            etag: "\"reviewed-etag\"".into(),
        },
    )
    .unwrap();
    assert!(mutate(&mut journal, &changed, || async {
        panic!("changed action dispatched")
    })
    .await
    .is_err());
}

#[test]
fn durable_metadata_contains_no_credentials_provider_urls_or_request_bodies() {
    let mutation = put("stable-put");
    let encoded = serde_json::to_value(ExternalReceipt {
        mutation,
        outcome: ExternalOutcome::PutAcknowledged,
    })
    .unwrap();
    let fields = encoded["mutation"].as_object().unwrap();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["effect", "fingerprint", "operation_id", "scope"]
    );
    let scope_fields = fields["scope"].as_object().unwrap();
    assert_eq!(
        scope_fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["full_key", "guard_namespace_id", "physical_authority_id"]
    );
    assert_eq!(
        fields["effect"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["kind", "sha256", "size"]
    );
}
