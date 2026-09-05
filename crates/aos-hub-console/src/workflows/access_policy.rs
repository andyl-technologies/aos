//! Shared delivery-access policy editor and validation.
//!
//! Gateways and Hub routes use the same public, external
//! provider, and private-network policy vocabulary. Hub-auth is intentionally
//! omitted here because direct gateways cannot enforce it.

use leptos::prelude::*;

/// Holds reactive fields for one direct-delivery access policy.
#[derive(Clone, Copy)]
pub(super) struct AccessPolicySignals {
    kind: RwSignal<String>,
    provider_kind: RwSignal<String>,
    provider_resource: RwSignal<String>,
    provider_revision: RwSignal<String>,
    mechanisms: RwSignal<String>,
    client_classes: RwSignal<String>,
    hub_principals: RwSignal<String>,
    hub_client_classes: RwSignal<String>,
    boundary_id: RwSignal<String>,
    boundary_revision: RwSignal<String>,
}

impl AccessPolicySignals {
    /// Creates a public access-policy draft.
    pub(super) fn public() -> Self {
        Self {
            kind: RwSignal::new("public".to_string()),
            provider_kind: RwSignal::new(String::new()),
            provider_resource: RwSignal::new(String::new()),
            provider_revision: RwSignal::new(String::new()),
            mechanisms: RwSignal::new(String::new()),
            client_classes: RwSignal::new(String::new()),
            hub_principals: RwSignal::new(String::new()),
            hub_client_classes: RwSignal::new(String::new()),
            boundary_id: RwSignal::new(String::new()),
            boundary_revision: RwSignal::new(String::new()),
        }
    }

    /// Creates a draft populated from an existing policy.
    pub(super) fn from_policy(policy: Option<aos_proto_types::DeliveryAccessPolicy>) -> Self {
        use aos_proto_types::delivery_access_policy::Policy;

        let signals = Self::public();
        match policy.and_then(|value| value.policy) {
            Some(Policy::ExternalProvider(value)) => {
                signals.kind.set("external-provider".to_string());
                signals.provider_kind.set(value.provider_kind);
                signals.provider_resource.set(value.resource_id);
                signals.provider_revision.set(value.revision);
                signals.mechanisms.set(
                    value
                        .client_mechanisms
                        .into_iter()
                        .map(|mechanism| {
                            format!("{}={}", mechanism.kind, mechanism.verification_secret_ref)
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
                signals.client_classes.set(value.client_classes.join("\n"));
            }
            Some(Policy::PrivateNetwork(value)) => {
                signals.kind.set("private-network".to_string());
                signals.boundary_id.set(value.boundary_id);
                signals
                    .boundary_revision
                    .set(value.boundary_revision.to_string());
            }
            Some(Policy::HubAuth(value)) => {
                signals.kind.set("hub-auth".to_string());
                signals.hub_principals.set(value.principals.join("\n"));
                signals
                    .hub_client_classes
                    .set(value.client_classes.join("\n"));
            }
            Some(Policy::Public(_)) | None => {}
        }
        signals
    }

    /// Returns a reactive key for invalidating a reviewed plan after edits.
    pub(super) fn draft_key(self) -> String {
        [
            self.kind.get(),
            self.provider_kind.get(),
            self.provider_resource.get(),
            self.provider_revision.get(),
            self.mechanisms.get(),
            self.client_classes.get(),
            self.hub_principals.get(),
            self.hub_client_classes.get(),
            self.boundary_id.get(),
            self.boundary_revision.get(),
        ]
        .join("\u{1f}")
    }

    /// Validates and builds the protocol policy represented by this draft.
    ///
    /// # Errors
    ///
    /// Returns an error when required policy fields are missing, a boundary
    /// revision is invalid, or an external client mechanism is unsupported.
    pub(super) fn build(self) -> Result<aos_proto_types::DeliveryAccessPolicy, String> {
        self.build_with_hub_auth(false)
    }

    /// Validates a route policy, including optional Hub-auth enforcement.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::build`].
    pub(super) fn build_for_route(self) -> Result<aos_proto_types::DeliveryAccessPolicy, String> {
        self.build_with_hub_auth(true)
    }

    fn build_with_hub_auth(
        self,
        allow_hub_auth: bool,
    ) -> Result<aos_proto_types::DeliveryAccessPolicy, String> {
        use aos_proto_types::delivery_access_policy::Policy;

        let policy = match self.kind.get_untracked().as_str() {
            "public" => Policy::Public(true),
            "hub-auth" if allow_hub_auth => Policy::HubAuth(aos_proto_types::HubAuthPolicy {
                principals: lines(&self.hub_principals.get_untracked()),
                client_classes: lines(&self.hub_client_classes.get_untracked()),
                allow_anonymous_metadata: false,
            }),
            "external-provider" => {
                let provider_kind = required(self.provider_kind.get_untracked(), "Provider kind")?;
                let resource_id = required(
                    self.provider_resource.get_untracked(),
                    "Provider resource ID",
                )?;
                let revision =
                    required(self.provider_revision.get_untracked(), "Provider revision")?;
                let client_mechanisms = parse_mechanisms(&self.mechanisms.get_untracked())?;
                if client_mechanisms.is_empty() {
                    return Err(
                        "External-provider access requires at least one client mechanism"
                            .to_string(),
                    );
                }
                Policy::ExternalProvider(aos_proto_types::ExternalProviderPolicy {
                    provider_kind,
                    resource_id,
                    revision,
                    client_mechanisms,
                    client_classes: lines(&self.client_classes.get_untracked()),
                })
            }
            "private-network" => {
                let boundary_id = required(self.boundary_id.get_untracked(), "Boundary ID")?;
                let boundary_revision = self
                    .boundary_revision
                    .get_untracked()
                    .parse::<i64>()
                    .map_err(|_| "Boundary revision must be a positive integer".to_string())?;
                if boundary_revision <= 0 {
                    return Err("Boundary revision must be a positive integer".to_string());
                }
                Policy::PrivateNetwork(aos_proto_types::PrivateNetworkPolicy {
                    boundary_id,
                    boundary_revision,
                })
            }
            _ => return Err("Unsupported direct-delivery access policy".to_string()),
        };
        Ok(aos_proto_types::DeliveryAccessPolicy {
            policy: Some(policy),
        })
    }
}

/// Renders fields for one direct-delivery access policy.
#[component]
pub(super) fn AccessPolicyFields(
    signals: AccessPolicySignals,
    #[prop(default = false)] allow_hub_auth: bool,
    #[prop(default = Vec::new())] boundaries: Vec<aos_proto_types::NetworkPolicy>,
) -> impl IntoView {
    let selected_boundaries = boundaries.clone();
    let on_boundary_change = Callback::new(move |value: String| {
        signals.boundary_id.set(value.clone());
        let revision = selected_boundaries
            .iter()
            .find(|boundary| boundary.stable_id == value)
            .map(|boundary| boundary.default_revision)
            .unwrap_or_default();
        signals.boundary_revision.set(revision.to_string());
    });
    view! {
        <label>
            <span>"Access policy"</span>
            <select prop:value=move || signals.kind.get() on:change=move |event| signals.kind.set(event_target_value(&event))>
                <option value="public">"Public"</option>
                {allow_hub_auth.then(|| view! { <option value="hub-auth">"AOS Hub authentication"</option> })}
                <option value="external-provider">"External authorization provider"</option>
                <option value="private-network">"Private network"</option>
            </select>
        </label>
        {move || match signals.kind.get().as_str() {
            "hub-auth" if allow_hub_auth => view! {
                <label class="full-field"><span>"Allowed principals (one per line; empty uses role grants)"</span><textarea prop:value=move || signals.hub_principals.get() on:input=move |event| signals.hub_principals.set(event_target_value(&event))></textarea></label>
                <label class="full-field"><span>"Allowed client classes (one per line)"</span><textarea prop:value=move || signals.hub_client_classes.get() on:input=move |event| signals.hub_client_classes.set(event_target_value(&event))></textarea></label>
            }.into_any(),
            "external-provider" => view! {
                <label><span>"Provider kind"</span><input required prop:value=move || signals.provider_kind.get() on:input=move |event| signals.provider_kind.set(event_target_value(&event))/></label>
                <label><span>"Provider resource ID"</span><input required prop:value=move || signals.provider_resource.get() on:input=move |event| signals.provider_resource.set(event_target_value(&event))/></label>
                <label><span>"Provider revision"</span><input required prop:value=move || signals.provider_revision.get() on:input=move |event| signals.provider_revision.set(event_target_value(&event))/></label>
                <label class="full-field"><span>"Client mechanisms (one kind=secret-ref per line)"</span><textarea required prop:value=move || signals.mechanisms.get() on:input=move |event| signals.mechanisms.set(event_target_value(&event))></textarea></label>
                <label class="full-field"><span>"Client classes (one per line)"</span><textarea prop:value=move || signals.client_classes.get() on:input=move |event| signals.client_classes.set(event_target_value(&event))></textarea></label>
            }.into_any(),
            "private-network" => { let on_boundary_change = on_boundary_change.clone(); view! {
                <label><span>"Network policy"</span><select required prop:value=move || signals.boundary_id.get() on:change=move |event| on_boundary_change.run(event_target_value(&event))>{boundaries.iter().map(|boundary| view! { <option value=boundary.stable_id.clone()>{format!("{} · {}", boundary.name, boundary.kind)}</option> }).collect_view()}{(!signals.boundary_id.get_untracked().is_empty() && !boundaries.iter().any(|boundary| boundary.stable_id == signals.boundary_id.get_untracked())).then(|| view! { <option value=signals.boundary_id.get_untracked()>{"Currently pinned boundary"}</option> })}</select>{boundaries.is_empty().then(|| view! { <small>"No selectable network policies are available in this scope."</small> })}</label>
                <label><span>"Boundary revision"</span><select required prop:value=move || signals.boundary_revision.get()><option value=signals.boundary_revision.get_untracked()>{format!("Pinned revision {}", signals.boundary_revision.get_untracked())}</option>{boundaries.iter().filter(|boundary| boundary.stable_id == signals.boundary_id.get_untracked()).map(|boundary| view! { <option value=boundary.default_revision.to_string()>{format!("Current revision {}", boundary.default_revision)}</option> }).collect_view()}</select></label>
            }.into_any() },
            _ => ().into_any(),
        }}
    }
}

/// Returns a concise display name for a delivery-access policy.
pub(super) fn access_policy_name(
    policy: Option<&aos_proto_types::DeliveryAccessPolicy>,
) -> &'static str {
    use aos_proto_types::delivery_access_policy::Policy;

    match policy.and_then(|value| value.policy.as_ref()) {
        Some(Policy::Public(_)) => "public",
        Some(Policy::ExternalProvider(_)) => "external provider",
        Some(Policy::PrivateNetwork(_)) => "private network",
        Some(Policy::HubAuth(_)) => "Hub auth",
        None => "unspecified",
    }
}

/// Validates and normalizes an absolute URL path.
///
/// # Errors
///
/// Returns an error when the value is not absolute or contains a repeated or
/// parent path segment.
pub(super) fn canonical_path(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if !value.starts_with('/') || value.contains("//") || value.contains("..") {
        return Err(format!(
            "{field} must be an absolute canonical path without // or .."
        ));
    }
    Ok(value.to_string())
}

/// Trims one required string field.
///
/// # Errors
///
/// Returns an error when the trimmed value is empty.
pub(super) fn required(value: String, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(value.to_string())
    }
}

fn parse_mechanisms(value: &str) -> Result<Vec<aos_proto_types::ExternalClientMechanism>, String> {
    lines(value)
        .into_iter()
        .map(|line| {
            let (kind, secret) = line
                .split_once('=')
                .ok_or_else(|| "Client mechanisms use kind=secret-ref".to_string())?;
            if !matches!(
                kind,
                "bearer-token" | "signed-cookie" | "signed-header" | "mtls"
            ) || secret.trim().is_empty()
            {
                return Err(format!(
                    "Unsupported or incomplete client mechanism '{line}'"
                ));
            }
            Ok(aos_proto_types::ExternalClientMechanism {
                kind: kind.to_string(),
                verification_secret_ref: secret.trim().to_string(),
            })
        })
        .collect()
}

fn lines(value: &str) -> Vec<String> {
    let mut values = value
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}
