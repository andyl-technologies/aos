//! The authenticated producer console: human management pages.
//!
//! RFC-0004 Phase 5 (console-dedup stage A) lifts every console page builder
//! into the shared, wasm-clean [`aos_hub_core::web::console_render`] so the
//! native hub and the eventual Cloudflare Worker render the producer console
//! from one code path. This module re-exports those builders unchanged, so the
//! hub's handlers ([`crate::console`]) keep calling `crate::ui::console::…`
//! exactly as before.
//!
//! The page set: the auth pages (login, "check your email", the two-step SSO
//! page, the account profile, passkey management, and the RFC 8628 device
//! approval at `/activate`), the org/project pages (org list, per-org
//! dashboard, audit feed), and the registry-management pages (token management,
//! the channel rollout console, the key roster and rotation wizard, the org
//! hosted-key enrollment, webhooks, SSO, instance settings, serving/mirror,
//! publishes, config edit, and change requests).
//!
//! Every page is the no-JS floor — plain `GET`/`POST` forms and redirects, no
//! client-side framework. Each `POST` form embeds a hidden per-session CSRF
//! synchronizer token ([`crate::auth::extract::mint_csrf_token`]) that the
//! handler verifies on submit; the [`csrf_field`](aos_hub_core::web::console_render::csrf_field)
//! helper renders that hidden input.

// The console page builders + their supporting types now live in the shared
// core crate; re-export them so every `crate::ui::console::…` call site is
// unchanged.
pub use aos_hub_core::web::console_render::{
    account_page, activate_page, audit_page, changes_page, changeset_rows, channel_console,
    config_edit_page, grants_allow, instance_settings_page, keys_page, keys_rotate_page,
    login_page, login_sent_page, login_sso_page, new_org_page, new_registry_page, org_dashboard,
    org_hosted_keys_page, org_sso_page, org_webhooks_page, orgs_page, passkeys_page, publishes_page,
    registry_settings_page, serving_page, tokens_page, ChangeRequestView, MemberRow,
    WEBHOOK_EVENT_TYPES,
};
