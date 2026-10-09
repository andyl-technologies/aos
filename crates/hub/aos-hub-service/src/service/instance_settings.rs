//! Field-level effects for immutable instance-settings plans.

use super::RpcError;
use crate::db::InstanceSettings;

/// Shows normalized changes only, including the effective value after a reset.
///
/// # Errors
///
/// Returns an invalid-argument error for an unrecognized setting key.
pub(super) fn effects(
    current: &InstanceSettings,
    writes: &[(String, Option<String>)],
) -> Result<Vec<String>, RpcError> {
    let mut effects = Vec::new();
    for (key, value) in writes {
        let (label, before, default) = match key.as_str() {
            "site_title" => (
                "Site title",
                current.site_title.clone().unwrap_or_default(),
                "",
            ),
            "tagline" => ("Tagline", current.tagline.clone().unwrap_or_default(), ""),
            "announcement" => (
                "Announcement",
                current.announcement.clone().unwrap_or_default(),
                "",
            ),
            "tos_url" => ("Terms URL", current.tos_url.clone().unwrap_or_default(), ""),
            "privacy_url" => (
                "Privacy URL",
                current.privacy_url.clone().unwrap_or_default(),
                "",
            ),
            "support_url" => (
                "Support URL",
                current.support_url.clone().unwrap_or_default(),
                "",
            ),
            "signup_policy" => (
                "Signup policy",
                current.signup_policy.as_str().to_string(),
                "invite_only",
            ),
            "signup_domains" => (
                "Allowed signup domains",
                current.signup_domains.join(","),
                "",
            ),
            "password_login" => (
                "Password login",
                on_off(current.password_login).to_string(),
                "on",
            ),
            "caches_public" => (
                "Public cache discovery",
                on_off(current.caches_public).to_string(),
                "off",
            ),
            "session_lifetime_secs" => (
                "Session lifetime (seconds)",
                current.session_lifetime_secs.unwrap_or(0).to_string(),
                "0",
            ),
            "default_crawl_policy" => (
                "Default crawl policy",
                current.default_crawl_policy.clone(),
                "allow_all",
            ),
            "max_upload_bytes" => (
                "Maximum upload size (bytes)",
                current.max_upload_bytes.unwrap_or(0).to_string(),
                "0",
            ),
            _ => {
                return Err(RpcError::invalid(format!(
                    "unknown instance setting: {key}"
                )))
            }
        };
        let after = value.as_deref().unwrap_or(default);
        if before == after {
            continue;
        }

        let display = |value: &str| {
            if value.is_empty() {
                if key == "site_title" {
                    "AOS Hub (default)".to_string()
                } else {
                    "(not set)".to_string()
                }
            } else {
                format!("{value:?}")
            }
        };
        let reset = if value.is_none() { " (reset)" } else { "" };
        effects.push(format!(
            "{label}: {} → {}{reset}",
            display(&before),
            display(after)
        ));
    }
    if effects.is_empty() {
        effects.push("No instance settings changes".to_string());
    }
    Ok(effects)
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn effects_show_changes_and_resets_without_unchanged_fields() {
        let db = Database::open_in_memory().await.unwrap();
        db.instance_config_set("site_title", "Old Hub")
            .await
            .unwrap();
        db.instance_config_set("announcement", "Maintenance")
            .await
            .unwrap();
        let current = db.instance_settings().await.unwrap();
        let writes = vec![
            ("announcement".into(), None),
            ("password_login".into(), Some("on".into())),
            ("site_title".into(), Some("New Hub".into())),
            (
                "support_url".into(),
                Some("https://example.com/support".into()),
            ),
        ];

        let result = effects(&current, &writes).unwrap();

        assert_eq!(
            result,
            vec![
                "Announcement: \"Maintenance\" → (not set) (reset)",
                "Site title: \"Old Hub\" → \"New Hub\"",
                "Support URL: (not set) → \"https://example.com/support\"",
            ]
        );
        assert_eq!(
            effects(&current, &[("site_title".into(), None)]).unwrap(),
            vec!["Site title: \"Old Hub\" → AOS Hub (default) (reset)"]
        );
        assert_eq!(
            effects(&current, &[("password_login".into(), Some("on".into()))]).unwrap(),
            vec!["No instance settings changes"]
        );
    }
}
