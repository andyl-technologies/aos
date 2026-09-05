//! Handles hub auth commands and their domain-specific request validation.

use crate::commands::hub::output::print_hub_json;
use anyhow::Result;
use aos_core::output::Printer;

/// Handles `aos hub login` through device authorization or explicit bootstrap.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn login(
    printer: &Printer,
    hub: &str,
    provisioning_token: Option<&str>,
    scope: Option<&str>,
) -> Result<()> {
    if let Some(provisioning_token) = provisioning_token {
        let grant = aos_remote::exchange_token(hub, provisioning_token).await?;
        if print_hub_json(
            printer,
            "login",
            serde_json::json!({
                "access_token": grant.access_token,
                "token_type": grant.token_type,
                "expires_in": grant.expires_in,
                "stored": false,
            }),
        ) {
            return Ok(());
        }
        printer.info(&format!(
            "access token issued ({}, expires in {}s):",
            grant.token_type, grant.expires_in
        ));
        println!("{}", grant.access_token);
        return Ok(());
    }

    let authorization = aos_remote::start_device_authorization(hub, scope, &[]).await?;
    printer.info("Approve this AOS CLI in your browser:");
    printer.plain(&format!("  {}", authorization.verification_uri_complete));
    printer.plain(&format!("  code: {}", authorization.user_code));
    let started = std::time::Instant::now();
    let mut interval = authorization.interval.max(1) as u64;
    let grant = loop {
        if started.elapsed().as_secs() >= authorization.expires_in.max(1) as u64 {
            anyhow::bail!("device authorization expired");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        match aos_remote::poll_device_token(hub, &authorization.device_code).await? {
            aos_remote::DeviceTokenPoll::Pending => {}
            aos_remote::DeviceTokenPoll::SlowDown => interval = interval.saturating_add(5),
            aos_remote::DeviceTokenPoll::Granted(grant) => break grant,
        }
    };
    let access_expires_at = crate::commands::hub_auth::install_device_grant(hub, grant)?;
    if print_hub_json(
        printer,
        "login",
        serde_json::json!({
            "hub": hub,
            "stored": true,
            "access_expires_at": access_expires_at,
        }),
    ) {
        return Ok(());
    }
    printer.success(&format!("signed in to {hub}"));
    Ok(())
}
