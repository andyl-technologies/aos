# tests/vm/hub-native-operations.nix -- Native aos-hub operator lifecycle.
#
# This check starts from an empty state directory and exercises the recovery
# and maintenance commands an operator uses around the long-running native Hub.
# It never enables development mode or demo seeding.
{
  testing,
  pkgs,
}: let
  jwtSecret = pkgs.writeTextFile {
    name = "hub-native-operations-jwt-secret";
    destination = "/value";
    text = "native-hub-vm-stable-jwt-secret-v1";
  };
  probeSigners = pkgs.writeTextFile {
    name = "hub-native-operations-probe-signers";
    destination = "/value";
    text = "[]";
  };
  routeKeys = pkgs.writeTextFile {
    name = "hub-native-operations-route-keys";
    destination = "/value";
    text = ''{"activeVersion":1,"keys":[{"version":1,"keyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}'';
  };
  webhookSecret = pkgs.writeTextFile {
    name = "hub-native-operations-webhook-secret";
    destination = "/value";
    text = "native-hub-webhook-secret-v1";
  };
in
  testing.mkVMTest {
    name = "hub-native-operations";
    memory = 2048;
    rootfsDeps = [
      pkgs.aos
      pkgs.aos-hub
      pkgs.coreutils
      pkgs.curl
      pkgs.grep
      pkgs.iproute2
      pkgs.jq
      pkgs.sed
      jwtSecret
      probeSigners
      routeKeys
      webhookSecret
    ];
    testScript = ''
      set -eu

      hub_root=/tmp/aos-hub
      hub_url=http://127.0.0.1:18420
      credential_dir=/run/aos-hub-credentials
      jwt_secret=$credential_dir/jwt-secret
      probe_signers=$credential_dir/probe-signers.json
      route_keys=$credential_dir/route-keys.json
      secret_version_manifest=$credential_dir/secret-versions.json
      webhook_secret=$credential_dir/webhook-secret-v1
      hub_exec="${pkgs.coreutils}/bin/chroot --userspec=65534:65534 / ${pkgs.aos-hub}/bin/aos-hub"
      hub_pid=

      cleanup() {
        if test -n "$hub_pid"; then
          kill "$hub_pid" 2>/dev/null || true
          wait "$hub_pid" 2>/dev/null || true
        fi
      }
      trap cleanup EXIT

      # Materialize host-store fixtures the way a native service manager
      # presents credentials: private regular files owned by the service uid.
      mkdir -m 0700 "$credential_dir"
      cp ${jwtSecret}/value "$jwt_secret"
      cp ${probeSigners}/value "$probe_signers"
      cp ${routeKeys}/value "$route_keys"
      cp ${webhookSecret}/value "$webhook_secret"
      printf '%s\n' \
        "{\"native://operations/webhook/v1\":\"$webhook_secret\"}" \
        >"$secret_version_manifest"
      chmod 0600 "$jwt_secret" "$probe_signers" "$route_keys" \
        "$webhook_secret" "$secret_version_manifest"
      chown -R 65534:65534 "$credential_dir"
      webhook_fingerprint=$(${pkgs.coreutils}/bin/sha256sum "$webhook_secret" \
        | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)

      echo '==> Schema is inspectable before instance creation'
      $hub_exec schema dump > /tmp/schema.json
      ${pkgs.jq}/bin/jq -e 'type == "array" and length > 0' /tmp/schema.json >/dev/null

      echo '==> Initialize a fresh native instance without seed data'
      test ! -e "$hub_root/hub.db"
      printf '%s\n' 'initial-password' | \
        $hub_exec --root "$hub_root" init \
          --root-email operator@example.test --root-password-stdin
      test -s "$hub_root/hub.db"
      test ! -e "$hub_root/seeded"

      echo '==> Exercise offline indexing on the empty production database'
      $hub_exec --root "$hub_root" index

      echo '==> Recover the root credential through the native operator command'
      printf '%s\n' 'recovered-password' | \
        $hub_exec --root "$hub_root" reset-root \
          --email operator@example.test --password-stdin

      echo '==> Start the native server with required production secret files'
      ${pkgs.iproute2}/sbin/ip link set lo up
      HUB_JWT_SECRET_FILE="$jwt_secret" \
      HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE="$probe_signers" \
      HUB_ROUTE_RESERVATION_KEYS_FILE="$route_keys" \
      HUB_SECRET_VERSION_MANIFEST_FILE="$secret_version_manifest" \
      HUB_DNS_JSON_ENDPOINT=https://8.8.8.8/resolve \
        $hub_exec --root "$hub_root" serve \
          --listen 127.0.0.1:18420 \
          --external-url "$hub_url" \
          --reindex-interval 0 \
          >/tmp/aos-hub.log 2>&1 &
      hub_pid=$!

      hub_ready=
      for attempt in $(${pkgs.coreutils}/bin/seq 1 600); do
        if ${pkgs.curl}/bin/curl -fsS "$hub_url/healthz" >/dev/null 2>&1; then
          hub_ready=yes
          break
        fi
        if ! kill -0 "$hub_pid" 2>/dev/null; then
          ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
          exit 1
        fi
        ${pkgs.coreutils}/bin/sleep 0.1
      done
      if test "$hub_ready" != yes; then
        ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
        exit 1
      fi

      echo '==> Confirm the reset credential authenticates and the old one does not'
      ${pkgs.curl}/bin/curl -sS -D /tmp/old-login.headers -o /tmp/old-login.html -X POST \
        --data-urlencode 'email=operator@example.test' \
        --data-urlencode 'password=initial-password' \
        "$hub_url/login/password"
      ! ${pkgs.grep}/bin/grep -qi '^set-cookie:' /tmp/old-login.headers
      ${pkgs.grep}/bin/grep -q 'Invalid email or password' /tmp/old-login.html
      ${pkgs.curl}/bin/curl -sS -D /tmp/login.headers -o /dev/null -X POST \
        --data-urlencode 'email=operator@example.test' \
        --data-urlencode 'password=recovered-password' \
        "$hub_url/login/password"
      cookie=$(${pkgs.sed}/bin/sed -n 's/^set-cookie: \([^;]*\).*/\1/ip' /tmp/login.headers | ${pkgs.coreutils}/bin/head -n1)
      test -n "$cookie"
      ${pkgs.curl}/bin/curl -fsS -H "Cookie: $cookie" "$hub_url/-/instance" > /tmp/instance.html
      csrf=$(${pkgs.sed}/bin/sed -n 's/.*name="aos-session-csrf" content="\([^"]*\)".*/\1/p' /tmp/instance.html | ${pkgs.coreutils}/bin/head -n1)
      test -n "$csrf"
      token=$(${pkgs.curl}/bin/curl -fsS -X POST \
        -H "Cookie: $cookie" \
        -H "Origin: $hub_url" \
        -H "x-aos-csrf: $csrf" \
        -H 'x-aos-console-route: /-/instance' \
        "$hub_url/-/auth/session-token" | ${pkgs.jq}/bin/jq -er .accessToken)

      reviewed() {
        label=$1
        shift
        plan_file="/tmp/$label-plan.json"
        apply_file="/tmp/$label-apply.json"
        if ! ${pkgs.aos}/bin/aos --json hub "$@" \
          --hub "$hub_url" --token "$token" \
          --plan --idempotency-key "$label-plan" >"$plan_file"; then
          ${pkgs.coreutils}/bin/cat "$plan_file" >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$plan_file" >&2
        plan_id=$(${pkgs.jq}/bin/jq -er .data.plan.plan_id "$plan_file")
        confirm_hash=$(${pkgs.jq}/bin/jq -er .data.plan.confirmation_hash "$plan_file")
        if ! ${pkgs.aos}/bin/aos --json hub "$@" \
          --hub "$hub_url" --token "$token" \
          --plan-id "$plan_id" --confirm-hash "$confirm_hash" --yes \
          --idempotency-key "$label-apply" >"$apply_file"; then
          ${pkgs.coreutils}/bin/cat "$apply_file" >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$apply_file"
      }

      hub_cli() {
        ${pkgs.aos}/bin/aos --json hub "$@" \
          --hub "$hub_url" --token "$token"
      }

      retained_plan() {
        label=$1
        shift
        plan_file="/tmp/$label-retained-plan.json"
        if ! hub_cli "$@" >"$plan_file"; then
          ${pkgs.coreutils}/bin/cat "$plan_file" >&2
          return 1
        fi
        ${pkgs.jq}/bin/jq -e \
          '.data.plan.plan_id != "" and .data.plan.confirmation_hash != ""' \
          "$plan_file" >/dev/null
      }

      retained_apply() {
        label=$1
        shift
        plan_file="/tmp/$label-retained-plan.json"
        plan_id=$(${pkgs.jq}/bin/jq -er .data.plan.plan_id "$plan_file")
        confirm_hash=$(${pkgs.jq}/bin/jq -er .data.plan.confirmation_hash "$plan_file")
        apply_file="/tmp/$label-retained-apply.json"
        if ! hub_cli "$@" apply \
          --plan-id "$plan_id" --confirm-hash "$confirm_hash" \
          --idempotency-key "$label-apply" --yes >"$apply_file"; then
          ${pkgs.coreutils}/bin/cat "$apply_file" >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$apply_file"
      }

      resource_version() {
        ${pkgs.jq}/bin/jq -er \
          '[.. | objects | .resource_version? // empty][0]' "$1"
      }

      echo '==> Exercise the installed aos client against the native service'
      ${pkgs.aos}/bin/aos --json hub whoami --hub "$hub_url" --token "$token" \
        >/tmp/whoami.json
      ${pkgs.coreutils}/bin/cat /tmp/whoami.json
      ${pkgs.jq}/bin/jq -e '.data.email == "operator@example.test"' \
        /tmp/whoami.json >/dev/null
      ${pkgs.aos}/bin/aos --json hub org list --hub "$hub_url" --token "$token" \
        >/tmp/org-list-empty.json
      ${pkgs.coreutils}/bin/cat /tmp/org-list-empty.json
      ${pkgs.jq}/bin/jq -e '(.data.organizations // []) == []' \
        /tmp/org-list-empty.json >/dev/null
      reviewed org-create org create --slug operations --display-name 'Operations qualification' \
        > /tmp/org-create.json
      reviewed registry-create registry create --org operations --name maintenance \
        --visibility private \
        --trust-key 'maintenance:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIEtMspYqYtUjGxOcRGRwn4WVoEYXgbIV+4crzbmtYAXy' \
        > /tmp/registry-create.json
      ${pkgs.aos}/bin/aos --json hub registry show operations/maintenance \
        --hub "$hub_url" --token "$token" >/tmp/registry-show.json
      ${pkgs.coreutils}/bin/cat /tmp/registry-show.json
      ${pkgs.jq}/bin/jq -e '.data.registry.slug == "operations/maintenance"' \
        /tmp/registry-show.json >/dev/null
      registry_version=$(${pkgs.jq}/bin/jq -er .data.registry.resource_version \
        /tmp/registry-show.json)

      echo '==> Provision and reconcile native local-filesystem storage'
      ${pkgs.aos}/bin/aos --json hub binding list \
        --hub "$hub_url" --token "$token" >/tmp/bindings.json
      ${pkgs.jq}/bin/jq -e \
        '.data.bindings | any(.stable_id == "instance-default" and .health.state == "valid")' \
        /tmp/bindings.json >/dev/null
      reviewed placement-create placement add registry:operations/maintenance primary \
        --binding instance-default --prefix registries/maintenance \
        --kind complete --desired-state active --read enabled \
        >/tmp/placement-create.json
      ${pkgs.aos}/bin/aos --json hub placement show \
        registry:operations/maintenance primary \
        --hub "$hub_url" --token "$token" >/tmp/placement.json
      placement_version=$(${pkgs.jq}/bin/jq -er .data.placement.resource_version \
        /tmp/placement.json)
      reviewed placement-scan placement scan registry:operations/maintenance primary \
        --wait --timeout 2m --if-version "$placement_version" \
        >/tmp/placement-scan.json
      ${pkgs.aos}/bin/aos --json hub placement show \
        registry:operations/maintenance primary \
        --hub "$hub_url" --token "$token" >/tmp/placement.json
      ${pkgs.jq}/bin/jq -e '.data.placement.observation.state == "ready"' \
        /tmp/placement.json >/dev/null
      placement_version=$(${pkgs.jq}/bin/jq -er .data.placement.resource_version \
        /tmp/placement.json)
      reviewed placement-promote placement promote \
        registry:operations/maintenance primary \
        --if-version "$placement_version" >/tmp/placement-promote.json

      echo '==> Exercise tenant inventory and ordinary reviewed CRUD'
      ${pkgs.aos}/bin/aos --json hub org show operations \
        --hub "$hub_url" --token "$token" >/tmp/org-show.json
      ${pkgs.coreutils}/bin/cat /tmp/org-show.json
      org_version=$(${pkgs.jq}/bin/jq -er .data.organization.resource_version \
        /tmp/org-show.json)
      org_scope=$(${pkgs.jq}/bin/jq -er .data.organization.stable_id \
        /tmp/org-show.json)
      reviewed org-update org update operations --display-name 'Operations production' \
        --if-version "$org_version" \
        >/tmp/org-update.json
      ${pkgs.aos}/bin/aos --json hub org show operations \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '.data.organization.display_name == "Operations production"' >/dev/null

      echo '==> Exercise retained instance-setting plan/apply contracts'
      hub_cli instance identity show >/tmp/instance-identity.json
      identity_version=$(resource_version /tmp/instance-identity.json)
      retained_plan identity-update instance identity update plan \
        signup_policy=invite_only --if-version "$identity_version" \
        --idempotency-key identity-update-plan
      retained_apply identity-update instance identity update \
        >/tmp/identity-update.json
      hub_cli instance identity show >/tmp/instance-identity-updated.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("invite_only")' \
        /tmp/instance-identity-updated.json >/dev/null

      hub_cli instance branding show >/tmp/instance-branding.json
      branding_version=$(resource_version /tmp/instance-branding.json)
      retained_plan branding-update instance branding update plan \
        site_title='Operations Hub' --if-version "$branding_version" \
        --idempotency-key branding-update-plan
      retained_apply branding-update instance branding update \
        >/tmp/branding-update.json
      hub_cli instance branding show \
        | ${pkgs.jq}/bin/jq -e '.data | tostring | contains("Operations Hub")' >/dev/null

      hub_cli instance resource-defaults show >/tmp/instance-resource-defaults.json
      defaults_version=$(resource_version /tmp/instance-resource-defaults.json)
      retained_plan resource-defaults-update instance resource-defaults update plan \
        max_upload_bytes=1048576 --if-version "$defaults_version" \
        --idempotency-key resource-defaults-update-plan
      retained_apply resource-defaults-update instance resource-defaults update \
        >/tmp/resource-defaults-update.json

      echo '==> Exercise service-account and membership lifecycle'
      retained_plan service-account-create org service-account create plan \
        operations release-bot --idempotency-key service-account-create-plan
      retained_apply service-account-create org service-account create \
        >/tmp/service-account-create.json
      hub_cli org service-account list operations --page-size 1 \
        >/tmp/service-account-list.json
      ${pkgs.jq}/bin/jq -e '.data | tostring | contains("release-bot")' \
        /tmp/service-account-list.json >/dev/null
      hub_cli org service-account show operations release-bot \
        >/tmp/service-account-show.json
      service_account_version=$(resource_version /tmp/service-account-show.json)

      retained_plan service-account-update org service-account update plan \
        operations release-bot --new-name publisher-bot \
        --if-version "$service_account_version" \
        --idempotency-key service-account-update-plan
      retained_apply service-account-update org service-account update \
        >/tmp/service-account-update.json
      hub_cli org service-account show operations publisher-bot \
        >/tmp/service-account-renamed.json
      service_account_ref=operations/publisher-bot

      retained_plan member-set-role org member set-role plan \
        --principal-kind service_account --principal "$service_account_ref" \
        --scope "$org_scope" --role viewer --if-version absent \
        --idempotency-key member-set-role-plan
      retained_apply member-set-role org member set-role >/tmp/member-set-role.json
      hub_cli org member show --principal-kind service_account \
        --principal "$service_account_ref" --scope "$org_scope" \
        >/tmp/member-show.json
      member_version=$(resource_version /tmp/member-show.json)
      retained_plan member-remove org member remove plan \
        --principal-kind service_account --principal "$service_account_ref" \
        --scope "$org_scope" --if-version "$member_version" \
        --idempotency-key member-remove-plan
      retained_apply member-remove org member remove >/tmp/member-remove.json

      publisher_version=$(resource_version /tmp/service-account-renamed.json)
      retained_plan service-account-delete org service-account delete plan \
        operations publisher-bot --if-version "$publisher_version" \
        --idempotency-key service-account-delete-plan
      retained_apply service-account-delete org service-account delete \
        >/tmp/service-account-delete.json

      echo '==> Exercise invitation create/read/cancel and rejected acceptance'
      retained_plan invitation-create org invitation create plan \
        operations new-user@example.test --scope "$org_scope" --role viewer \
        --ttl 3600 --idempotency-key invitation-create-plan
      retained_apply invitation-create org invitation create \
        >/tmp/invitation-create.json
      hub_cli org invitation list operations --page-size 1 >/tmp/invitation-list.json
      invitation_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .invitation_id? // empty][0]' /tmp/invitation-list.json)
      hub_cli org invitation show operations "$invitation_id" >/tmp/invitation-show.json
      invitation_version=$(resource_version /tmp/invitation-show.json)
      if hub_cli org invitation accept operations --secret invalid-secret \
        >/tmp/invitation-accept-invalid.json 2>&1; then
        echo 'invalid invitation secret unexpectedly succeeded' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'invalid|secret|invitation' \
        /tmp/invitation-accept-invalid.json
      retained_plan invitation-cancel org invitation cancel plan \
        operations "$invitation_id" --if-version "$invitation_version" \
        --idempotency-key invitation-cancel-plan
      retained_apply invitation-cancel org invitation cancel \
        >/tmp/invitation-cancel.json

      echo '==> Exercise OIDC configuration lifecycle'
      retained_plan oidc-set org identity-provider set plan operations \
        --issuer https://idp.example.test \
        --authorization-endpoint https://idp.example.test/authorize \
        --token-endpoint https://idp.example.test/token \
        --jwks-uri https://idp.example.test/keys \
        --client-id operations-hub --client-secret test-client-secret \
        --groups-claim groups --role-map-json '{"operators":"admin"}' \
        --allow-jit --default-role viewer --if-version absent \
        --idempotency-key oidc-set-plan
      retained_apply oidc-set org identity-provider set >/tmp/oidc-set.json
      hub_cli org identity-provider show operations >/tmp/oidc-show.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("idp.example.test") and (contains("test-client-secret") | not)' \
        /tmp/oidc-show.json >/dev/null
      oidc_version=$(resource_version /tmp/oidc-show.json)
      retained_plan oidc-remove org identity-provider remove plan operations \
        --if-version "$oidc_version" --idempotency-key oidc-remove-plan
      retained_apply oidc-remove org identity-provider remove >/tmp/oidc-remove.json

      echo '==> Exercise scoped access-token issuance and retirement'
      retained_plan access-token-issue access-token issue plan "$org_scope" \
        --owner user:operator@example.test --permission read \
        --ttl-secs 3600 --comment 'VM production qualification' \
        --idempotency-key access-token-issue-plan
      retained_apply access-token-issue access-token issue \
        >/tmp/access-token-issue.json
      hub_cli access-token list "$org_scope" --page-size 10 >/tmp/access-token-list.json
      token_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .token_id? // empty][0]' \
        /tmp/access-token-list.json)
      token_version=$(resource_version /tmp/access-token-list.json)
      retained_plan access-token-retire access-token retire plan "$token_id" \
        --if-version "$token_version" --idempotency-key access-token-retire-plan
      retained_apply access-token-retire access-token retire \
        >/tmp/access-token-retire.json
      reviewed project-create org project create operations --path platform --name Platform \
        >/tmp/project-create.json
      ${pkgs.aos}/bin/aos --json hub org project list operations \
        --hub "$hub_url" --token "$token" --page-size 1 \
        | ${pkgs.jq}/bin/jq -e '.data | tostring | contains("platform")' >/dev/null
      ${pkgs.aos}/bin/aos --json hub org project show operations --path platform \
        --hub "$hub_url" --token "$token" >/tmp/project-show.json
      ${pkgs.jq}/bin/jq -e '.data | tostring | contains("Platform")' \
        /tmp/project-show.json >/dev/null
      project_version=$(${pkgs.jq}/bin/jq -er .data.project.resource_version \
        /tmp/project-show.json)

      reviewed webhook-create org webhook create operations \
        --url https://hooks.example.test/events \
        --event release.published \
        --secret-version-ref native://operations/webhook/v1 \
        --credential-fingerprint "$webhook_fingerprint" \
        >/tmp/webhook-create.json
      ${pkgs.aos}/bin/aos --json hub org webhook list operations \
        --hub "$hub_url" --token "$token" > /tmp/webhooks.json
      webhook_id=$(${pkgs.jq}/bin/jq -er '.data.webhooks[0].id' /tmp/webhooks.json)
      webhook_version=$(${pkgs.jq}/bin/jq -er '.data.webhooks[0].resource_version' /tmp/webhooks.json)
      reviewed webhook-delete org webhook delete "$webhook_id" --if-version "$webhook_version" \
        >/tmp/webhook-delete.json
      ${pkgs.aos}/bin/aos --json hub org webhook list operations \
        --hub "$hub_url" --token "$token" >/tmp/webhooks-empty.json
      ${pkgs.coreutils}/bin/cat /tmp/webhooks-empty.json
      ${pkgs.jq}/bin/jq -e '(.data.webhooks // []) == []' \
        /tmp/webhooks-empty.json >/dev/null

      echo '==> Exercise audit and instance configuration reads'
      if ! ${pkgs.aos}/bin/aos --json hub org audit list \
        --hub "$hub_url" --token "$token" --page-size 10 \
        >/tmp/audit.json 2>/tmp/audit.err; then
        ${pkgs.coreutils}/bin/cat /tmp/audit.json >&2
        ${pkgs.coreutils}/bin/cat /tmp/audit.err >&2
        ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
        exit 1
      fi
      ${pkgs.coreutils}/bin/cat /tmp/audit.json
      ${pkgs.jq}/bin/jq -e '.data | type == "object"' /tmp/audit.json >/dev/null
      ${pkgs.aos}/bin/aos --json hub instance identity show \
        --hub "$hub_url" --token "$token" >/tmp/instance-identity.json
      ${pkgs.coreutils}/bin/cat /tmp/instance-identity.json
      ${pkgs.jq}/bin/jq -e '.data | type == "object"' /tmp/instance-identity.json >/dev/null
      ${pkgs.aos}/bin/aos --json hub instance branding show \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '.data | type == "object"' >/dev/null
      ${pkgs.aos}/bin/aos --json hub instance resource-defaults show \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '.data | type == "object"' >/dev/null

      reviewed registry-update registry update operations/maintenance \
        --if-version "$registry_version" \
        --visibility internal >/tmp/registry-update.json
      ${pkgs.aos}/bin/aos --json hub registry list \
        --hub "$hub_url" --token "$token" --page-size 1 \
        | ${pkgs.jq}/bin/jq -e '.data | tostring | contains("maintenance")' >/dev/null
      ${pkgs.aos}/bin/aos --json hub registry releases operations/maintenance \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '(.data.releases // []) == []' >/dev/null
      ${pkgs.aos}/bin/aos --json hub registry package list operations/maintenance \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '(.data.packages // []) == []' >/dev/null

      reviewed project-delete org project delete operations --path platform \
        --if-version "$project_version" \
        >/tmp/project-delete.json
      ${pkgs.aos}/bin/aos --json hub org project list operations \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '(.data.projects // []) == []' >/dev/null

      kill "$hub_pid"
      wait "$hub_pid" || true
      hub_pid=

      echo '==> Re-run native maintenance after a clean shutdown'
      $hub_exec --root "$hub_root" index operations/maintenance
      $hub_exec --root "$hub_root" validate run operations/maintenance
      $hub_exec --root "$hub_root" validate run operations/maintenance --depth integrity
      $hub_exec --root "$hub_root" validate run operations/maintenance --depth deep
      $hub_exec --root "$hub_root" validate repair operations/maintenance \
        --external-url "$hub_url"
      if $hub_exec --root "$hub_root" validate run missing/registry \
        >/tmp/validate-missing.out 2>&1; then
        echo 'validation unexpectedly accepted a missing registry' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'not found|unknown|missing' /tmp/validate-missing.out
      if $hub_exec --root "$hub_root" validate repair missing/registry \
        >/tmp/repair-missing.out 2>&1; then
        echo 'repair unexpectedly accepted a missing registry' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'not found|unknown|missing' /tmp/repair-missing.out

      echo 'native Hub operator lifecycle: PASS'
    '';
  }
