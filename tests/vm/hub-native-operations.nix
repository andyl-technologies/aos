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
      reviewed org-update org update operations --display-name 'Operations production' \
        --if-version "$org_version" \
        >/tmp/org-update.json
      ${pkgs.aos}/bin/aos --json hub org show operations \
        --hub "$hub_url" --token "$token" \
        | ${pkgs.jq}/bin/jq -e '.data.organization.display_name == "Operations production"' >/dev/null
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
