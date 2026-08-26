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
        "{\"native://operations/webhook/v1\":\"$webhook_secret\",\"native://operations/storage/v1\":\"$route_keys\",\"native://operations/storage/v2\":\"$probe_signers\"}" \
        >"$secret_version_manifest"
      chmod 0600 "$jwt_secret" "$probe_signers" "$route_keys" \
        "$webhook_secret" "$secret_version_manifest"
      chown -R 65534:65534 "$credential_dir"
      webhook_fingerprint=$(${pkgs.coreutils}/bin/sha256sum "$webhook_secret" \
        | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
      storage_v1_fingerprint=$(${pkgs.coreutils}/bin/sha256sum "$route_keys" \
        | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
      storage_v2_fingerprint=$(${pkgs.coreutils}/bin/sha256sum "$probe_signers" \
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
          ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$plan_file" >&2
        plan_id=$(${pkgs.jq}/bin/jq -er .data.plan.plan_id "$plan_file")
        confirm_hash=$(${pkgs.jq}/bin/jq -er .data.plan.confirmation_hash "$plan_file")
        if ! ${pkgs.aos}/bin/aos --json hub "$@" \
          --hub "$hub_url" --token "$token" \
          --plan-id "$plan_id" --confirm-hash "$confirm_hash" --yes \
          --idempotency-key "$label-apply" >"$apply_file" 2>&1; then
          ${pkgs.coreutils}/bin/cat "$apply_file" >&2
          ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
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

      expect_hub_error() {
        label=$1
        pattern=$2
        shift 2
        output="/tmp/$label-expected-error.json"
        if hub_cli "$@" >"$output" 2>&1; then
          echo "$label unexpectedly succeeded" >&2
          ${pkgs.coreutils}/bin/cat "$output" >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$output" >&2
        ${pkgs.grep}/bin/grep -Eiq "$pattern" "$output"
      }

      reviewed_apply_error() {
        label=$1
        pattern=$2
        shift 2
        plan_file="/tmp/$label-expected-plan.json"
        hub_cli "$@" --plan --idempotency-key "$label-plan" >"$plan_file"
        plan_id=$(${pkgs.jq}/bin/jq -er .data.plan.plan_id "$plan_file")
        confirm_hash=$(${pkgs.jq}/bin/jq -er .data.plan.confirmation_hash "$plan_file")
        output="/tmp/$label-expected-apply-error.json"
        if hub_cli "$@" --plan-id "$plan_id" --confirm-hash "$confirm_hash" \
          --yes --idempotency-key "$label-apply" >"$output" 2>&1; then
          echo "$label apply unexpectedly succeeded" >&2
          ${pkgs.coreutils}/bin/cat "$output" >&2
          return 1
        fi
        ${pkgs.coreutils}/bin/cat "$output" >&2
        ${pkgs.grep}/bin/grep -Eiq "$pattern" "$output"
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
      registry_id=$(${pkgs.jq}/bin/jq -er .data.registry.stable_id \
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

      echo '==> Exercise multi-placement operations, equivalence, and policy selection'
      reviewed placement-secondary-create placement add \
        registry:operations/maintenance secondary \
        --binding instance-default --prefix registries/maintenance-secondary \
        --kind complete --desired-state active --read enabled --read-order 5 \
        >/tmp/placement-secondary-create.json
      hub_cli placement list registry:operations/maintenance --page-size 1 \
        >/tmp/placement-list.json
      ${pkgs.jq}/bin/jq -e \
        '.data.placements | length == 1' /tmp/placement-list.json >/dev/null
      secondary_version=$(resource_version /tmp/placement-secondary-create.json)
      reviewed placement-secondary-scan placement scan \
        registry:operations/maintenance secondary \
        --wait --timeout 2m --if-version "$secondary_version" \
        >/tmp/placement-secondary-scan.json
      hub_cli placement show registry:operations/maintenance secondary \
        >/tmp/placement-secondary.json
      secondary_version=$(resource_version /tmp/placement-secondary.json)
      reviewed placement-secondary-update placement update \
        registry:operations/maintenance secondary \
        --read enabled --read-order 10 --if-version "$secondary_version" \
        >/tmp/placement-secondary-update.json
      secondary_version=$(resource_version /tmp/placement-secondary-update.json)
      hub_cli placement presence registry:operations/maintenance \
        nar/00000000000000000000000000000000.nar --page-size 1 \
        >/tmp/placement-presence.json
      reviewed placement-replicate placement replicate \
        registry:operations/maintenance --from primary --to secondary \
        --wait --timeout 2m --if-version "$secondary_version" \
        >/tmp/placement-replicate.json
      reviewed placement-repair placement repair \
        registry:operations/maintenance secondary \
        --wait --timeout 2m --if-version "$secondary_version" \
        >/tmp/placement-repair.json
      hub_cli placement show registry:operations/maintenance primary \
        >/tmp/placement-primary.json
      primary_version=$(resource_version /tmp/placement-primary.json)
      hub_cli placement show registry:operations/maintenance secondary \
        >/tmp/placement-secondary.json
      secondary_version=$(resource_version /tmp/placement-secondary.json)
      expect_hub_error placement-equivalence-distinct \
        'different physical object identities' \
        placement-equivalence confirm \
        registry:operations/maintenance primary secondary \
        --if-a-version "$primary_version" --if-b-version "$secondary_version" \
        --if-version "$primary_version" --plan \
        --idempotency-key placement-equivalence-distinct
      hub_cli placement-equivalence list registry:operations/maintenance \
        --page-size 1 >/tmp/placement-equivalence-list.json
      expect_hub_error placement-equivalence-remove-missing 'not.?found' \
        placement-equivalence remove equivalence:00000000000000000000000000000000 \
        --if-version 1 --plan \
        --idempotency-key placement-equivalence-remove-missing

      reviewed placement-policy-create placement-policy create \
        registry:operations/maintenance operations-failover \
        --kind ordered-failover --member primary --member secondary \
        --retry-on connect-failure --retry-on origin-503 --if-version 0 \
        >/tmp/placement-policy-create.json
      hub_cli placement-policy list registry:operations/maintenance --page-size 1 \
        >/tmp/placement-policy-list.json
      hub_cli placement-policy show registry:operations/maintenance \
        operations-failover >/tmp/placement-policy-show.json
      policy_version=$(resource_version /tmp/placement-policy-show.json)
      reviewed placement-policy-revise placement-policy revise \
        registry:operations/maintenance operations-failover \
        --kind ordered-failover --member secondary --member primary \
        --retry-on timeout-before-headers --if-version "$policy_version" \
        >/tmp/placement-policy-revise.json
      hub_cli placement-policy revisions registry:operations/maintenance \
        operations-failover --page-size 1 >/tmp/placement-policy-revisions.json
      hub_cli placement-policy show registry:operations/maintenance \
        operations-failover --revision 2 >/tmp/placement-policy-revision.json
      hub_cli placement-policy test registry:operations/maintenance \
        operations-failover --revision 2 \
        --object nar/00000000000000000000000000000000.nar \
        >/tmp/placement-policy-test.json

      echo '==> Exercise reversible placement drain and metadata removal'
      reviewed placement-transient-create placement add \
        registry:operations/maintenance transient \
        --binding instance-default --prefix registries/maintenance-transient \
        --kind complete --desired-state active --read enabled --read-order 20 \
        >/tmp/placement-transient-create.json
      transient_version=$(resource_version /tmp/placement-transient-create.json)
      reviewed placement-transient-drain placement drain \
        registry:operations/maintenance transient \
        --if-version "$transient_version" >/tmp/placement-transient-drain.json
      hub_cli placement show registry:operations/maintenance transient \
        >/tmp/placement-transient-draining.json
      transient_version=$(resource_version /tmp/placement-transient-draining.json)
      reviewed placement-transient-drain-cancel placement drain cancel \
        registry:operations/maintenance transient \
        --if-version "$transient_version" >/tmp/placement-transient-drain-cancel.json
      transient_version=$(resource_version /tmp/placement-transient-drain-cancel.json)
      reviewed placement-transient-remove placement remove \
        registry:operations/maintenance transient \
        --if-version "$transient_version" >/tmp/placement-transient-remove.json
      expect_hub_error placement-promotion-cancel-ready \
        'no unconfirmed promotion' placement promotion cancel \
        registry:operations/maintenance --if-version 1 --plan \
        --idempotency-key placement-promotion-cancel-ready

      echo '==> Exercise surface inventory, topology, and resolution explanation'
      hub_cli surface show registry:operations/maintenance \
        >/tmp/surface-show.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("operations/maintenance")' \
        /tmp/surface-show.json >/dev/null
      hub_cli surface topology registry:operations/maintenance \
        >/tmp/surface-topology.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("primary")' /tmp/surface-topology.json >/dev/null
      hub_cli surface explain registry:operations/maintenance \
        --url "$hub_url/operations/maintenance" --access-class web \
        >/tmp/surface-explain.json
      ${pkgs.jq}/bin/jq -e '.data | type == "object"' \
        /tmp/surface-explain.json >/dev/null

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

      echo '==> Exercise instance and organization topology-default inheritance'
      hub_cli instance topology-defaults show >/tmp/instance-topology-defaults.json
      reviewed instance-topology-clear instance topology-defaults clear --domain \
        >/tmp/instance-topology-clear.json
      hub_cli instance topology-defaults set --domain domain:missing \
        --plan --idempotency-key instance-topology-set-plan \
        >/tmp/instance-topology-set-plan.json
      ${pkgs.jq}/bin/jq -e '.data.plan.plan_id != ""' \
        /tmp/instance-topology-set-plan.json >/dev/null
      hub_cli org topology-defaults show operations >/tmp/org-topology-defaults.json
      reviewed org-topology-set org topology-defaults set operations \
        --binding instance-default >/tmp/org-topology-set.json
      reviewed org-topology-clear org topology-defaults clear operations --binding \
        >/tmp/org-topology-clear.json

      echo '==> Exercise immutable serving-domain configuration lifecycle'
      reviewed domain-add domain add packages.operations.example.test \
        --org operations >/tmp/domain-add.json
      hub_cli domain list --org operations --page-size 1 >/tmp/domain-list.json
      hub_cli domain show packages.operations.example.test >/tmp/domain-show.json
      domain_id=$(${pkgs.jq}/bin/jq -er '.data.domain.stable_id' \
        /tmp/domain-show.json)
      domain_version=$(resource_version /tmp/domain-show.json)
      reviewed domain-dns domain dns configure "$domain_id" \
        --mode external --expected-target packages-origin.example.test \
        --if-version "$domain_version" >/tmp/domain-dns.json
      hub_cli domain show "$domain_id" >/tmp/domain-after-dns.json
      domain_version=$(resource_version /tmp/domain-after-dns.json)
      reviewed domain-certificate domain certificate configure \
        "$domain_id" --mode external \
        --certificate-ref native://operations/certificate/v1 \
        --if-version "$domain_version" >/tmp/domain-certificate.json
      hub_cli domain status "$domain_id" >/tmp/domain-status.json
      hub_cli domain show "$domain_id" >/tmp/domain-before-remove.json
      domain_version=$(resource_version /tmp/domain-before-remove.json)
      reviewed domain-remove domain remove "$domain_id" \
        --if-version "$domain_version" >/tmp/domain-remove.json
      reviewed domain-verify-add domain add verify.operations.example.test \
        --org operations >/tmp/domain-verify-add.json
      hub_cli domain show verify.operations.example.test \
        >/tmp/domain-before-verify.json
      verify_domain_id=$(${pkgs.jq}/bin/jq -er '.data.domain.stable_id' \
        /tmp/domain-before-verify.json)
      domain_version=$(resource_version /tmp/domain-before-verify.json)
      reviewed domain-verify domain verify "$verify_domain_id" \
        --if-version "$domain_version" >/tmp/domain-verify.json
      domain_verify_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.operation.operation_id' /tmp/domain-verify.json)
      if hub_cli operation watch "$domain_verify_operation_id" --timeout 10s \
        >/tmp/domain-verify-watch.json 2>&1; then
        ${pkgs.jq}/bin/jq -e \
          '.data.operation.operation.state == "failed" and .data.terminal == true' \
          /tmp/domain-verify-watch.json >/dev/null
      else
        ${pkgs.grep}/bin/grep -Eiq 'not_found|unavailable|DNS' \
          /tmp/domain-verify-watch.json
      fi

      echo '==> Exercise organization binding, credentials, grants, and revisions'
      reviewed consumer-org-create org create --slug analytics \
        --display-name 'Analytics consumer' >/tmp/consumer-org-create.json
      hub_cli org show analytics >/tmp/consumer-org-show.json
      consumer_org_scope=$(${pkgs.jq}/bin/jq -er \
        '.data.organization.stable_id' /tmp/consumer-org-show.json)
      consumer_org_version=$(${pkgs.jq}/bin/jq -er \
        '.data.organization.resource_version' /tmp/consumer-org-show.json)
      reviewed binding-create binding create --org operations --name archive \
        --kind s3 --bucket operations-archive --prefix objects \
        --endpoint https://objects.example.test --region us-test-1 --access private \
        >/tmp/binding-create.json
      hub_cli binding list --org operations --page-size 1 >/tmp/binding-list-org.json
      ${pkgs.jq}/bin/jq -e \
        '.data.bindings | length == 1 and .[0].spec.name == "archive"' \
        /tmp/binding-list-org.json >/dev/null
      binding_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .stable_id? // empty][0]' /tmp/binding-list-org.json)
      hub_cli binding show operations:archive >/tmp/binding-show.json
      reviewed binding-grant binding grant "$binding_id" \
        --consumer-scope "$consumer_org_scope" >/tmp/binding-grant.json
      reviewed binding-revoke binding revoke "$binding_id" \
        --consumer-scope "$consumer_org_scope" >/tmp/binding-revoke.json

      reviewed binding-credential-set binding credential set "$binding_id" \
        --purpose write \
        --secret-version-ref native://operations/storage/v1 \
        --credential-fingerprint "$storage_v1_fingerprint" \
        >/tmp/binding-credential-set.json
      reviewed binding-credential-rotate binding credential rotate "$binding_id" \
        --purpose write \
        --from-generation 1 \
        --secret-version-ref native://operations/storage/v2 \
        --credential-fingerprint "$storage_v2_fingerprint" \
        >/tmp/binding-credential-rotate.json
      hub_cli binding write-revision list operations:archive \
        >/tmp/binding-write-revisions.json
      if hub_cli binding write-revision show operations:archive 1 \
        >/tmp/binding-write-revision.json 2>&1; then
        ${pkgs.jq}/bin/jq -e '.data | type == "object"' \
          /tmp/binding-write-revision.json >/dev/null
      else
        ${pkgs.grep}/bin/grep -Eiq 'not found|revision' \
          /tmp/binding-write-revision.json
      fi
      hub_cli binding show operations:archive >/tmp/binding-before-validate.json
      binding_version=$(resource_version /tmp/binding-before-validate.json)
      reviewed binding-credential-validate binding credential validate \
        "$binding_id" --purpose write --if-version "$binding_version" \
        >/tmp/binding-credential-validate.json
      credential_operation_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .operation_id? // empty][0]' \
        /tmp/binding-credential-validate.json)
      echo '==> Inspect the credential-validation operation'
      hub_cli operation show "$credential_operation_id" \
        >/tmp/credential-operation-show.json
      echo '==> List credential-validation operations by owner scope'
      hub_cli operation list --scope "$org_scope" --page-size 1 \
        >/tmp/credential-operation-list.json
      echo '==> Wait for credential-validation terminal state'
      hub_cli operation watch "$credential_operation_id" --timeout 10s \
        >/tmp/credential-operation-watch.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | test("failed|succeeded|cancelled")' \
        /tmp/credential-operation-watch.json >/dev/null

      echo '==> Exercise network-policy revision and grant lifecycle'
      reviewed network-policy-add network-policy add operations-allowlist \
        --stable-id operations-allowlist --kind source-allowlist --org operations \
        --allowlist-id operations-allowlist-v1 --protected-transport required \
        --probe-location native-operations >/tmp/network-policy-add.json
      hub_cli network-policy list --org operations --page-size 1 \
        >/tmp/network-policy-list.json
      hub_cli network-policy show operations-allowlist \
        >/tmp/network-policy-show.json
      hub_cli network-policy status operations-allowlist \
        >/tmp/network-policy-status.json
      network_policy_version=$(resource_version /tmp/network-policy-show.json)
      reviewed network-policy-revise network-policy revise operations-allowlist \
        --cidr 10.20.0.0/16 --if-version "$network_policy_version" \
        >/tmp/network-policy-revise.json
      hub_cli network-policy revision list operations-allowlist --page-size 1 \
        >/tmp/network-policy-revisions.json
      hub_cli network-policy revision show operations-allowlist@2 \
        >/tmp/network-policy-revision-two.json
      network_revision_two_version=$(resource_version /tmp/network-policy-revision-two.json)
      expect_hub_error network-policy-activate-unverified 'verified staged' \
        network-policy revision activate \
        operations-allowlist@2 --mode overlap --default-for-new-plans yes \
        --if-version "$network_revision_two_version" \
        --plan --idempotency-key network-policy-activate-unverified
      hub_cli network-policy revision show operations-allowlist@1 \
        >/tmp/network-policy-revision-one.json
      network_revision_one_version=$(resource_version /tmp/network-policy-revision-one.json)
      reviewed_apply_error network-policy-retire-staged 'active|retiring' \
        network-policy revision retire \
        operations-allowlist@1 --if-version "$network_revision_one_version" \
        >/tmp/network-policy-retire.json
      reviewed network-policy-grant network-policy grant operations-allowlist \
        --consumer-scope "$consumer_org_scope" >/tmp/network-policy-grant.json
      network_policy_grant_version=$(resource_version /tmp/network-policy-grant.json)
      reviewed network-policy-revoke network-policy revoke operations-allowlist \
        --consumer-scope "$consumer_org_scope" \
        --if-version "$network_policy_grant_version" \
        >/tmp/network-policy-revoke.json

      echo '==> Exercise endpoint generation and grant lifecycle'
      reviewed endpoint-add endpoint add http://127.0.0.1:18420 \
        --stable-id operations-endpoint --org operations --acknowledge-cleartext \
        --network-policy instance:public@1 --ingress hub \
        --listener-provider hub-native --listener-resource-id native-operations-v1 \
        --probe-provider native-file --probe-signer-secret-ref native-probe-v1 \
        --probe-public-key 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo \
        >/tmp/endpoint-add.json
      hub_cli endpoint list --org operations --page-size 1 >/tmp/endpoint-list.json
      hub_cli endpoint show operations-endpoint >/tmp/endpoint-show.json
      hub_cli endpoint generations operations-endpoint --page-size 1 \
        >/tmp/endpoint-generations.json
      hub_cli endpoint generation operations-endpoint 1 \
        >/tmp/endpoint-generation-one.json
      hub_cli endpoint status operations-endpoint >/tmp/endpoint-status.json
      endpoint_version=$(resource_version /tmp/endpoint-show.json)
      reviewed endpoint-stage endpoint stage operations-endpoint \
        --ingress layer7 --listener-provider layer7 \
        --listener-resource-id native-operations-v2 \
        --if-version "$endpoint_version" \
        >/tmp/endpoint-stage.json
      hub_cli endpoint generation operations-endpoint 2 \
        >/tmp/endpoint-generation-two.json
      hub_cli endpoint show operations-endpoint >/tmp/endpoint-before-activate.json
      endpoint_activate_version=$(resource_version /tmp/endpoint-before-activate.json)
      reviewed endpoint-activate endpoint activate operations-endpoint 2 \
        --if-version "$endpoint_activate_version" \
        >/tmp/endpoint-activate.json
      reviewed endpoint-grant endpoint grant operations-endpoint \
        --consumer-scope "$consumer_org_scope" >/tmp/endpoint-grant.json
      endpoint_grant_version=$(resource_version /tmp/endpoint-grant.json)
      reviewed endpoint-revoke endpoint revoke operations-endpoint \
        --consumer-scope "$consumer_org_scope" \
        --if-version "$endpoint_grant_version" >/tmp/endpoint-revoke.json

      echo '==> Exercise route creation, revision, serving, and replacement'
      reviewed route-add route add registry:operations/maintenance \
        --stable-id operations-route --endpoint operations-endpoint \
        --endpoint-generation 2 --base-path /maintenance --mode hub-proxy \
        --placement primary --serves web --serves cache --access public \
        >/tmp/route-add.json
      hub_cli route list registry:operations/maintenance --page-size 1 \
        >/tmp/route-list.json
      hub_cli route explain operations-route --path /maintenance \
        --access-class web >/tmp/route-explain.json
      route_version=$(resource_version /tmp/route-add.json)
      reviewed route-update route update operations-route \
        --serves web --access public --if-version "$route_version" \
        >/tmp/route-update.json
      route_version=$(resource_version /tmp/route-update.json)
      reviewed route-enable route enable operations-route \
        --if-version "$route_version" >/tmp/route-enable.json
      route_version=$(resource_version /tmp/route-enable.json)
      expect_hub_error route-canonical-unreconciled 'ready|reconciled|canonical' \
        route canonical registry:operations/maintenance operations-route \
        --audience web --if-version "$route_version" --plan \
        --idempotency-key route-canonical-unreconciled
      reviewed route-disable route disable operations-route \
        --if-version "$route_version" >/tmp/route-disable.json
      route_version=$(resource_version /tmp/route-disable.json)
      expect_hub_error route-replace-disabled 'must be enabled' \
        route replace operations-route \
        --endpoint operations-endpoint --endpoint-generation 2 \
        --base-path /maintenance-v2 --mode hub-proxy --placement primary \
        --serves web --access public --if-version "$route_version" --plan \
        --idempotency-key route-replace-disabled
      reviewed route-reenable route enable operations-route \
        --if-version "$route_version" >/tmp/route-reenable.json
      route_version=$(resource_version /tmp/route-reenable.json)
      reviewed route-replace route replace operations-route \
        --endpoint operations-endpoint --endpoint-generation 2 \
        --base-path /maintenance-v2 --mode hub-proxy --placement primary \
        --serves web --access public --if-version "$route_version" \
        >/tmp/route-replace.json
      replacement_route_id=$(${pkgs.jq}/bin/jq -er \
        '.data.result.route.stable_id' /tmp/route-replace.json)
      replacement_route_version=$(resource_version /tmp/route-replace.json)
      reviewed route-replacement-remove route remove "$replacement_route_id" \
        --if-version "$replacement_route_version" \
        >/tmp/route-replacement-remove.json
      reviewed route-redisable route disable operations-route \
        --if-version "$route_version" >/tmp/route-redisable.json
      route_version=$(resource_version /tmp/route-redisable.json)
      reviewed route-remove route remove operations-route \
        --if-version "$route_version" >/tmp/route-remove.json

      echo '==> Exercise gateway generation, authorization, and lifecycle'
      reviewed gateway-add gateway add --stable-id operations-gateway \
        --binding operations:archive --endpoint operations-endpoint@2 \
        --client-base-path /archive --origin-prefix /objects --access public \
        >/tmp/gateway-add.json
      hub_cli gateway list --binding operations:archive --page-size 1 \
        >/tmp/gateway-list.json
      hub_cli gateway show operations-gateway >/tmp/gateway-show.json
      hub_cli gateway preview operations-gateway >/tmp/gateway-preview.json
      gateway_version=$(resource_version /tmp/gateway-show.json)
      reviewed gateway-update gateway update operations-gateway \
        --origin-prefix /objects-v2 --access public --if-version "$gateway_version" \
        >/tmp/gateway-update.json
      reviewed gateway-grant gateway grant operations-gateway@2 \
        --consumer-scope "$consumer_org_scope" >/tmp/gateway-grant.json
      gateway_grant_version=$(resource_version /tmp/gateway-grant.json)
      reviewed gateway-revoke gateway revoke operations-gateway@2 \
        --consumer-scope "$consumer_org_scope" \
        --if-version "$gateway_grant_version" >/tmp/gateway-revoke.json
      hub_cli gateway show operations-gateway >/tmp/gateway-before-enable.json
      gateway_enable_version=$(resource_version /tmp/gateway-before-enable.json)
      expect_hub_error gateway-enable-unreconciled 'reconciled and ready' \
        gateway enable operations-gateway --if-version "$gateway_enable_version" \
        --plan --idempotency-key gateway-enable-unreconciled
      hub_cli gateway show operations-gateway >/tmp/gateway-before-disable.json
      gateway_disable_version=$(resource_version /tmp/gateway-before-disable.json)
      reviewed gateway-disable gateway disable operations-gateway \
        --if-version "$gateway_disable_version" >/tmp/gateway-disable.json
      hub_cli gateway show operations-gateway >/tmp/gateway-before-remove.json
      gateway_remove_version=$(resource_version /tmp/gateway-before-remove.json)
      reviewed gateway-remove gateway remove operations-gateway \
        --if-version "$gateway_remove_version" >/tmp/gateway-remove.json

      hub_cli endpoint show operations-endpoint >/tmp/endpoint-before-remove.json
      endpoint_remove_version=$(resource_version /tmp/endpoint-before-remove.json)
      reviewed endpoint-remove endpoint remove operations-endpoint \
        --if-version "$endpoint_remove_version" >/tmp/endpoint-remove.json
      hub_cli network-policy show operations-allowlist \
        >/tmp/network-policy-before-remove.json
      network_policy_remove_version=$(resource_version \
        /tmp/network-policy-before-remove.json)
      reviewed network-policy-remove network-policy remove operations-allowlist \
        --if-version "$network_policy_remove_version" \
        >/tmp/network-policy-remove.json

      hub_cli binding show operations:archive >/tmp/binding-before-delete.json
      binding_delete_version=$(resource_version /tmp/binding-before-delete.json)
      echo '==> Delete the unused binding'
      reviewed binding-delete binding delete "$binding_id" \
        --if-version "$binding_delete_version" >/tmp/binding-delete.json
      reviewed consumer-org-delete org delete analytics \
        --if-version "$consumer_org_version" >/tmp/consumer-org-delete.json

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

      echo '==> Exercise organization email-domain claim and release'
      hub_cli org domain list operations >/tmp/org-domains-empty.json
      retained_plan org-domain-claim org domain claim plan operations example.test \
        --if-version absent --idempotency-key org-domain-claim-plan
      retained_apply org-domain-claim org domain claim >/tmp/org-domain-claim.json
      hub_cli org domain show operations example.test >/tmp/org-domain-show.json
      org_domain_version=$(resource_version /tmp/org-domain-show.json)
      retained_plan org-domain-verify org domain verify plan operations example.test \
        --if-version "$org_domain_version" --idempotency-key org-domain-verify-plan
      org_domain_verify_plan_id=$(${pkgs.jq}/bin/jq -er \
        .data.plan.plan_id /tmp/org-domain-verify-retained-plan.json)
      org_domain_verify_hash=$(${pkgs.jq}/bin/jq -er \
        .data.plan.confirmation_hash /tmp/org-domain-verify-retained-plan.json)
      expect_hub_error org-domain-verify \
        'unavailable.*DNS TXT verification is temporarily unavailable' \
        org domain verify apply --plan-id "$org_domain_verify_plan_id" \
        --confirm-hash "$org_domain_verify_hash" \
        --idempotency-key org-domain-verify-apply --yes
      hub_cli org domain show operations example.test >/tmp/org-domain-after-verify.json
      org_domain_version=$(resource_version /tmp/org-domain-after-verify.json)
      retained_plan org-domain-release org domain release plan operations example.test \
        --if-version "$org_domain_version" --idempotency-key org-domain-release-plan
      retained_apply org-domain-release org domain release >/tmp/org-domain-release.json

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

      echo '==> Exercise externally custodied signing-key lifecycle and usage pins'
      printf '%s' '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo' \
        >/tmp/signing-key-generation-1.pub
      printf '%s' 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw' \
        >/tmp/signing-key-generation-2.pub
      hub_cli signing-key list --scope "$org_scope" >/tmp/signing-keys-empty.json
      ${pkgs.jq}/bin/jq -e '(.data.signing_keys // []) == []' \
        /tmp/signing-keys-empty.json >/dev/null
      retained_plan signing-key-enroll signing-key enroll plan release-root \
        --scope "$org_scope" \
        --public-key-file /tmp/signing-key-generation-1.pub \
        --public-key-fingerprint 21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9 \
        --custody external --idempotency-key signing-key-enroll-plan
      retained_apply signing-key-enroll signing-key enroll \
        >/tmp/signing-key-enroll.json
      hub_cli signing-key show --scope "$org_scope" release-root \
        >/tmp/signing-key-show.json
      signing_key_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .stable_id? // empty][0]' /tmp/signing-key-show.json)
      signing_key_version=$(resource_version /tmp/signing-key-show.json)
      hub_cli signing-key list --scope "$org_scope" --page-size 1 \
        | ${pkgs.jq}/bin/jq -e '.data | tostring | contains("release-root")' >/dev/null

      retained_plan signing-key-usage signing-key usage plan \
        --consumer "$registry_id" --purpose registry-publication \
        --signing-key "$signing_key_id" --generation 1 \
        --state active --if-version absent \
        --idempotency-key signing-key-usage-plan
      retained_apply signing-key-usage signing-key usage \
        >/tmp/signing-key-usage.json
      hub_cli signing-key usage show --consumer "$registry_id" \
        --purpose registry-publication >/tmp/signing-key-usage-show.json
      usage_version=$(resource_version /tmp/signing-key-usage-show.json)

      retained_plan signing-key-rotate signing-key rotate plan release-root \
        --scope "$org_scope" \
        --public-key-file /tmp/signing-key-generation-2.pub \
        --public-key-fingerprint 39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f \
        --custody external --if-version "$signing_key_version" \
        --idempotency-key signing-key-rotate-plan
      retained_apply signing-key-rotate signing-key rotate \
        >/tmp/signing-key-rotate.json
      hub_cli signing-key show --scope "$org_scope" release-root \
        >/tmp/signing-key-rotated.json
      ${pkgs.jq}/bin/jq -e \
        '[.data | .. | objects | .generation? // empty] | any(. == 2 or . == "2")' \
        /tmp/signing-key-rotated.json >/dev/null

      retained_plan signing-key-usage-rotate signing-key usage plan \
        --consumer "$registry_id" --purpose registry-publication \
        --signing-key "$signing_key_id" --generation 2 \
        --state detached --if-version "$usage_version" \
        --idempotency-key signing-key-usage-rotate-plan
      retained_apply signing-key-usage-rotate signing-key usage \
        >/tmp/signing-key-usage-detached.json
      signing_key_version=$(resource_version /tmp/signing-key-rotated.json)
      retained_plan signing-key-retire signing-key retire plan release-root \
        --scope "$org_scope" --if-version "$signing_key_version" \
        --idempotency-key signing-key-retire-plan
      retained_apply signing-key-retire signing-key retire \
        >/tmp/signing-key-retire.json
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
