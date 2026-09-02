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
  cutoverRecipe = pkgs.writeTextFile {
    name = "hub-native-operations-cutover-recipe";
    destination = "/recipe.json";
    text = builtins.readFile ../../docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-bundle-generation-v1.fixture.json;
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
      pkgs.git
      pkgs.iproute2
      pkgs.jq
      pkgs.nix
      pkgs.openssh
      pkgs.sed
      jwtSecret
      probeSigners
      routeKeys
      webhookSecret
      cutoverRecipe
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

      export NIX_REMOTE=""
      export NIX_CONF_DIR=/tmp/nix-conf
      mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots
      printf '%s\n' 'experimental-features = nix-command' 'sandbox = false' \
        >"$NIX_CONF_DIR/nix.conf"
      ${pkgs.nix}/bin/nix-store --init || true
      ${pkgs.nix}/bin/nix-store --load-db </aos-registration

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

      echo '==> Exercise offline topology-cutover command boundaries'
      mkdir -p /tmp/cutover-bundle/bin /tmp/cutover-source /tmp/cutover-inputs
      ${pkgs.aos}/bin/aos --json hub topology cutover materialize-verifier \
        --bundle /tmp/cutover-bundle \
        --bundle-recipe ${cutoverRecipe}/recipe.json \
        >/tmp/cutover-materialize.json
      test -x /tmp/cutover-bundle/bin/aos
      ${pkgs.jq}/bin/jq -e '.result == "materialized"' \
        /tmp/cutover-materialize.json >/dev/null
      printf '%s\n' invalid >/tmp/cutover-inputs/key
      if ${pkgs.aos}/bin/aos --json hub topology cutover generate \
        --bundle /tmp/cutover-bundle --bundle-source /tmp/cutover-source \
        --bundle-recipe ${cutoverRecipe}/recipe.json \
        --bundle-manifest-output /tmp/cutover-inputs/manifest.json \
        --root-signing-key /tmp/cutover-inputs/key \
        --document-signing-key /tmp/cutover-inputs/key \
        --verification-signing-key /tmp/cutover-inputs/key \
        --trusted-root-public-key /tmp/cutover-inputs/key \
        --root-signer-key-id root --document-signer-key-id documents \
        --verification-signer-key-id verification \
        >/tmp/cutover-generate-invalid.json 2>&1; then
        echo 'cutover generation unexpectedly accepted an incomplete source' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'input|bundle|source|missing|invalid' \
        /tmp/cutover-generate-invalid.json
      printf '%s\n' '{}' >/tmp/cutover-inputs/manifest.json
      if ${pkgs.aos}/bin/aos --json hub topology cutover verify \
        --bundle /tmp/cutover-bundle \
        --bundle-manifest /tmp/cutover-inputs/manifest.json \
        --trusted-root-public-key /tmp/cutover-inputs/key \
        --trusted-root-sha256 \
          0000000000000000000000000000000000000000000000000000000000000000 \
        >/tmp/cutover-verify-invalid.json 2>&1; then
        echo 'cutover verification unexpectedly accepted an invalid manifest' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'manifest|schema|invalid|fingerprint' \
        /tmp/cutover-verify-invalid.json

      echo '==> Exercise package credential authoring and render service boundaries'
      printf '%s' 'production-bootstrap-secret' >/tmp/credential-plaintext
      mkdir -p /tmp/apm-author-home /tmp/apm-render-config
      if HOME=/tmp/apm-author-home \
        ${pkgs.aos.apm}/bin/apm --json credential encrypt bootstrap-token \
          /tmp/credential-plaintext --unit bootstrap.socket \
          >/tmp/credential-invalid-unit.json 2>&1; then
        echo 'credential encryption unexpectedly accepted a non-service unit' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'must be a service unit' \
        /tmp/credential-invalid-unit.json
      if APM_SYSTEM_CONFIG_DIR=/tmp/apm-render-config \
        ${pkgs.aos.packageRuntime}/bin/aos-package-runtime --json render-one example \
          --manifest /tmp/nonexistent-config-manifest.json \
          --marker-root /tmp/render-markers --staging-root /tmp/render-stage \
          >/tmp/render-one-non-aos.json 2>&1; then
        echo 'render-one unexpectedly accepted a non-AOS runtime' >&2
        exit 1
      fi
      ${pkgs.jq}/bin/jq -e \
        '.error | contains("the running system is not AOS")' \
        /tmp/render-one-non-aos.json >/dev/null
      mkdir -p /aos-toplevel
      printf '%s\n' 'ID=aos' 'AOS_MODULE_ABI=2' >/aos-toplevel/os-release
      if APM_SYSTEM_CONFIG_DIR=/tmp/apm-render-config \
        ${pkgs.aos.packageRuntime}/bin/aos-package-runtime --json render-one example \
          --manifest /tmp/nonexistent-config-manifest.json \
          --marker-root /tmp/render-markers --staging-root /tmp/render-stage \
          >/tmp/render-one-missing.json 2>&1; then
        echo 'render-one unexpectedly accepted a missing eval manifest' >&2
        exit 1
      fi
      ${pkgs.jq}/bin/jq -e \
        '.op == "render-one" and .package == "example"
          and (.error | contains("reading manifest"))' \
        /tmp/render-one-missing.json >/dev/null

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

      hub_cli_into() {
        output=$1
        shift
        if ! hub_cli "$@" >"$output" 2>&1; then
          ${pkgs.coreutils}/bin/cat "$output" >&2
          return 1
        fi
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

      echo '==> Exercise the public CLI device-login and logout ceremony'
      cli_profile_home=/tmp/hub-cli-profile
      mkdir -p "$cli_profile_home"
      HOME="$cli_profile_home" ${pkgs.aos}/bin/aos hub login --hub "$hub_url" \
        >/tmp/hub-cli-login.out 2>&1 &
      login_pid=$!
      device_code=
      for attempt in $(${pkgs.coreutils}/bin/seq 1 300); do
        device_code=$(${pkgs.grep}/bin/grep -Eo \
          '[A-Z0-9]{4}-[A-Z0-9]{4}' /tmp/hub-cli-login.out \
          | ${pkgs.coreutils}/bin/head -n1 || true)
        if test -n "$device_code"; then
          break
        fi
        if ! kill -0 "$login_pid" 2>/dev/null; then
          ${pkgs.coreutils}/bin/cat /tmp/hub-cli-login.out >&2
          wait "$login_pid"
        fi
        ${pkgs.coreutils}/bin/sleep 0.1
      done
      if test -z "$device_code"; then
        kill "$login_pid" 2>/dev/null || true
        ${pkgs.coreutils}/bin/cat /tmp/hub-cli-login.out >&2
        exit 1
      fi
      ${pkgs.curl}/bin/curl -fsS -o /tmp/device-approval.out -X POST \
        -H "Cookie: $cookie" -H "Origin: $hub_url" \
        --data-urlencode "csrf=$csrf" \
        --data-urlencode "user_code=$device_code" \
        --data-urlencode 'decision=approve' "$hub_url/activate"
      for attempt in $(${pkgs.coreutils}/bin/seq 1 300); do
        if ! kill -0 "$login_pid" 2>/dev/null; then
          break
        fi
        ${pkgs.coreutils}/bin/sleep 0.1
      done
      if kill -0 "$login_pid" 2>/dev/null; then
        kill "$login_pid" 2>/dev/null || true
        ${pkgs.coreutils}/bin/cat /tmp/hub-cli-login.out >&2
        exit 1
      fi
      wait "$login_pid"
      HOME="$cli_profile_home" ${pkgs.aos}/bin/aos --json hub whoami \
        --hub "$hub_url" >/tmp/profile-whoami.json
      ${pkgs.jq}/bin/jq -e '.data.email == "operator@example.test"' \
        /tmp/profile-whoami.json >/dev/null
      HOME="$cli_profile_home" ${pkgs.aos}/bin/aos --json hub logout \
        --hub "$hub_url" >/tmp/hub-cli-logout.json
      ${pkgs.jq}/bin/jq -e '.data.revoked == true' \
        /tmp/hub-cli-logout.json >/dev/null

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
      producer_home=/tmp/producer-home
      mkdir -p "$producer_home"
      producer_path=${pkgs.git}/bin:${pkgs.openssh}/bin:${pkgs.coreutils}/bin
      HOME="$producer_home" ${pkgs.git}/bin/git config --global \
        user.name 'Operations Maintainer'
      HOME="$producer_home" ${pkgs.git}/bin/git config --global \
        user.email maintainer@example.test
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json keys generate maintainer --registry maintenance \
        >/tmp/producer-key.json
      ${pkgs.coreutils}/bin/cat /tmp/producer-key.json
      producer_trust_key=$(${pkgs.jq}/bin/jq -er \
        '.public_key // .trust_key' /tmp/producer-key.json)
      producer_key=$(${pkgs.jq}/bin/jq -er \
        '.private_key // .key_path' /tmp/producer-key.json)
      test -n "$producer_trust_key"
      test -s "$producer_key"
      reviewed registry-create registry create --org operations --name maintenance \
        --visibility private \
        --trust-key "$producer_trust_key" \
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
      ${pkgs.aos}/bin/aos --json hub org show operations \
        --hub "$hub_url" --token "$token" >/tmp/operations-org-show.json
      operations_org_scope=$(${pkgs.jq}/bin/jq -er \
        .data.organization.stable_id /tmp/operations-org-show.json)
      reviewed instance-default-grant binding grant instance-default \
        --consumer-scope "$operations_org_scope" \
        >/tmp/instance-default-grant.json
      ${pkgs.aos}/bin/aos --json hub binding list --org operations --include-granted \
        --hub "$hub_url" --token "$token" >/tmp/operations-bindings.json
      ${pkgs.jq}/bin/jq -e \
        '.data.bindings | any(.stable_id == "instance-default" and .health.state == "valid")' \
        /tmp/operations-bindings.json >/dev/null
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

      echo '==> Publish a real APR-produced initial registry surface'
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr create maintenance \
        --trust-key "$producer_trust_key" --trust-key-id maintainer \
        --key "$producer_key" >/tmp/apr-create.json
      producer_registry="$producer_home/.local/share/apm/registries/maintenance"
      test -s "$producer_registry/registry.toml"
      test -s "$producer_registry/.git/HEAD"
      test -s "$producer_registry/.git/info/refs"
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json add --no-verify \
        "file://$producer_registry" --name maintenance --no-clone \
        >/tmp/apr-add-maintainer-config.json
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json keys register maintainer \
        --key "$producer_key" --registry maintenance \
        >/tmp/apr-register-maintainer-key.json
      if ! HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json publish ${pkgs.grep} \
        --name qualification-grep --version 1.0.0 \
        --description 'Hermetic package used by native Hub qualification' \
        --license GPL-3.0-or-later \
        --maintainer maintainer@example.test --registry maintenance \
        --key-id maintainer \
        >/tmp/apr-publish-package.json 2>&1; then
        ${pkgs.coreutils}/bin/cat /tmp/apr-publish-package.json >&2
        exit 1
      fi
      ${pkgs.coreutils}/bin/cat /tmp/apr-publish-package.json
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json web generate --registry maintenance \
        --output /tmp/producer-web >/tmp/apr-web-generate.json
      test -s /tmp/producer-web/index.html
      test -s /tmp/producer-web/web/config.json
      producer_surface=/tmp/producer-surface
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json origin upload \
        --registry maintenance --upload-url "file://$producer_surface" \
        >/tmp/apr-origin-upload.json
      ${pkgs.coreutils}/bin/cat /tmp/apr-origin-upload.json
      test -s "$producer_surface/HEAD"
      test -s "$producer_surface/info/refs"
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json origin prepare-index-bundles \
        --surface-dir "$producer_surface" \
        >/tmp/apr-origin-index-bundles.json
      hub_cli_into /tmp/publication-upload.json registry publish upload \
        operations/maintenance --root "$producer_surface"
      ${pkgs.jq}/bin/jq \
        '{publication_id: .data.publication_id, state: .data.state,
          indexed_commit: .data.indexed_commit,
          object_count: (.data.objects | length)}' \
        /tmp/publication-upload.json
      publication_id=$(${pkgs.jq}/bin/jq -er .data.publication_id \
        /tmp/publication-upload.json)
      hub_cli_into /tmp/publication-show.json registry publish show "$publication_id"
      ${pkgs.jq}/bin/jq -e '.data.state == "ready"' \
        /tmp/publication-show.json >/dev/null
      hub_cli_into /tmp/registry-indexed.json registry show \
        operations/maintenance
      ${pkgs.jq}/bin/jq -e '.data.registry.index_state == "fresh"' \
        /tmp/registry-indexed.json >/dev/null
      hub_cli_into /tmp/registry-packages-indexed.json registry package list \
        operations/maintenance
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("qualification-grep")' \
        /tmp/registry-packages-indexed.json >/dev/null
      hub_cli_into /tmp/publication-list.json registry publish list operations/maintenance \
        --state ready --page-size 1
      ${pkgs.jq}/bin/jq -e --arg id "$publication_id" \
        '.data.publications | any(.publication_id == $id and .state == "ready")' \
        /tmp/publication-list.json >/dev/null
      hub_cli_into /tmp/publication-commit-idempotent.json \
        registry publish commit "$publication_id"
      ${pkgs.jq}/bin/jq -e '.data.state == "ready"' \
        /tmp/publication-commit-idempotent.json >/dev/null

      ${pkgs.jq}/bin/jq \
        '.data as $publication
          | {registry: "operations/maintenance", generation: ("a" * 64),
             refs_digest: $publication.refs_digest,
             default_commit: $publication.default_commit,
             parent_publication_id: $publication.publication_id,
             objects: [($publication.objects[]
               | {path, sha256, byte_size, kind, media_type})][0:1]}' \
        /tmp/publication-upload.json >/tmp/publication-abort-manifest.json
      hub_cli_into /tmp/publication-begin.json registry publish begin \
        operations/maintenance --manifest /tmp/publication-abort-manifest.json
      ${pkgs.coreutils}/bin/cat /tmp/publication-begin.json
      abort_publication_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .publication_id? // empty][0]' \
        /tmp/publication-begin.json)
      hub_cli_into /tmp/publication-abort.json registry publish abort \
        "$abort_publication_id"
      ${pkgs.coreutils}/bin/cat /tmp/publication-abort.json
      ${pkgs.jq}/bin/jq -e '.data.state == "failed"' \
        /tmp/publication-abort.json >/dev/null
      hub_cli_into /tmp/registry-channels.json registry channel list \
        operations/maintenance --page-size 1
      ${pkgs.jq}/bin/jq -e '(.data.channels // []) == []' \
        /tmp/registry-channels.json >/dev/null
      expect_hub_error registry-channel-missing 'not.?found' \
        registry channel show operations/maintenance stable

      reviewed registry-mirror-set registry mirror set operations/maintenance \
        --source https://mirror.operations.example.test/registry/ \
        --refspec refs/heads/main --interval 1h \
        --signature-policy required --mode full \
        >/tmp/registry-mirror-set.json
      hub_cli_into /tmp/registry-mirror-show.json registry mirror show \
        operations/maintenance
      mirror_version=$(resource_version /tmp/registry-mirror-show.json)
      ${pkgs.jq}/bin/jq -e \
        '.data.mirror.source_url
          == "https://mirror.operations.example.test/registry"' \
        /tmp/registry-mirror-show.json >/dev/null
      reviewed registry-mirror-sync registry mirror sync operations/maintenance \
        --if-version "$mirror_version" >/tmp/registry-mirror-sync.json
      mirror_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.result.operation.operation_id
          // .data.operation.operation_id
          // .data.result.operation_id' /tmp/registry-mirror-sync.json)
      if hub_cli operation watch "$mirror_operation_id" --timeout 30s \
        >/tmp/registry-mirror-watch.json 2>&1; then
        echo 'unreachable mirror synchronization unexpectedly succeeded' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq 'failed|resolve|dns|mirror|timed out' \
        /tmp/registry-mirror-watch.json
      hub_cli_into /tmp/registry-mirror-show-failed.json registry mirror show \
        operations/maintenance
      mirror_version=$(resource_version /tmp/registry-mirror-show-failed.json)
      reviewed registry-mirror-remove registry mirror remove operations/maintenance \
        --if-version "$mirror_version" >/tmp/registry-mirror-remove.json
      expect_hub_error registry-mirror-removed 'not.?found' \
        registry mirror show operations/maintenance

      echo '==> Exercise registry consumer-cache configuration and review reads'
      hub_cli_into /tmp/cache-stack-empty.json registry cache-stack show \
        operations/maintenance
      ${pkgs.coreutils}/bin/cat /tmp/cache-stack-empty.json
      if ! ${pkgs.jq}/bin/jq -e \
        '.data.stack.registry_id == "operations/maintenance"
          and (.data.stack.entries // []) == []
          and .data.stack.resource_version != ""' \
        /tmp/cache-stack-empty.json >/dev/null; then
        ${pkgs.coreutils}/bin/cat /tmp/aos-hub.log >&2
        exit 1
      fi
      cache_stack_version=$(${pkgs.jq}/bin/jq -er \
        .data.stack.resource_version /tmp/cache-stack-empty.json)
      hub_cli_into /tmp/cache-stack-validation-empty.json \
        registry cache-stack validate operations/maintenance
      ${pkgs.coreutils}/bin/cat /tmp/cache-stack-validation-empty.json
      ${pkgs.jq}/bin/jq -e \
        '.data.valid == true
          and (.data.warnings | any(contains("no signed consumer-cache entries")))' \
        /tmp/cache-stack-validation-empty.json >/dev/null
      expect_hub_error cache-stack-url-scheme 'http or https' \
        registry cache-stack add operations/maintenance \
        --url ftp://cache.example.test --plan
      expect_hub_error cache-stack-url-credentials \
        'credentials, query, or fragment' \
        registry cache-stack add operations/maintenance \
        --url https://user@cache.example.test --plan
      expect_hub_error cache-stack-url-query \
        'credentials, query, or fragment' \
        registry cache-stack add operations/maintenance \
        --url 'https://cache.example.test?tenant=operations' --plan
      expect_hub_error cache-stack-url-fragment \
        'credentials, query, or fragment' \
        registry cache-stack add operations/maintenance \
        --url 'https://cache.example.test#unsigned' --plan
      reviewed cache-stack-external-add registry cache-stack add \
        operations/maintenance --url https://cache-a.example.test \
        --if-version "$cache_stack_version" >/tmp/cache-stack-external-add.json
      cache_stack_change_id=$(${pkgs.jq}/bin/jq -er \
        '.data.result.change_id // .data.change_id // .change_id' \
        /tmp/cache-stack-external-add.json)
      ${pkgs.jq}/bin/jq -e \
        '(.data.result.state // .data.state // .state) == "draft"' \
        /tmp/cache-stack-external-add.json >/dev/null

      hub_cli_into /tmp/config-changesets.json registry configuration changesets \
        --scope "$registry_id" --page-size 1
      ${pkgs.jq}/bin/jq -e --arg id "$cache_stack_change_id" \
        '.data.changesets | any(.change_id == $id and .status == "draft")' \
        /tmp/config-changesets.json >/dev/null
      hub_cli_into /tmp/config-show.json registry configuration show \
        "$cache_stack_change_id"
      ${pkgs.jq}/bin/jq -e --arg id "$cache_stack_change_id" \
        '.data.changeset.change_id == $id
          and (.data.revisions | length) == 1' /tmp/config-show.json >/dev/null
      hub_cli_into /tmp/config-change-requests.json \
        registry configuration change-requests \
        operations/maintenance --page-size 1
      ${pkgs.jq}/bin/jq -e --arg id "$cache_stack_change_id" \
        '.data.change_requests
          | any(.change_id == $id and (.merge_command | contains("apr change merge")))' \
        /tmp/config-change-requests.json >/dev/null
      hub_cli_into /tmp/config-log.json registry configuration log \
        operations/maintenance \
        --page-size 1
      ${pkgs.jq}/bin/jq -e '.data | type == "object"' \
        /tmp/config-log.json >/dev/null
      hub_cli_into /tmp/config-diff.json registry configuration diff \
        operations/maintenance
      ${pkgs.jq}/bin/jq -e '.data | type == "object"' \
        /tmp/config-diff.json >/dev/null

      echo '==> Publish a producer-signed cache stack and draft structural edits'
      if ! HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json cache generate --registry maintenance \
          --output /tmp/producer-cache-a \
          --cache-url https://cache-a.example.test --priority 100 \
          >/tmp/apr-cache-a.json 2>&1; then
        ${pkgs.coreutils}/bin/cat /tmp/apr-cache-a.json >&2
        exit 1
      fi
      if ! HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json cache generate --registry maintenance \
          --output /tmp/producer-cache-b \
          --cache-url https://cache-b.example.test --priority 90 \
          >/tmp/apr-cache-b.json 2>&1; then
        ${pkgs.coreutils}/bin/cat /tmp/apr-cache-b.json >&2
        exit 1
      fi
      ${pkgs.jq}/bin/jq -e \
        '.cache_pointer_updated == true and .committed == true' \
        /tmp/apr-cache-a.json >/dev/null
      ${pkgs.jq}/bin/jq -e \
        '.cache_pointer_updated == true and .committed == true' \
        /tmp/apr-cache-b.json >/dev/null
      HOME="$producer_home" PATH="$producer_path" \
        ${pkgs.aos.apr}/bin/apr --json origin upload \
          --registry maintenance --upload-url "file://$producer_surface" \
          >/tmp/apr-origin-cache-stack-upload.json
      hub_cli_into /tmp/cache-stack-publication.json registry publish upload \
        operations/maintenance --root "$producer_surface"
      ${pkgs.jq}/bin/jq -e '.data.state == "ready"' \
        /tmp/cache-stack-publication.json >/dev/null
      hub_cli_into /tmp/cache-stack-indexed.json registry cache-stack show \
        operations/maintenance
      ${pkgs.jq}/bin/jq -e \
        '.data.stack.entries | length == 2' \
        /tmp/cache-stack-indexed.json >/dev/null
      cache_stack_version=$(${pkgs.jq}/bin/jq -er \
        .data.stack.resource_version /tmp/cache-stack-indexed.json)
      cache_stack_first=$(${pkgs.jq}/bin/jq -er \
        '.data.stack.entries[0].entry_id' /tmp/cache-stack-indexed.json)
      cache_stack_second=$(${pkgs.jq}/bin/jq -er \
        '.data.stack.entries[1].entry_id' /tmp/cache-stack-indexed.json)
      reviewed cache-stack-move registry cache-stack move \
        operations/maintenance "$cache_stack_second" \
        --before "$cache_stack_first" --if-version "$cache_stack_version" \
        >/tmp/cache-stack-move.json
      ${pkgs.jq}/bin/jq -e \
        '(.data.result.state // .data.state // .state) == "draft"' \
        /tmp/cache-stack-move.json >/dev/null
      reviewed cache-stack-remove registry cache-stack remove \
        operations/maintenance "$cache_stack_first" \
        --if-version "$cache_stack_version" >/tmp/cache-stack-remove.json
      ${pkgs.jq}/bin/jq -e \
        '(.data.result.state // .data.state // .state) == "draft"' \
        /tmp/cache-stack-remove.json >/dev/null

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
      ${pkgs.jq}/bin/jq -e \
        '.data.terminal == true
          and .data.operation.operation.state == "succeeded"' \
        /tmp/placement-replicate.json >/dev/null
      reviewed placement-repair placement repair \
        registry:operations/maintenance secondary \
        --wait --timeout 2m --if-version "$secondary_version" \
        >/tmp/placement-repair.json
      ${pkgs.jq}/bin/jq -e \
        '.data.terminal == true
          and .data.operation.operation.state == "succeeded"' \
        /tmp/placement-repair.json >/dev/null
      hub_cli placement show registry:operations/maintenance primary \
        >/tmp/placement-primary.json
      ${pkgs.jq}/bin/jq -e \
        '.data.placement.observation.state == "ready"
          and .data.placement.observation.completeness == "complete"' \
        /tmp/placement-primary.json >/dev/null
      primary_version=$(resource_version /tmp/placement-primary.json)
      hub_cli placement show registry:operations/maintenance secondary \
        >/tmp/placement-secondary.json
      ${pkgs.jq}/bin/jq -e \
        '.data.placement.observation.state == "ready"
          and .data.placement.observation.completeness == "complete"' \
        /tmp/placement-secondary.json >/dev/null
      secondary_version=$(resource_version /tmp/placement-secondary.json)
      hub_cli placement presence registry:operations/maintenance HEAD \
        --page-size 10 >/tmp/placement-presence-head.json
      ${pkgs.jq}/bin/jq -e \
        '.data.presences
          | any(.placement_name == "secondary" and .state == "present")' \
        /tmp/placement-presence-head.json >/dev/null
      sample_publication_object=$(${pkgs.jq}/bin/jq -er \
        '.data.objects[0].path' /tmp/publication-upload.json)
      hub_cli placement presence registry:operations/maintenance \
        "$sample_publication_object" --page-size 10 \
        >/tmp/placement-presence-sample.json
      ${pkgs.jq}/bin/jq -e \
        '.data.presences
          | any(.placement_name == "secondary" and .state == "present")' \
        /tmp/placement-presence-sample.json >/dev/null
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

      echo '==> Exercise binary-cache, retention, lease, and population lifecycles'
      reviewed cache-create cache create operations/build-cache \
        --name 'Operations build cache' --visibility private \
        --nix-priority 35 --compression zstd --mass-query enabled \
        >/tmp/cache-create.json
      hub_cli cache list --org operations --page-size 1 >/tmp/cache-list.json
      ${pkgs.jq}/bin/jq -e \
        '.data | tostring | contains("operations/build-cache")' \
        /tmp/cache-list.json >/dev/null
      hub_cli cache show operations/build-cache >/tmp/cache-show.json
      cache_version=$(resource_version /tmp/cache-show.json)
      reviewed cache-update cache update operations/build-cache \
        --name 'Operations production cache' --visibility internal \
        --nix-priority 30 --compression xz --mass-query disabled \
        --if-version "$cache_version" >/tmp/cache-update.json

      reviewed cache-placement-create placement add \
        cache:operations/build-cache primary \
        --binding instance-default --prefix caches/operations-build \
        --kind complete --desired-state active --read enabled \
        >/tmp/cache-placement-create.json
      cache_placement_version=$(resource_version /tmp/cache-placement-create.json)
      reviewed cache-placement-scan placement scan \
        cache:operations/build-cache primary --wait --timeout 2m \
        --if-version "$cache_placement_version" \
        >/tmp/cache-placement-scan.json
      hub_cli placement show cache:operations/build-cache primary \
        >/tmp/cache-placement-show.json
      cache_placement_version=$(resource_version /tmp/cache-placement-show.json)
      reviewed cache-placement-promote placement promote \
        cache:operations/build-cache primary \
        --if-version "$cache_placement_version" \
        >/tmp/cache-placement-promote.json

      expect_hub_error cache-integrate-unrouted 'canonical Nix-cache route is not ready' \
        cache integrate operations/build-cache \
        --registry operations/maintenance --use-for-clients \
        --retain-current-catalog --retain-channel stable \
        --retain-recent-releases 2 --retain-release 1.0.0 \
        --retain-semver '>=1.0.0,<2.0.0' --populate best-effort \
        --population-trigger manual
      hub_cli cache integrate operations/build-cache \
        --registry operations/maintenance --retain-current-catalog \
        --retain-channel stable --retain-recent-releases 2 \
        --retain-release 1.0.0 --retain-semver '>=1.0.0,<2.0.0' \
        --populate best-effort --population-trigger manual
      hub_cli cache integration list operations/build-cache --page-size 1 \
        >/tmp/cache-integration-list-empty.json

      reviewed cache-retention-set cache retention set operations/build-cache \
        --registry operations/maintenance --current-catalog --channel stable \
        --recent-releases 2 --release 1.0.0 --semver '>=1.0.0,<2.0.0' \
        --removal-grace 1h --if-version absent \
        >/tmp/cache-retention-set.json
      retention_version=$(resource_version /tmp/cache-retention-set.json)
      hub_cli cache retention list operations/build-cache --page-size 1 \
        >/tmp/cache-retention-list.json
      hub_cli cache retention roots operations/build-cache \
        --registry operations/maintenance --page-size 1 \
        >/tmp/cache-retention-roots.json
      reviewed cache-retention-refresh-invalid cache retention refresh \
        operations/build-cache --registry operations/maintenance \
        --if-version "$retention_version" \
        >/tmp/cache-retention-refresh-invalid.json
      invalid_refresh_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.result.operation.operation_id
          // .data.operation.operation_id
          // .data.result.operation_id' /tmp/cache-retention-refresh-invalid.json)
      if hub_cli operation watch "$invalid_refresh_operation_id" --timeout 30s \
        >/tmp/cache-retention-refresh-invalid-watch.json 2>&1; then
        echo 'invalid release selector refresh unexpectedly succeeded' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -Eiq \
        'failed|no complete verified artifact snapshot' \
        /tmp/cache-retention-refresh-invalid-watch.json
      reviewed cache-retention-current-only cache retention set \
        operations/build-cache --registry operations/maintenance \
        --current-catalog --removal-grace 1h \
        --if-version "$retention_version" \
        >/tmp/cache-retention-current-only.json
      retention_version=$(resource_version \
        /tmp/cache-retention-current-only.json)
      reviewed cache-retention-refresh cache retention refresh \
        operations/build-cache --registry operations/maintenance \
        --if-version "$retention_version" --wait --timeout 2m \
        >/tmp/cache-retention-refresh.json
      hub_cli cache gc policy show operations/build-cache \
        >/tmp/cache-gc-policy-before-refresh-all.json
      cache_gc_version=$(${pkgs.jq}/bin/jq -er \
        '.data.generation.resource_version' \
        /tmp/cache-gc-policy-before-refresh-all.json)
      reviewed cache-retention-refresh-all cache retention refresh \
        operations/build-cache --if-version "$cache_gc_version" \
        --wait --timeout 2m >/tmp/cache-retention-refresh-all.json

      cache_store_hash=00000000000000000000000000000000
      reviewed cache-root-create cache root create operations/build-cache \
        "$cache_store_hash" --reason 'production qualification lease' \
        --lease-until 4102444800 \
        >/tmp/cache-root-create.json
      root_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .root_id? // empty][0]' /tmp/cache-root-create.json)
      lease_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .lease_id? // empty][0]' /tmp/cache-root-create.json)
      root_version=$(resource_version /tmp/cache-root-create.json)
      hub_cli cache root list operations/build-cache --page-size 1 \
        >/tmp/cache-root-list.json
      hub_cli cache root show operations/build-cache "$root_id" \
        >/tmp/cache-root-show.json
      hub_cli cache retention explain operations/build-cache "$cache_store_hash" \
        >/tmp/cache-retention-explain.json
      reviewed cache-lease-renew cache lease renew operations/build-cache \
        "$root_id" --expires 4102448400 --if-version "$root_version" \
        >/tmp/cache-lease-renew.json
      successor_lease_id=$(${pkgs.jq}/bin/jq -er \
        '[.. | objects | .lease_id? // empty][0]' /tmp/cache-lease-renew.json)
      test "$successor_lease_id" != "$lease_id"
      hub_cli cache root show operations/build-cache "$root_id" \
        >/tmp/cache-root-after-renew.json
      successor_lease_version=$(resource_version /tmp/cache-root-after-renew.json)
      reviewed cache-lease-revoke cache lease revoke operations/build-cache \
        "$successor_lease_id" --if-version "$successor_lease_version" \
        >/tmp/cache-lease-revoke.json
      hub_cli cache root show operations/build-cache "$root_id" \
        >/tmp/cache-root-after-revoke.json
      revoked_lease_version=$(resource_version /tmp/cache-root-after-revoke.json)
      reviewed cache-root-delete cache root delete operations/build-cache \
        "$root_id" --if-version "$revoked_lease_version" \
        >/tmp/cache-root-delete.json

      reviewed cache-population-set cache population set operations/build-cache \
        --registry operations/maintenance --trigger manual --best-effort \
        --validation-gate presence --if-version absent \
        >/tmp/cache-population-set.json
      population_version=$(resource_version /tmp/cache-population-set.json)
      hub_cli cache population list operations/build-cache --page-size 1 \
        >/tmp/cache-population-list.json
      hub_cli cache coverage show operations/build-cache \
        --registry operations/maintenance >/tmp/cache-coverage-show.json
      reviewed cache-population-run cache population run operations/build-cache \
        --registry operations/maintenance --if-version "$population_version" \
        >/tmp/cache-population-run.json
      population_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.result.operation.operation_id
          // .data.operation.operation_id
          // .data.result.operation_id' /tmp/cache-population-run.json)
      hub_cli operation show "$population_operation_id" \
        >/tmp/population-operation-pending.json
      population_operation_version=$(resource_version \
        /tmp/population-operation-pending.json)
      hub_cli operation cancel "$population_operation_id" \
        --if-version "$population_operation_version" \
        >/tmp/population-operation-cancel.json
      ${pkgs.jq}/bin/jq -e \
        '.data.operation.operation.state == "cancelled"' \
        /tmp/population-operation-cancel.json >/dev/null
      population_operation_version=$(resource_version \
        /tmp/population-operation-cancel.json)
      hub_cli operation retry "$population_operation_id" \
        --if-version "$population_operation_version" \
        >/tmp/population-operation-retry.json
      ${pkgs.jq}/bin/jq -e \
        '.data.operation.operation.state == "pending"' \
        /tmp/population-operation-retry.json >/dev/null
      population_operation_version=$(resource_version \
        /tmp/population-operation-retry.json)
      hub_cli operation cancel "$population_operation_id" \
        --if-version "$population_operation_version" \
        >/tmp/population-operation-recancel.json
      reviewed cache-coverage-validate cache coverage validate \
        operations/build-cache --registry operations/maintenance \
        --if-version "$population_version" \
        >/tmp/cache-coverage-validate.json
      reviewed cache-coverage-repair cache coverage repair \
        operations/build-cache --registry operations/maintenance \
        --if-version "$population_version" \
        >/tmp/cache-coverage-repair.json
      hub_cli cache integration list operations/build-cache \
        --registry operations/maintenance >/tmp/cache-integration-list.json
      hub_cli cache integration show operations/build-cache \
        --registry operations/maintenance >/tmp/cache-integration-show.json
      reviewed cache-population-remove cache population remove \
        operations/build-cache --registry operations/maintenance \
        --if-version "$population_version" >/tmp/cache-population-remove.json
      expect_hub_error cache-retention-remove-stale \
        'retention subscription resource version is stale' \
        cache retention remove operations/build-cache \
        --registry operations/maintenance --if-version "$retention_version"
      hub_cli cache retention list operations/build-cache \
        >/tmp/cache-retention-list-current.json
      retention_version=$(${pkgs.jq}/bin/jq -er \
        '.data.subscriptions[]
          | select(.registry_id == "operations/maintenance")
          | .resource_version' /tmp/cache-retention-list-current.json)
      reviewed cache-retention-remove cache retention remove \
        operations/build-cache --registry operations/maintenance \
        --if-version "$retention_version" >/tmp/cache-retention-remove.json

      echo '==> Exercise reviewed cache garbage-collection controls'
      hub_cli cache gc policy show operations/build-cache \
        >/tmp/cache-gc-policy-show.json
      cache_gc_policy_version=$(${pkgs.jq}/bin/jq -er \
        '.data.policy.resource_version' /tmp/cache-gc-policy-show.json)
      reviewed cache-gc-policy-bounded cache gc policy set \
        operations/build-cache --unreferenced-grace 1h \
        --soft-max-bytes 1073741824 --soft-max-objects 10000 \
        --schedule 3600 --deletion-concurrency 2 \
        --retry-initial 10s --retry-max 5m --retry-max-attempts 5 \
        --tombstone-retention 24h --if-version "$cache_gc_policy_version" \
        >/tmp/cache-gc-policy-bounded.json
      cache_gc_policy_version=$(${pkgs.jq}/bin/jq -er \
        '.data.result.policy.resource_version' /tmp/cache-gc-policy-bounded.json)
      reviewed cache-gc-policy-unbounded cache gc policy set \
        operations/build-cache --unreferenced-grace 2h \
        --clear-soft-max-bytes --clear-soft-max-objects \
        --schedule 7200 --deletion-concurrency 4 \
        --retry-initial 30s --retry-max 10m --retry-max-attempts 8 \
        --tombstone-retention 48h --if-version "$cache_gc_policy_version" \
        >/tmp/cache-gc-policy-unbounded.json
      ${pkgs.jq}/bin/jq -e \
        '.data.result.policy.soft_max_bytes == null and .data.result.policy.soft_max_objects == null' \
        /tmp/cache-gc-policy-unbounded.json >/dev/null

      expect_hub_error cache-gc-missing-retained-inventory \
        'retained root.*is absent from the active cache inventory' \
        cache gc plan create operations/build-cache

      reviewed cache-gc-control-create cache create operations/gc-control-cache \
        --name 'GC control qualification cache' --visibility private \
        --nix-priority 40 --compression zstd --mass-query enabled \
        >/tmp/cache-gc-control-create.json
      hub_cli_into /tmp/cache-gc-control-bootstrap-plan.json \
        cache gc plan create operations/gc-control-cache
      gc_control_bootstrap_plan_id=$(${pkgs.jq}/bin/jq -er \
        '.data.plan.plan_id' /tmp/cache-gc-control-bootstrap-plan.json)
      hub_cli_into /tmp/cache-gc-control-bootstrap-plan-show.json \
        cache gc plan show operations/gc-control-cache \
        "$gc_control_bootstrap_plan_id"
      hub_cli_into /tmp/cache-gc-control-ack-plan.json \
        cache gc first-sweep plan-acknowledgement \
        operations/gc-control-cache \
        --gc-plan-id "$gc_control_bootstrap_plan_id" \
        --idempotency-key cache-gc-control-first-sweep-plan
      gc_control_ack_plan_id=$(${pkgs.jq}/bin/jq -er \
        '.data.plan.plan_id' /tmp/cache-gc-control-ack-plan.json)
      gc_control_ack_hash=$(${pkgs.jq}/bin/jq -er \
        '.data.plan.confirmation_hash' /tmp/cache-gc-control-ack-plan.json)
      hub_cli_into /tmp/cache-gc-control-acknowledge.json \
        cache gc first-sweep acknowledge operations/gc-control-cache \
        --ack-plan-id "$gc_control_ack_plan_id" \
        --confirm-hash "$gc_control_ack_hash" \
        --idempotency-key cache-gc-control-first-sweep-apply --yes

      hub_cli_into /tmp/cache-gc-run-plan.json \
        cache gc plan create operations/gc-control-cache
      gc_run_plan_id=$(${pkgs.jq}/bin/jq -er \
        '.data.plan.plan_id' /tmp/cache-gc-run-plan.json)
      gc_run_hash=$(${pkgs.jq}/bin/jq -er \
        '.data.plan.confirmation_hash' /tmp/cache-gc-run-plan.json)
      hub_cli cache gc run operations/gc-control-cache \
        --plan-id "$gc_run_plan_id" --confirm-hash "$gc_run_hash" \
        --idempotency-key cache-gc-run --yes \
        >/tmp/cache-gc-run.json
      gc_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.operation.operation_id' /tmp/cache-gc-run.json)
      hub_cli cache gc runs list operations/gc-control-cache --page-size 1 \
        >/tmp/cache-gc-runs-list.json
      hub_cli cache gc runs show operations/gc-control-cache "$gc_operation_id" \
        >/tmp/cache-gc-runs-show.json
      hub_cli cache gc runs watch operations/gc-control-cache "$gc_operation_id" \
        --timeout 30s >/tmp/cache-gc-runs-watch.json
      ${pkgs.jq}/bin/jq -e '.data.terminal == true' \
        /tmp/cache-gc-runs-watch.json >/dev/null
      hub_cli cache gc jobs list operations/gc-control-cache "$gc_operation_id" \
        --page-size 1 >/tmp/cache-gc-jobs-list.json
      ${pkgs.jq}/bin/jq -e '(.data.jobs // []) == []' \
        /tmp/cache-gc-jobs-list.json >/dev/null
      expect_hub_error cache-gc-job-show-missing 'not found' \
        cache gc jobs show operations/gc-control-cache missing-job
      reviewed_apply_error cache-gc-job-retry-missing 'not found' \
        cache gc jobs retry operations/gc-control-cache missing-job \
        --if-version 0
      expect_hub_error cache-gc-job-abandon-missing 'not found' \
        cache gc jobs abandon operations/gc-control-cache missing-job \
        --if-version absent --plan --idempotency-key missing-job-abandon

      reviewed cache-eviction-placement-create placement add \
        cache:operations/gc-control-cache eviction-target \
        --binding instance-default --prefix caches/gc-control-eviction \
        --kind complete --desired-state active --read disabled \
        >/tmp/cache-eviction-placement-create.json
      hub_cli placement show cache:operations/gc-control-cache eviction-target \
        >/tmp/cache-eviction-placement-show.json
      eviction_placement_version=$(resource_version \
        /tmp/cache-eviction-placement-show.json)
      hub_cli placement eviction plan cache:operations/gc-control-cache \
        eviction-target --if-version "$eviction_placement_version" \
        --idempotency-key cache-placement-eviction-plan \
        >/tmp/cache-placement-eviction-plan.json
      eviction_plan_id=$(${pkgs.jq}/bin/jq -er .data.plan.plan_id \
        /tmp/cache-placement-eviction-plan.json)
      eviction_plan_hash=$(${pkgs.jq}/bin/jq -er .data.plan.confirmation_hash \
        /tmp/cache-placement-eviction-plan.json)
      hub_cli placement eviction run --plan-id "$eviction_plan_id" \
        --confirm-hash "$eviction_plan_hash" --yes \
        --idempotency-key cache-placement-eviction-run \
        >/tmp/cache-placement-eviction-run.json
      eviction_operation_id=$(${pkgs.jq}/bin/jq -er \
        '.data.operation.operation_id' /tmp/cache-placement-eviction-run.json)
      hub_cli operation show "$eviction_operation_id" \
        >/tmp/cache-placement-eviction-operation.json
      eviction_operation_version=$(resource_version \
        /tmp/cache-placement-eviction-operation.json)
      hub_cli operation cancel "$eviction_operation_id" \
        --if-version "$eviction_operation_version" \
        >/tmp/cache-placement-eviction-cancel.json
      hub_cli placement show cache:operations/gc-control-cache eviction-target \
        >/tmp/cache-eviction-placement-draining.json
      eviction_placement_version=$(resource_version \
        /tmp/cache-eviction-placement-draining.json)
      reviewed cache-eviction-placement-remove placement remove \
        cache:operations/gc-control-cache eviction-target \
        --if-version "$eviction_placement_version" \
        >/tmp/cache-eviction-placement-remove.json
      hub_cli cache show operations/gc-control-cache \
        >/tmp/cache-gc-control-before-delete.json
      gc_control_cache_version=$(resource_version \
        /tmp/cache-gc-control-before-delete.json)
      reviewed cache-gc-control-delete cache delete operations/gc-control-cache \
        --if-version "$gc_control_cache_version" \
        >/tmp/cache-gc-control-delete.json

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
          '.data.terminal == true
            and (.data.operation.operation.state
              | IN("succeeded", "failed", "cancelled"))' \
          /tmp/domain-verify-watch.json >/dev/null
      else
        ${pkgs.jq}/bin/jq -e \
          'select(.kind == "watch_operation_response")
            | .data.terminal == true
              and .data.operation.operation.state == "failed"' \
          /tmp/domain-verify-watch.json >/dev/null
        ${pkgs.grep}/bin/grep -Fq \
          'domain verification requires exactly one desired HTTPS/443 terminator' \
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
      reviewed disposable-registry-create registry create --org analytics \
        --name disposable --visibility private \
        >/tmp/disposable-registry-create.json
      hub_cli registry show analytics/disposable \
        >/tmp/disposable-registry-show.json
      disposable_registry_version=$(resource_version \
        /tmp/disposable-registry-show.json)
      reviewed disposable-registry-delete registry delete analytics/disposable \
        --if-version "$disposable_registry_version" \
        >/tmp/disposable-registry-delete.json
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
      if hub_cli operation watch "$credential_operation_id" --timeout 10s \
        >/tmp/credential-operation-watch.json 2>&1; then
        echo 'unreachable S3 credential validation unexpectedly succeeded' >&2
        exit 1
      fi
      ${pkgs.jq}/bin/jq -e \
        'select(.kind == "watch_operation_response")
          | .data.terminal == true
            and .data.operation.operation.state == "failed"
            and (.data.operation.error | length > 0)' \
        /tmp/credential-operation-watch.json >/dev/null
      ${pkgs.grep}/bin/grep -Eq 'Hub operation .* failed' \
        /tmp/credential-operation-watch.json

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
        | ${pkgs.jq}/bin/jq -e \
          '.data | tostring | contains("qualification-grep")' >/dev/null

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
