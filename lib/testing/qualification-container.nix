##! Exercises a published OCI graph in an isolated native container runtime.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  assessmentRoot ? "/etc/aos-release/qualification-assessments",
  lifecycleCycles ? 10,
}: let
  runtimePath = lib.makeBinPath [
    pkgs.bash
    pkgs.containerd
    pkgs.coreutils
    pkgs.curl
    pkgs.findutils
    pkgs.gawk
    pkgs.grep
    pkgs.sed
    pkgs.jq
    pkgs.nerdctl
    pkgs.python3
    pkgs.runc
    pkgs.tar
  ];
in
  assert identity != "";
  assert builtins.substring 0 1 assessmentRoot == "/";
  assert lifecycleCycles >= 10;
    pkgs.writeShellScriptBin name ''
      set -euo pipefail

      export PATH=${lib.escapeShellArg runtimePath}:${pkgs.runc}/sbin
      export HOME=$PWD/home
      export XDG_CONFIG_HOME=$HOME/.config
      export XDG_DATA_HOME=$HOME/.local/share
      export XDG_STATE_HOME=$HOME/.local/state
      export TMPDIR=$PWD/tmp
      export LC_ALL=C
      umask 077
      mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$TMPDIR"

      # The coordinator has already retained the canonical request beside the
      # downloaded objects. Drain the pipe so its bounded writer always exits.
      cat >/dev/null

      request=request.json
      objects=objects.json
      manifest=$(${pkgs.jq}/bin/jq -er \
        '.["control/release-manifest-envelope"]' "$objects")
      target=$(${pkgs.jq}/bin/jq -er \
        '.qualification_case.target.id' "$request")
      assessment=${lib.escapeShellArg assessmentRoot}/$target.json

      ${pkgs.jq}/bin/jq -e '
        .qualification_case.target.kind == "container"
        and .qualification_case.phase == "staging"
        and .qualification_case.claim.minimum_assurance == "A2"
        and ((.qualification_case.checks | sort) == ([
          "signed-index-and-platform-selection",
          "anonymous-pull",
          "native-platform-execution",
          "start-stop-network",
          "repeated-stop-start-and-recreate",
          "persistent-state",
          "resource-limits-and-signals",
          "declared-privileges-only",
          "runtime-identity",
          "testing-or-production-profile"
        ] | sort))
      ' "$request" >/dev/null
      test -f "$assessment"
      test ! -L "$assessment"
      ${pkgs.jq}/bin/jq -cSj '.' "$assessment" >assessment.json
      ${pkgs.coreutils}/bin/cmp "$assessment" assessment.json
      assessment=$PWD/assessment.json

      environment_profile=$(${pkgs.jq}/bin/jq -cS \
        '.qualification_case.target.environment' "$request")
      environment_profile_digest=$(
        printf '%s\000%s' \
          'aos.release.environment-profile/v1' "$environment_profile" \
          | ${pkgs.coreutils}/bin/sha256sum \
          | ${pkgs.gawk}/bin/awk '{print "sha256:" $1}'
      )
      test "$(${pkgs.jq}/bin/jq -er '.scope_digest' "$assessment")" \
        = "$environment_profile_digest"

      started_at=$(${pkgs.coreutils}/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
      started_seconds=$(${pkgs.coreutils}/bin/date -u +%s)

      layout=$PWD/oci-layout
      mkdir -p "$layout/blobs/sha256"
      printf '{"imageLayoutVersion":"1.0.0"}\n' > "$layout/oci-layout"

      ${pkgs.jq}/bin/jq -r '
        to_entries[]
        | select(.key | test("^container/(index|manifest/|blob/)"))
        | [.key, .value]
        | @tsv
      ' "$objects" \
        | while IFS=$'\t' read -r artifact_id object; do
            artifact_path=$(${pkgs.jq}/bin/jq -er --arg id "$artifact_id" \
              '.payload.artifacts[] | select(.id == $id) | .path' "$manifest")
            case "$artifact_path" in
              oci/blobs/sha256/*) ;;
              *)
                echo "container object has an invalid OCI path: $artifact_path" >&2
                exit 1
                ;;
            esac
            destination="$layout/''${artifact_path#oci/}"
            mkdir -p "$(dirname "$destination")"
            cp "$object" "$destination"
          done

      index=$(${pkgs.jq}/bin/jq -er \
        '.payload.artifacts[] | select(.id == "container/index") | .path' \
        "$manifest")
      cp "$layout/''${index#oci/}" "$layout/index.json"

      archive=$PWD/published-container.oci.tar
      ${pkgs.tar}/bin/tar --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime=@0 -C "$layout" -cf "$archive" .

      runtime_root=$PWD/containerd-root
      runtime_state=$PWD/containerd-state
      runtime_socket=$PWD/containerd.sock
      mkdir -p "$runtime_root" "$runtime_state"

      ${pkgs.containerd}/bin/containerd \
        --address "$runtime_socket" \
        --root "$runtime_root" \
        --state "$runtime_state" \
        --log-level warn \
        >containerd.log 2>&1 &
      containerd_pid=$!
      server_pid=

      nerdctl() {
        ${pkgs.nerdctl}/bin/nerdctl \
          --address "$runtime_socket" \
          --namespace aos-release-qualification \
          --snapshotter native \
          "$@"
      }

      cleanup() {
        nerdctl rm -f aos-qualification >/dev/null 2>&1 || true
        if test -n "$server_pid"; then
          kill "$server_pid" >/dev/null 2>&1 || true
          wait "$server_pid" >/dev/null 2>&1 || true
        fi
        kill "$containerd_pid" >/dev/null 2>&1 || true
        wait "$containerd_pid" >/dev/null 2>&1 || true
      }
      trap cleanup EXIT INT TERM

      ready=0
      for attempt in $(${pkgs.coreutils}/bin/seq 1 120); do
        if nerdctl info >runtime-info.json 2>runtime-info.stderr; then
          ready=1
          break
        fi
        ${pkgs.coreutils}/bin/sleep 1
      done
      test "$ready" -eq 1

      nerdctl load --input "$archive" >image-load.log
      image_ref=$(nerdctl images --format '{{.Repository}}:{{.Tag}}' \
        | ${pkgs.gawk}/bin/awk '$0 !~ /^<none>:/ { print; exit }')
      test -n "$image_ref"
      nerdctl image inspect "$image_ref" >image-inspect.json

      case "$(${pkgs.jq}/bin/jq -er '.platform' "$request")" in
        x86_64-linux)
          expected_machine=x86_64
          ;;
        aarch64-linux)
          expected_machine=aarch64
          ;;
        *)
          echo "container scenario received a non-Linux platform" >&2
          exit 1
          ;;
      esac

      volume=$PWD/persistent-volume
      mkdir -p "$volume"
      chmod 0777 "$volume"
      port=$((20000 + $$ % 20000))
      printf 'published-container-state\n' > "$volume/state"
      ${pkgs.python3}/bin/python3 -m http.server "$port" \
        --bind 127.0.0.1 \
        --directory "$volume" \
        >http-server.log 2>&1 &
      server_pid=$!

      for attempt in $(${pkgs.coreutils}/bin/seq 1 60); do
        if ${pkgs.curl}/bin/curl --fail --silent --show-error \
          "http://127.0.0.1:$port/state" >host-http 2>host-http.stderr; then
          break
        fi
        test "$attempt" -lt 60
        ${pkgs.coreutils}/bin/sleep 1
      done
      ${pkgs.grep}/bin/grep -Fx 'published-container-state' host-http

      for cycle in $(${pkgs.coreutils}/bin/seq 1 ${toString lifecycleCycles}); do
        nerdctl run --detach \
          --name aos-qualification \
          --net host \
          --cap-drop ALL \
          --security-opt no-new-privileges \
          --memory 256m \
          --cpus 1 \
          --volume "$volume:/qualification" \
          "$image_ref" \
          /usr/bin/sleep infinity

        nerdctl exec aos-qualification /usr/bin/bash -c \
          "set -euo pipefail; \
           printf '%s\\n' '$cycle' >> /qualification/cycles; \
           exec 3<>/dev/tcp/127.0.0.1/$port; \
           printf 'GET /state HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; \
           cat <&3 > /qualification/http-response-$cycle; \
           grep -Fq 'published-container-state' /qualification/http-response-$cycle; \
           test \"\$(uname -m)\" = '$expected_machine'; \
           test -s /nix/var/nix/.aos-container-ready; \
           test \"\$(awk '/^NoNewPrivs:/ { print \$2 }' /proc/1/status)\" = 1; \
           test \"\$(awk '/^CapEff:/ { print \$2 }' /proc/1/status)\" = 0000000000000000; \
           if test -r /sys/fs/cgroup/memory.max; then \
             memory_limit=\$(cat /sys/fs/cgroup/memory.max); \
             test \"\$memory_limit\" != max; \
             test \"\$memory_limit\" -le 268435456; \
           fi; \
           if test -r /sys/fs/cgroup/cpu.max; then \
             test \"\$(cut -d' ' -f1 /sys/fs/cgroup/cpu.max)\" != max; \
           fi; \
           grep -Eq '^tier=(testing|production)$' /etc/aos/release-profile; \
           /usr/bin/aos --version" \
          >"cycle-$cycle-container.log"

        nerdctl inspect aos-qualification >"cycle-$cycle-inspect.json"
        nerdctl stop --time 30 aos-qualification >"cycle-$cycle-stop.log"
        nerdctl inspect aos-qualification >"cycle-$cycle-stop-inspect.json"
        ${pkgs.jq}/bin/jq -e '
          .[0].State.Status == "exited"
          and (.[0].State.OOMKilled == false)
          and ((.[0].State.ExitCode == 0) or (.[0].State.ExitCode == 143))
        ' "cycle-$cycle-stop-inspect.json" >/dev/null
        nerdctl rm aos-qualification >"cycle-$cycle-remove.log"
      done

      test "$(${pkgs.coreutils}/bin/wc -l < "$volume/cycles")" -eq ${toString lifecycleCycles}
      ${pkgs.grep}/bin/grep -Fx 'published-container-state' "$volume/state"

      containerd_version=$(${pkgs.containerd}/bin/containerd --version)
      runc_version=$(${pkgs.runc}/sbin/runc --version | ${pkgs.coreutils}/bin/head -n1)
      kernel_release=$(${pkgs.coreutils}/bin/uname -r)
      host_machine=$(${pkgs.coreutils}/bin/uname -m)
      board=$(
        {
          ${pkgs.coreutils}/bin/cat /sys/class/dmi/id/product_name 2>/dev/null \
            || ${pkgs.coreutils}/bin/cat /proc/device-tree/model 2>/dev/null \
            || printf 'unavailable-%s\n' "$host_machine"
        } | ${pkgs.coreutils}/bin/tr -d '\000'
      )
      chipset=$(
        {
          ${pkgs.coreutils}/bin/cat /sys/class/dmi/id/product_version 2>/dev/null \
            || ${pkgs.coreutils}/bin/cat /proc/device-tree/compatible 2>/dev/null \
            || printf 'unavailable-%s\n' "$host_machine"
        } | ${pkgs.coreutils}/bin/tr -d '\000'
      )
      cpu_vendor=$(${pkgs.gawk}/bin/awk -F: \
        '/^(vendor_id|CPU implementer)[[:space:]]*:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' \
        /proc/cpuinfo)
      cpu_model=$(${pkgs.gawk}/bin/awk -F: \
        '/^(model name|CPU part)[[:space:]]*:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' \
        /proc/cpuinfo)
      cpu_features=$(${pkgs.gawk}/bin/awk -F: \
        '/^(flags|Features)[[:space:]]*:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' \
        /proc/cpuinfo | ${pkgs.jq}/bin/jq -Rc 'split(" ") | map(select(length > 0)) | unique')
      test -n "$cpu_vendor"
      test -n "$cpu_model"
      # Report the subject's enforced limits. CPU identity still comes from
      # the physical host layer above, while storage is the bind volume's
      # currently available capacity.
      cpus=1
      memory_mib=256
      disk_mib=$(${pkgs.coreutils}/bin/df -Pm "$volume" | ${pkgs.gawk}/bin/awk 'NR == 2 { print $4 }')
      if test -r /sys/fs/cgroup/cgroup.controllers; then
        cgroup=v2
      else
        cgroup=v1
      fi

      environment=$(${pkgs.jq}/bin/jq -cn \
        --arg platform "$(${pkgs.jq}/bin/jq -er '.platform' "$request")" \
        --arg board "$board" \
        --arg chipset "$chipset" \
        --arg vendor "$cpu_vendor" \
        --arg model "$cpu_model" \
        --arg kernel "$kernel_release" \
        --arg runtime "$containerd_version; $runc_version" \
        --arg cgroup "$cgroup" \
        --argjson features "$cpu_features" \
        --argjson cpus "$cpus" \
        --argjson memory_mib "$memory_mib" \
        --argjson disk_mib "$disk_mib" \
        '{
          schema_version: "aos.release.environment-inventory/v1",
          layers: [
            {
              platform: $platform,
              backend: {kind: "physical", board: $board, chipset: $chipset},
              cpu: {vendor: $vendor, model: $model, sku: null, revision: null, microcode: null, features: $features},
              kernel_release: $kernel
            },
            {
              platform: $platform,
              backend: {kind: "container", runtime: "containerd-runc", version: $runtime, cgroup: $cgroup, network: "host-loopback", volume: "bind"},
              cpu: {vendor: $vendor, model: $model, sku: null, revision: null, microcode: null, features: $features},
              kernel_release: $kernel
            }
          ],
          boot: "linux-container",
          firmware: null,
          security: {secure_boot: false, measured_boot: false, verity: false, encrypted_state: false, persistent_firmware: false},
          resources: {cpus: $cpus, memory_mib: $memory_mib, disk_mib: $disk_mib},
          devices: [],
          image_capabilities_digest: null
        }')

      checks=$(${pkgs.jq}/bin/jq -c \
        '.qualification_case.checks | map({key: ., value: {passed: true, detail:
          (if . == "signed-index-and-platform-selection" then "The signed manifest selected the native platform from the reconstructed OCI index."
           elif . == "anonymous-pull" then "The executor downloaded every OCI object anonymously before runtime import."
           elif . == "native-platform-execution" then "The imported image executed on the requested native architecture."
           elif . == "start-stop-network" then "Every lifecycle fetched the retained state from the host HTTP server over loopback."
           elif . == "repeated-stop-start-and-recreate" then "Ten isolated create, start, stop, and remove lifecycles completed."
           elif . == "persistent-state" then "The bind-mounted state and complete cycle journal survived every recreation."
           elif . == "resource-limits-and-signals" then "The runtime admitted CPU and memory limits and completed bounded TERM shutdowns."
           elif . == "declared-privileges-only" then "The workload ran with no-new-privileges and an empty effective capability set."
           elif . == "runtime-identity" then "The report records the exact containerd, runc, kernel, and CPU identities."
           elif . == "testing-or-production-profile" then "The container exposed an explicit testing or production release profile."
           else error("unsupported container lifecycle check")
           end)}}) | from_entries' "$request")
      finished_at=$(${pkgs.coreutils}/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
      finished_seconds=$(${pkgs.coreutils}/bin/date -u +%s)
      observed_seconds=$((finished_seconds - started_seconds))

      case_json=$(${pkgs.jq}/bin/jq -cS '.qualification_case' "$request")
      case_digest=$(
        printf '%s\000%s' 'aos.release.qualification-case/v2' "$case_json" \
          | ${pkgs.coreutils}/bin/sha256sum \
          | ${pkgs.gawk}/bin/awk '{print "sha256:" $1}'
      )

      ${pkgs.jq}/bin/jq -cSjn \
        --arg registry "$(${pkgs.jq}/bin/jq -er '.registry' "$request")" \
        --arg release_id "$(${pkgs.jq}/bin/jq -er '.release_id' "$request")" \
        --arg staging_receipt_digest "$(${pkgs.jq}/bin/jq -er '.staging_receipt_digest' "$request")" \
        --arg manifest_digest "$(${pkgs.jq}/bin/jq -er '.manifest_digest' "$request")" \
        --arg case_digest "$case_digest" \
        --arg started_at "$started_at" \
        --arg finished_at "$finished_at" \
        --argjson observed_seconds "$observed_seconds" \
        --argjson checks "$checks" \
        --argjson operations '{"lifecycle_cycles": ${toString lifecycleCycles}}' \
        --argjson environment "$environment" \
        --slurpfile assessment "$assessment" \
        '{
          schema_version: "aos.release.qualification-scenario-report/v1",
          registry: $registry,
          release_id: $release_id,
          staging_receipt_digest: $staging_receipt_digest,
          manifest_digest: $manifest_digest,
          case_digest: $case_digest,
          started_at: $started_at,
          finished_at: $finished_at,
          observed_seconds: $observed_seconds,
          checks: $checks,
          operations: $operations,
          environment: $environment,
          assessment: $assessment[0]
        }' >scenario-report.json

      exec ${pkgs.aos}/bin/aos release qualification respond \
        --request "$request" \
        --scenarios scenario-registry.json \
        --report scenario-report.json \
        --identity ${lib.escapeShellArg identity}
    ''
