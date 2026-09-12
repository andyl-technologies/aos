{
  lib,
  pkgs,
}: let
  k3sModprobe = pkgs.writeShellScriptBin "modprobe" ''
    set -eu

    handled=false
    for arg in "$@"; do
      case "$arg" in
        -*)
          ;;
        nft-expr-counter)
          handled=true
          ;;
        *)
          handled=false
          break
          ;;
      esac
    done
    if [ "$handled" = true ]; then
      exit 0
    fi

    exec ${pkgs.kmod}/sbin/modprobe "$@"
  '';
in {
  runtimePath = [
    pkgs.k3s
    pkgs.containerd # provides containerd-shim-runc-v2
    pkgs.runc
    pkgs.cni-plugins # bridge, host-local, portmap, loopback
    pkgs.iptables # kube-proxy iptables mode + kube-router netpol
    pkgs.ipset # k3s netpol controller
    pkgs.conntrack-tools
    pkgs.socat
    pkgs.ethtool
    pkgs.iproute2
    pkgs.util-linux # mount/umount/findmnt
    # Linux 6.18 folds the nft counter expression into nf_tables core, but
    # kube-proxy still probes its historical loadable alias.
    k3sModprobe
    pkgs.kmod # modprobe/lsmod
    pkgs.coreutils
    pkgs.jq
  ];
  # Note: `pkgs.nftables` is intentionally NOT here. It's the
  # host-firewall tool (consumed by `nftables.service` from
  # `modules/security/firewall.nix`); k3s itself only needs
  # `iptables`. Including nftables would also make k3s's
  # iptables-availability probe potentially auto-detect nftables
  # mode in some k3s versions — best avoided.

  kernelModules = [
    "br_netfilter"
    "vxlan" # flannel default (VXLAN) backend
    "ip_set" # k3s netpol controller
  ];

  # Forwarding + bridge call-iptables. `bridge.bridge-nf-call-*`
  # only exist once br_netfilter is loaded; the stock
  # systemd-sysctl.service is ordered After=systemd-modules-load.service,
  # so as long as br_netfilter is in the module list above it loads
  # first and these keys are writable when systemd-sysctl runs.
  sysctls = {
    "net.ipv4.ip_forward" = "1";
    "net.ipv6.conf.all.forwarding" = "1";
    "net.bridge.bridge-nf-call-iptables" = "1";
    "net.bridge.bridge-nf-call-ip6tables" = "1";
  };

  enabledCheck = role:
    pkgs.writeShellScriptBin "k3s-${role}-enabled" ''
      set -eu

      [ "''${K3S_ENABLED:-false}" = true ]
    '';

  preflightService = role: required: let
    checks =
      lib.concatMapStringsSep "\n" (varName: ''
        : "''${${varName}:?[k3s-preflight] ${role}: ${varName} must be set in /etc/aos/packages/${role}/k3s.env}"
      '')
      required;
  in {
    description = "Pre-flight checks for ${role}";

    # `wantedBy` + `before` schedule preflight first under
    # `multi-user.target`; the matching `requisite` /
    # `after = [...preflight.service]` sit on the role's
    # `k3s.service` (declared inline per role, since k3s.service
    # itself diverges between roles in `ExecStart` and ports).
    wantedBy = ["multi-user.target"];
    before = ["k3s.service"];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      EnvironmentFile = "-/etc/aos/packages/${role}/k3s.env";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };

    script = ''
      set -eu

      if [ "''${K3S_ENABLED:-false}" != true ]; then
        echo "[k3s-preflight] ${role}: disabled, skipping checks"
        exit 0
      fi

      ${checks}

      echo "[k3s-preflight] ${role}: required env present, k3s may start"
    '';
  };

  addonRenderer = package: role:
    pkgs.writeShellScriptBin "${package}-render-addons" ''
      set -eu

      input=$1
      output=$2
      revision_output=$3

      validated_document=$(${pkgs.jq}/bin/jq -ceS \
        --arg role ${lib.escapeShellArg role} '
          def exact_keys($expected):
            type == "object" and ((keys | sort) == ($expected | sort));

          def canonical_value:
            if type == "null" or type == "boolean" or type == "string"
            then true
            elif type == "number"
            then tostring | test("^-?(0|[1-9][0-9]*)$")
            elif type == "array" or type == "object"
            then all(.[]; canonical_value)
            else false
            end;

          def canonicalize:
            if type == "array"
            then map(canonicalize)
            elif type == "object"
            then with_entries(.value |= canonicalize)
            else .
            end;

          select(exact_keys(["resources", "revision", "role", "schema"]))
          | select(.schema == "aos.kubernetes-resources/v2")
          | select(.role == $role)
          | select(.revision | test("^sha256:[0-9a-f]{64}$"))
          | select(.resources | type == "array")
          | select(.resources | all(
              exact_keys(["name", "object", "priority", "revision"])
              and (.name | type == "string" and length > 0)
              and (.priority | type == "number" and floor == . and . >= 0 and . <= 999)
              and (.revision | type == "string" and test("^sha256:[0-9a-f]{64}$"))
              and (.object | exact_keys(["apiVersion", "kind", "metadata", "spec"]))
              and (.object.apiVersion | type == "string" and length > 0)
              and (.object.kind | type == "string" and length > 0)
              and (.object.metadata | exact_keys(
                if has("namespace")
                then ["name", "namespace"]
                else ["name"]
                end
              ))
              and (.object.metadata.name | type == "string" and length > 0)
              and ((.object.metadata.namespace // "") | type == "string")
              and (.object.spec | type == "object" and canonical_value)
            ))
          | canonicalize
        ' "$input")

      canonical_payload=$(printf '%s' "$validated_document" \
        | ${pkgs.jq}/bin/jq -ceS '{ schema, role, resources }')
      declared_revision=$(printf '%s' "$validated_document" \
        | ${pkgs.jq}/bin/jq -er '.revision')
      actual_revision="sha256:$(printf '%s' "$canonical_payload" \
        | ${pkgs.coreutils}/bin/sha256sum \
        | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)"
      if [ "$actual_revision" != "$declared_revision" ]; then
        echo "[k3s] ${package}: add-on revision does not match its canonical payload" >&2
        exit 1
      fi

      resource_count=$(printf '%s' "$canonical_payload" \
        | ${pkgs.jq}/bin/jq -er '.resources | length')
      resource_index=0
      while [ "$resource_index" -lt "$resource_count" ]; do
        object_payload=$(printf '%s' "$canonical_payload" \
          | ${pkgs.jq}/bin/jq -ceS --argjson index "$resource_index" \
            '.resources[$index].object')
        declared_object_revision=$(printf '%s' "$canonical_payload" \
          | ${pkgs.jq}/bin/jq -er --argjson index "$resource_index" \
            '.resources[$index].revision')
        actual_object_revision="sha256:$(printf '%s' "$object_payload" \
          | ${pkgs.coreutils}/bin/sha256sum \
          | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)"
        if [ "$actual_object_revision" != "$declared_object_revision" ]; then
          echo "[k3s] ${package}: Kubernetes object revision does not match its canonical payload" >&2
          exit 1
        fi

        resource_index=$((resource_index + 1))
      done

      printf '%s' "$canonical_payload" | ${pkgs.jq}/bin/jq -cer '
        .resources
        | map(
            . as $resource
            | .object
            | .metadata.annotations = (
                (.metadata.annotations // {})
                + {"aos.andyl.com/object-revision": $resource.revision}
              )
            | tojson + "\n---\n"
          )
        | join("")
      ' > "$output"
      printf '%s\n' "$declared_revision" > "$revision_output"
    '';

  launcher = role: command: addonRenderer:
    pkgs.writeShellScriptBin "k3s-${role}-start" ''
      set -eu

      # The package check uses this side-effect-free path to prove that this
      # exact production launcher executes its retained k3s payload.
      if [ "''${1:-}" = verify-payload ]; then
        [ "$#" -eq 2 ]
        [ "$2" = ${lib.escapeShellArg "${pkgs.k3s}/bin/k3s"} ]
        "$2" --version >/dev/null
        printf '%s\n' k3s-payload-ok
        exit 0
      fi

      : "''${CREDENTIALS_DIRECTORY:?[k3s] ${role}: token credential was not loaded}"
      token_file="$CREDENTIALS_DIRECTORY/token"
      if [ ! -r "$token_file" ]; then
        echo "[k3s] ${role}: token credential is not readable" >&2
        exit 1
      fi

      export K3S_TOKEN_FILE="$token_file"

      case ${lib.escapeShellArg command} in
      server*)
        addons=/etc/aos/packages/${role}/addons.json
        destination=/var/lib/rancher/k3s/server/manifests/aos-runtime-addons.yaml
        temporary="$destination.tmp"
        revision_destination=/var/lib/rancher/k3s/server/aos-runtime-addons.revision
        revision_temporary="$revision_destination.tmp"
        ${pkgs.coreutils}/bin/mkdir -p "''${destination%/*}"
        ${addonRenderer}/bin/${role}-render-addons \
          "$addons" \
          "$temporary" \
          "$revision_temporary"
        ${pkgs.coreutils}/bin/mv -f "$temporary" "$destination"
        ${pkgs.coreutils}/bin/mv -f "$revision_temporary" "$revision_destination"
        ;;
      esac

      exec ${pkgs.k3s}/bin/k3s ${command} "$@"
    '';
}
