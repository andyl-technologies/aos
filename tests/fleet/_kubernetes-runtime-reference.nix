##! Shared signed-package registry and K3s runtime for Kubernetes native activation.
{
  lib,
  mkSystem,
  pkgs,
  guestTools ? false,
  transitionTransform ? transition: transition,
}: let
  packageSet = import ../abilities/reference-kubernetes/package.nix {
    inherit lib;
    inherit (pkgs) mkDerivation;
    kubernetesRuntime = pkgs.kubectl;
    systemdRuntime = pkgs.aos.packageRuntime;
    inherit transitionTransform;
  };

  orderedPackages = [
    {
      name = "ability-reference-cilium";
      package = packageSet.cilium;
    }
    {
      name = "ability-reference-k3s";
      package = packageSet.k3s;
    }
    {
      name = "ability-reference-kubernetes-terminal";
      package = packageSet.kubernetes;
    }
    {
      name = "ability-reference-longhorn";
      package = packageSet.longhorn;
    }
    {
      name = "ability-reference-systemd-bootstrap";
      package = packageSet.systemd;
    }
  ];

  packageRoots = lib.concatMap (entry: [entry.package entry.package.abilities]) orderedPackages;
  emptyAddonPayload = {
    schema = "aos.kubernetes-resources/v2";
    role = "combined";
    resources = [];
  };
  emptyAddons =
    emptyAddonPayload
    // {
      revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON emptyAddonPayload)}";
  };

  runtimeModule = {
    aos.packages.k3s-combined = {
      package = pkgs.k3s-combined;
      bundle = true;
      preset = false;
    };

    environment.etc = {
      "aos/packages/k3s-combined/k3s.env".text = ''
        K3S_ENABLED=true
        K3S_NODE_NAME=ability-runtime
        K3S_NODE_IP=192.168.50.10
        K3S_FLANNEL_IFACE=eth0
        K3S_KUBECONFIG_MODE=0600
        K3S_DISABLE=traefik,servicelb,metrics-server
      '';
      "aos/packages/k3s-combined/addons.json".text = builtins.toJSON emptyAddons;
      "tmpfiles.d/ability-kubernetes.conf".text = ''
        d /var/cache/aos-ability-evaluator-fixture 0700 root root - -
        d /run/credstore 0700 root root - -
        d /run/credstore/k3s-combined 0700 root root - -
      '';
    };

    systemd.services.aos-kubernetes-matrix-foreign = {
      description = "Disposable foreign unit for Kubernetes effect qualification";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  };
  runtimeModules = [
    ../../systems/server-test.nix
    runtimeModule
  ];
  runtimeSystem = mkSystem runtimeModules;
  qualificationSetupBody = ''
    aos.packages.k3s-combined = {
      package = pkgs.k3s-combined;
      bundle = true;
      preset = false;
    };
    environment.etc."aos/packages/k3s-combined/k3s.env".text = ${builtins.toJSON runtimeModule.environment.etc."aos/packages/k3s-combined/k3s.env".text};
    environment.etc."aos/packages/k3s-combined/addons.json".text = ${builtins.toJSON runtimeModule.environment.etc."aos/packages/k3s-combined/addons.json".text};
    environment.etc."tmpfiles.d/ability-kubernetes.conf".text = ${builtins.toJSON runtimeModule.environment.etc."tmpfiles.d/ability-kubernetes.conf".text};
    systemd.services.aos-kubernetes-matrix-foreign = {
      description = "Disposable foreign unit for Kubernetes effect qualification";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  '';
  qualificationExtraClosures =
    packageRoots
    ++ [
      pkgs.aos.testSupport
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.iproute2
      pkgs.jq
      pkgs.k3s-combined
      pkgs.kubectl
      pkgs.nix
      pkgs.util-linux
    ];
  qualificationCandidateRuntimeCompanions = map (name: let
    entry = builtins.head (builtins.filter (candidate: candidate.name == name) orderedPackages);
  in {
    inherit (entry) name;
    primary = entry.package;
    abilities = entry.package.abilities;
    originalRuntime = pkgs.aos.packageRuntime;
  }) ["ability-reference-systemd-bootstrap"];
in {
  inherit
    orderedPackages
    packageRoots
    packageSet
    qualificationExtraClosures
    qualificationCandidateRuntimeCompanions
    qualificationSetupBody
    runtimeModules
    runtimeSystem
    ;

  extraClosures =
    if guestTools
    then qualificationExtraClosures
    else
      qualificationExtraClosures
      ++ [
        pkgs.aos
        pkgs.aos.apm
        pkgs.aos.apr
        pkgs.k3s-combined
      ];

  testPrelude =
    # python
    ''
      import base64
      import hashlib
      import json
      import shlex
      import textwrap

      APM = ${
        if guestTools
        then ''runtime.guest_tool("apm")''
        else builtins.toJSON "${pkgs.aos.apm}/bin/apm"
      }
      APR = ${
        if guestTools
        then ''runtime.guest_tool("apr")''
        else builtins.toJSON "${pkgs.aos.apr}/bin/apr"
      }
      COREUTILS = "${pkgs.coreutils}/bin"
      FIXTURE = "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture"
      GIT = "${pkgs.git}/bin/git"
      JQ = "${pkgs.jq}/bin/jq"
      KUBECTL = "${pkgs.kubectl}/bin/kubectl"
      NIX_BIN = "${pkgs.nix}/bin"
      NIX_INSTANTIATE = "${pkgs.nix}/bin/nix-instantiate"
      PRLIMIT = "${pkgs.util-linux}/bin/prlimit"

      REFERENCE_PACKAGES = ${
        if guestTools
        then "runtime.candidate_handler_packages("
        else ""
      }${builtins.toJSON (map (entry: {
          inherit (entry) name;
          package = builtins.toString entry.package;
          abilities = builtins.toString entry.package.abilities;
        })
        orderedPackages)}${
        if guestTools
        then ")"
        else ""
      }


      def publish_kubernetes_packages():
          package_arguments = " ".join(
              " ".join(
                  shlex.quote(value)
                  for value in (entry["name"], entry["package"], entry["abilities"])
              )
              for entry in REFERENCE_PACKAGES
          )
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
              export GIT_AUTHOR_NAME='Kubernetes Ability Fixture'
              export GIT_AUTHOR_EMAIL=kubernetes-ability@example.test
              export GIT_COMMITTER_NAME='Kubernetes Ability Fixture'
              export GIT_COMMITTER_EMAIL=kubernetes-ability@example.test
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/kubernetes-ability-nix-conf
              export XDG_CONFIG_HOME=/tmp/kubernetes-ability-user-config
              export XDG_DATA_HOME=/tmp/kubernetes-ability-user-data
              mkdir -p "$NIX_CONF_DIR"
              printf 'experimental-features = nix-command\\nsandbox = false\\n' \\
                > "$NIX_CONF_DIR/nix.conf"

              {APR} keys generate release --registry kubernetes-reg \\
                > /tmp/kubernetes-ability-keygen.out 2>&1
              PUBKEY=$(${pkgs.gawk}/bin/awk \\
                '/Public key:/ {{print $NF; exit}}' \\
                /tmp/kubernetes-ability-keygen.out)
              KEY="$XDG_CONFIG_HOME/apm/keys/kubernetes-reg-release.key"
              {APR} create kubernetes-reg \\
                --trust-key "$PUBKEY" \\
                --trust-key-id release \\
                --key "$KEY"

              SOURCE="$XDG_DATA_HOME/apm/registries/kubernetes-reg"
              BASE_COMMIT=$({GIT} -C "$SOURCE" rev-parse HEAD)
              {FIXTURE} ability-registry \
                "$SOURCE" \
                /var/lib/kubernetes-ability-registry \
                kubernetes-reg \
                reference/kubernetes-reg \
                1.0.0 \
                sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
                "$BASE_COMMIT" \
                release \
                "$PUBKEY" \
                "$KEY" \
                {package_arguments}

              {APM} registry --system add \
                file:///var/lib/kubernetes-ability-registry \
                --name kubernetes-reg \
                --version '=1.0.0' \
                --trust-key "$PUBKEY" \
                --no-clone
              printf 'root_owner_signers = ["release"]\n' \
                >> /var/lib/apm/config/registries.d/kubernetes-reg.toml
              {APM} update --system --registry kubernetes-reg
          """), timeout=1200)


      def kubernetes_activation_command(
          output,
          replicas,
          include_longhorn,
          authority,
          fault=None,
          lifecycle="full",
      ):
          arguments = [
              FIXTURE,
              "kubernetes-activation",
              output,
              str(replicas),
              "true" if include_longhorn else "false",
          ]
          if fault:
              arguments.append(fault)
          arguments.extend(["--operator-authority-output", authority])
          arguments.extend(["--lifecycle", lifecycle])
          command = " ".join(shlex.quote(argument) for argument in arguments)
          return (
              f"PATH={NIX_BIN}:{COREUTILS} "
              f"AOS_NIX_INSTANTIATE={NIX_INSTANTIATE} "
              f"AOS_PRLIMIT={PRLIMIT} "
              f"AOS_TEST_ABILITY_CACHE=/var/cache/aos-ability-evaluator-fixture "
              f"{command}"
          )


      def reset_kubernetes_activation_paths(output, authority):
          runtime.succeed(
              f"{COREUTILS}/rm -rf {shlex.quote(output)} {shlex.quote(authority)}"
          )
          runtime.succeed(
              f"{COREUTILS}/mkdir -p {shlex.quote(output)} {shlex.quote(authority)}"
          )


      def generate_kubernetes_activation(
          output,
          replicas,
          include_longhorn,
          authority,
          fault=None,
          lifecycle="full",
      ):
          reset_kubernetes_activation_paths(output, authority)
          runtime.succeed(
              kubernetes_activation_command(
                  output,
                  replicas,
                  include_longhorn,
                  authority,
                  fault,
                  lifecycle,
              ),
              timeout=1200,
          )
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(output + '/activation.json')}"
          ))


      def provision_kubernetes_authority(activation, authority):
          digest = activation["authenticated_policy_set"]["document_sha256"]
          digest_hex = digest.removeprefix("sha256:")
          assert len(digest_hex) == 64, digest
          source = f"{authority}/{digest_hex}.json"
          runtime.succeed(
              f"{FIXTURE} kubernetes-authority-provision {shlex.quote(source)}"
          )


      def write_kubernetes_host(path, activation, extra_module=""):
          activation_json = json.dumps(activation, separators=(",", ":"))
          desired_packages = " ".join(
              json.dumps(entry["name"]) for entry in REFERENCE_PACKAGES
          )
          host_module = (
              "{ ... }: {\n"
              "  aos.apm.desiredPackages = [ "
              + desired_packages
              + " ];\n"
              "  aos.abilities.activationInput = builtins.fromJSON "
              + json.dumps(activation_json)
              + ";\n"
              + extra_module
              + "}\n"
          )
          encoded = base64.b64encode(host_module.encode()).decode()
          runtime.succeed(
              f"printf '%s' {shlex.quote(encoded)} | base64 -d "
              f"> {shlex.quote(path)}"
          )


      def switch_kubernetes_host(host, label):
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/kubernetes-ability-eval-{label}",
              timeout=1200,
          )
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def kubectl(arguments):
          return runtime.succeed(
              f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml {arguments}"
          )
    '';
}
