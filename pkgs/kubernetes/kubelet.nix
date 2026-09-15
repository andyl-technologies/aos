##! kubelet — Kubernetes node agent
{
  lib,
  mkGoPackage,
  kubeSource,
}:
mkGoPackage {
  pname = "kubelet";
  inherit (kubeSource) version src;

  goPackage = "./cmd/kubelet";
  goOutput = "kubelet";
  ldflags = "-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}";
  doCheck = false;
  abilities = ./_kubelet-config/module.nix;

  checks = {
    testing,
    self,
    pkgs,
  }: let
    evaluated = lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "deployment";
            key = "kubelet-package-check";
            stage = "host";
          };
          kubelet = {
            enable = true;
            nodeName = "worker-a";
            registerNode = true;
            kubeconfig.ref = "system-credential:kubelet-worker-a";
            maxPods = 80;
          };
        }
      ];
      packageModules = [
        {
          name = "kubelet";
          version = kubeSource.version;
          module = ./_kubelet-config/module.nix;
        }
      ];
    };
    requests = evaluated.config.aos.abilities.requests;
    configuration = builtins.fromJSON requests."kubelet:configuration".parameters.source.content;
    environment = requests."kubelet:kubelet-environment".parameters.variables;
  in {
    version = testing.mkToolCheck {
      pname = "tool-kubelet";
      tool = self;
      command = "kubelet --version";
    };
    config-module-contract = pkgs.runCommand "kubelet-config-module-contract" {} ''
      config=${builtins.toFile "kubelet.json" (builtins.toJSON configuration)}
      ${pkgs.jq}/bin/jq -e '
        .apiVersion == "kubelet.config.k8s.io/v1beta1"
        and .maxPods == 80
              and .containerRuntimeEndpoint == "unix:///run/containerd/containerd.sock"
          ' "$config" >/dev/null
        set +e
        ${pkgs.coreutils}/bin/timeout 5 \
        ${self}/bin/kubelet --config="$config" \
          >"$TMPDIR/kubelet.log" 2>&1
        status=$?
        set -e
        test "$status" -ne 0
        if ${pkgs.grep}/bin/grep -E 'failed to (load|parse)|strict decoding error|unknown field' \
          "$TMPDIR/kubelet.log"; then
          cat "$TMPDIR/kubelet.log" >&2
          exit 1
        fi
      test '${environment.KUBELET_NODE_NAME}' = worker-a
      test '${requests."kubelet:kubeconfig-source".parameters.name}' = kubelet-worker-a
      touch "$out"
    '';
  };

  meta = {
    description = "kubelet — Kubernetes node agent that manages pods";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
