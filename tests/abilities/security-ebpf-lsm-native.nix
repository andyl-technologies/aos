##! Checks the package-owned fleet BPF-LSM policy loader declaration.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-ebpf-lsm";
    module = ../../modules/security/ebpf-lsm.nix;
    packages = [pkgs.aos];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  lifecycle = requests."aos:aos-ebpf-lsm-policies-lifecycle".parameters;
  isolation = requests."aos:aos-ebpf-lsm-policies-linux_isolation".parameters;
in
  assert lifecycle.execution_model == "oneshot";
  assert lifecycle.remain_after_exit;
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "bin/aos-package-runtime";
        arguments = ["_load-ebpf-lsm-policies" "--system"];
      };
      ignore_failure = false;
    }
  ];
  assert builtins.elem "CAP_BPF" isolation.capability_bounds.capabilities;
  assert builtins.elem "CAP_SYS_ADMIN" isolation.capability_bounds.capabilities;
  assert builtins.elem "CAP_SYS_RESOURCE" isolation.capability_bounds.capabilities;
  assert requests."aos:aos-ebpf-lsm-policies-conditions".parameters.all
  == [
    {
      kind = "path";
      predicate = "exists";
      path = "/etc/aos/policy.toml";
      negated = false;
    }
  ];
  assert requests."aos:aos-ebpf-lsm-policies-resources".parameters.locked_memory_bytes.kind
  == "unbounded";
  assert config.systemd.services == {};
  assert !(config.aos.config._artifactSources or {} ? "ebpf-lsm-prepare-bpffs"); true
