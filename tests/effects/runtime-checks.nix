##! Verifies retained package runtime checks select the canonical VM harness.
let
  root = ../..;
  lib = import (root + /lib) {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
  payload = name: {
    type = "derivation";
    pname = name;
    version = "1";
    system = "x86_64-linux";
    outPath = toString (fixturePayload name);
  };
  package = name: dir: deps:
    (payload name)
    // {
      module = builtins.path {
        path = root + dir;
        name = "${name}-module";
      };
      moduleDeps = deps;
      runtimeDeps = map payload ["bash" "coreutils" "sed"];
    };
  checks = package "aos-runtime-checks" /pkgs/system/_aos-runtime-checks [];
  services = package "service-management" /pkgs/system/_service-management [checks];
  filesystem = package "aos-filesystem-provider" /pkgs/filesystem/_aos-filesystem-provider [];
  pam = package "linux-pam" /pkgs/security/_linux-pam [services filesystem];
  bus = package "dbus" /pkgs/system/_dbus [services filesystem];
  polkit = package "polkit" /pkgs/security/_polkit [services filesystem pam bus];
  lower = package "aos-configuration-lower" /pkgs/boot/_aos-configuration-lower [];
  virt = (package "libvirt" /pkgs/virtualization/_libvirt [services filesystem bus polkit lower]) // {runtimeDeps = map payload ["bridge-utils" "coreutils" "dbus" "dnsmasq" "iproute2" "iptables" "nftables" "numactl" "numad" "parted" "passt" "pm-utils" "qemu" "swtpm" "systemd" "util-linux" "zfs"];};

  kernel = package "kernel-interface" /pkgs/kernel/_kernel-interface [];
  docker = package "docker-engine" /pkgs/containers/_docker-engine [services filesystem checks];
  tailscale = (package "tailscale" /pkgs/networking/_tailscale [services checks]) // {runtimeDeps = map payload ["getent" "iproute2" "iptables" "procps-ng"];};
  chrony = package "chrony" /pkgs/networking/_chrony-abilities [services checks];
  firewall = package "nftables" /pkgs/networking/_nftables [checks];
  bind = package "bind" /pkgs/networking/_bind [services firewall checks];
  dnsmasq = package "dnsmasq" /pkgs/networking/_dnsmasq [services firewall checks];
  ssh = package "openssh" /pkgs/networking/_openssh [services filesystem firewall pam checks];
  audit = package "audit" /pkgs/security/_audit [services kernel checks];
  evaluate = enabled:
    lib.evalPackageModules {
      scope = ["test" "runtime-checks"];
      packages = [docker tailscale chrony bind dnsmasq ssh audit virt firewall checks];
      operatorModules = [
        {
          aos.services = {
            docker.enable = enabled;
            tailscale.enable = enabled;
            chrony.enable = enabled;
            bind = {
              enable = enabled;
              port = 5353;
            };
            dnsmasq = {
              enable = enabled;
              port = 5454;
            };
            ssh.enable = enabled;
          };
          aos.security.audit.enable = enabled;
          aos.virtualization.libvirt.enable = enabled;
          aos.networkPolicy.enable = enabled;
        }
      ];
    };
  enabledConfiguration = (evaluate true).config;
  bindService = enabledConfiguration.aos.services.bind;
  dnsmasqService = enabledConfiguration.aos.services.dnsmasq;
  enabled = enabledConfiguration.system.checks;
  disabled = (evaluate false).config.system.checks;
  names = ["audit" "bind" "chrony" "dnsmasq" "docker" "firewall" "libvirt" "ssh" "tailscale"];
in {
  libvirtPreservesAccountIds = assert enabledConfiguration.aos.abilities.identity.operations.group.effects.libvirt-qemu.input.requested_id == 64054;
  assert enabledConfiguration.aos.abilities.identity.operations.group.effects.libvirt-access.input.requested_id == 64055;
  assert enabledConfiguration.aos.abilities.identity.operations.principal.effects.libvirt-qemu.input.requested_id == 64054; true;
  bindPreservesMasterHardening = let
    policy = bindService.policy.hardening;
  in
    assert policy.resource_control_access == "host";
    assert builtins.all (name: policy.${name}) [
      "host_clock_mutation"
      "host_name_mutation"
      "operating_system_log_access"
      "operating_system_extension_access"
      "operating_system_tunable_access"
      "writable_executable_memory"
      "permit_realtime"
      "permit_elevated_file_identity"
    ];
    assert !policy.lock_execution_personality;
    assert !policy.allow_privilege_escalation;
    assert policy.network_families == [] && policy.security_label == null;
    assert policy.operation_profile == "privileged" && policy.operation_allow == [] && policy.operation_deny == []; true;
  bindPreservesMasterIsolation = assert bindService.isolation.home_access == "inaccessible";
  assert bindService.isolation.filesystem == "read-only-system";
  assert bindService.isolation.temporary_directory == "private";
  assert bindService.isolation.permit_core_dumps; true;
  bindPreservesManagedDirectoryModes = assert builtins.map (mount: mount.name) bindService.storage.mounts == ["state" "runtime"];
  assert builtins.map (mount: mount.source) bindService.storage.mounts == ["/var/lib/aos-pkg-bind" "/run/aos-pkg-bind"];
  assert builtins.all (mount: mount.access == "read-write" && mount.ownership == "service-identity" && mount.directory_mode == "0750") bindService.storage.mounts; true;
  dnsmasqPreservesMasterHardening = let
    policy = dnsmasqService.policy.hardening;
  in
    assert policy.resource_control_access == "host";
    assert builtins.all (name: policy.${name}) [
      "host_clock_mutation"
      "host_name_mutation"
      "operating_system_log_access"
      "operating_system_extension_access"
      "operating_system_tunable_access"
      "writable_executable_memory"
      "permit_realtime"
      "permit_elevated_file_identity"
    ];
    assert !policy.lock_execution_personality;
    assert !policy.allow_privilege_escalation;
    assert policy.network_families == [] && policy.security_label == null;
    assert policy.operation_profile == "privileged" && policy.operation_allow == [] && policy.operation_deny == []; true;
  dnsmasqPreservesMasterIsolation = assert dnsmasqService.isolation.home_access == "inaccessible";
  assert dnsmasqService.isolation.filesystem == "read-only-system";
  assert dnsmasqService.isolation.temporary_directory == "private";
  assert dnsmasqService.isolation.permit_core_dumps; true;
  dnsmasqPreservesRuntimeDirectoryMode = let
    runtimeMount = builtins.head dnsmasqService.storage.mounts;
  in
    assert runtimeMount.name == "runtime" && runtimeMount.access == "read-write";
    assert runtimeMount.source == "/run/aos-pkg-dnsmasq";
    assert runtimeMount.ownership == "service-identity" && runtimeMount.directory_mode == "0750"; true;
  dnsStorageHasSingleOwner = let
    directories = enabledConfiguration.aos.abilities.filesystem.operations.directory.effects;
  in
    assert builtins.all (name: !(builtins.hasAttr name directories)) ["bind-state" "bind-runtime" "dnsmasq-runtime" "dnsmasq-state"];
    assert builtins.all (effect: !(builtins.elem effect.input.path ["/var/lib/aos-pkg-bind" "/run/aos-pkg-bind" "/run/aos-pkg-dnsmasq"])) (builtins.attrValues directories); true;
  selected = assert builtins.attrNames enabled == names; true;
  preservedScripts = assert builtins.all (name: enabled.${name}.checks != [] && builtins.all (check: check.name != "" && check.script != "") enabled.${name}.checks) names; true;
  disabled = assert disabled == {}; true;
  harnessDefaults = assert builtins.all (name: enabled.${name}.extraDisks == [] && enabled.${name}.kernelParams == [] && enabled.${name}.memoryMiB == null && enabled.${name}.timeoutSeconds == null) names; true;
}
