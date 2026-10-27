# Runs the production quota boundary against real ext4 in an isolated guest.
# The host needs KVM only; no host mount, cgroup, or quota state is changed.
{
  pkgs,
  lib,
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleBinaries workspaceTests;
  probe = mkCrucibleBinaries {
    pname = "crucible-project-quota-flight";
    builds = [workspaceTests.apacheRelease];
    executables = {
      project-quota-flight = "build --release -p aos-linux-project-quota --example project-quota-flight";
    };
  };
  quotaKernel = pkgs.linux.override {
    extraConfig = ''
      CONFIG_QUOTA=y
      CONFIG_QFMT_V2=y
      CONFIG_QUOTACTL=y
    '';
  };
  testing = import ../../lib/testing {
    inherit lib;
    pkgs = pkgs // {linux = quotaKernel;};
  };
in
  testing.mkVMTest {
    name = "crucible-project-quota";
    memory = 512;
    rootfsDeps = [probe pkgs.e2fsprogs pkgs.coreutils pkgs.util-linux pkgs.grep];
    testScript = ''
      set -eu
      # All filesystem setup runs in the disposable guest, not the Nix host.
      truncate -s 128M /tmp/quota.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/quota.img
      mkdir /tmp/quota-root
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/quota.img /tmp/quota-root
      ${pkgs.coreutils}/bin/timeout -k 5 60 \
        ${probe}/bin/project-quota-flight /tmp/quota-root > /tmp/quota-result
      cat /tmp/quota-result
      grep -Fxq PASS /tmp/quota-result
      grep -Fxq bytes_quota_enforced=true /tmp/quota-result
      grep -Fxq inodes_quota_enforced=true /tmp/quota-result
      grep -Fxq nonempty_release_retains_authority=true /tmp/quota-result
      grep -Fxq cleared_project_ids_reusable=true /tmp/quota-result
      ${pkgs.util-linux}/bin/umount /tmp/quota-root
    '';
  }
