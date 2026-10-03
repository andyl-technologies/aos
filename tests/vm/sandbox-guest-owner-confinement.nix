# UID-zero MAC/cgroup prerequisite, NOT installed launch or accepted Create qualification.
{
  testing,
  pkgs,
}: let
  production = pkgs.aos-selinux-production-policy;
  evidence = "${production}/share/aos-selinux-production-policy";
  probe = pkgs.mkDerivation {
    pname = "aos-guest-owner-confinement-fixture";
    version = "1";
    src = null;
    phases = [
      {
        name = "build";
        script = ''
          $CC -static -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/guest-owner-confinement-probe.c} -o confinement-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 0755 confinement-probe "$out/bin/"
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  # This entry/setup exception exists ONLY in this check's artifact. Production
  # neither imports nor installs it. Its effective-policy gate rejects the
  # Owner owner_exec:file entrypoint grant below if it leaks into production.
  fixtureEntry = builtins.toFile "aos-guest-owner-fixture-entry.cil" ''
    (allow kernel_t aos_sandbox_guest_owner_t (process (transition)))
    (allow kernel_t aos_sandbox_guest_owner_t (process2 (nnp_transition nosuid_transition)))
    (allow kernel_t aos_sandbox_guest_owner_exec_t (file (execute getattr map open read)))
    (allow aos_sandbox_guest_owner_t aos_sandbox_guest_owner_exec_t (file (entrypoint)))
    (allow aos_sandbox_guest_owner_t kernel_t (fd (use)))
    (allow kernel_t aos_sandbox_guest_anchor_t (dir (getattr open read relabelto search)))
    (allow kernel_t aos_sandbox_guest_private_t (dir (getattr open read relabelto search)))
    (allow kernel_t aos_sandbox_guest_store_t (dir (getattr open read relabelto search)))
    (allow kernel_t aos_sandbox_guest_config_t (dir (getattr open read relabelto search)))
    (allow kernel_t aos_sandbox_guest_owner_exec_t (file (getattr relabelto)))
    (allow kernel_t aos_sandbox_guest_private_t (file (getattr relabelto)))
    (allow kernel_t aos_sandbox_guest_store_t (file (getattr relabelto)))
    (allow kernel_t aos_sandbox_guest_config_t (file (getattr relabelto)))
    (allow kernel_t aos_sandbox_guest_tenant_data_t (file (getattr relabelto)))
  '';
  fixturePolicy = pkgs.mkDerivation {
    pname = "aos-guest-owner-fixture-policy-never-installed";
    version = "1";
    src = null;
    buildDeps = [pkgs.secilc];
    phases = [
      {
        name = "build";
        script = ''
          # Original production evidence and bytes remain unchanged.
          test -s ${evidence}/effective-policy.tsv
          ${pkgs.secilc}/bin/secilc -c 33 -f /dev/null -o fixture-policy.33 \
            ${evidence}/final-policy.cil ${fixtureEntry}
          test -s fixture-policy.33
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          install -m 0644 fixture-policy.33 "$out/"
          install -m 0644 ${fixtureEntry} "$out/fixture-entry.cil"
        '';
      }
    ];
  };
in
  assert !(builtins.elem fixtureEntry production.buildDeps);
  assert !(builtins.elem probe pkgs.aos-sandbox-agent.buildDeps);
    testing.mkVMTest {
      name = "sandbox-guest-owner-confinement";
      rootfsDeps = [probe fixturePolicy pkgs.coreutils pkgs.policycoreutils pkgs.util-linux];
      memory = 512;
      testScript = ''
        unset LD_LIBRARY_PATH
        mkdir -p /sys/fs/selinux /sys/fs/cgroup /run/aos-guest-owner-fixture
        ${pkgs.util-linux}/bin/mount -t selinuxfs selinuxfs /sys/fs/selinux
        ${pkgs.util-linux}/bin/mount -t cgroup2 cgroup2 /sys/fs/cgroup
        # Headless fixture policy, not immutable stage-0/readiness qualification.
        ${pkgs.coreutils}/bin/cat ${fixturePolicy}/fixture-policy.33 > /sys/fs/selinux/load
        printf 1 > /sys/fs/selinux/enforce
        test "$(cat /sys/fs/selinux/enforce)" = 1
        test "$(cat /sys/fs/selinux/policy_capabilities/nnp_nosuid_transition)" = 1
        if test -f /proc/sys/kernel/yama/ptrace_scope; then
          printf 0 > /proc/sys/kernel/yama/ptrace_scope
          test "$(cat /proc/sys/kernel/yama/ptrace_scope)" = 0
        fi

        root=/run/aos-guest-owner-fixture
        mkdir -p "$root/private" "$root/manager" "$root/config" "$root/store"
        mkdir /sys/fs/cgroup/aos-guest-owner-fixture
        chmod 0700 /sys/fs/cgroup/aos-guest-owner-fixture
        chmod 0600 /sys/fs/cgroup/aos-guest-owner-fixture/cgroup.procs \
          /sys/fs/cgroup/aos-guest-owner-fixture/cgroup.threads \
          /sys/fs/cgroup/aos-guest-owner-fixture/cgroup.kill
        cp ${probe}/bin/confinement-probe "$root/owner"
        cp ${probe}/bin/confinement-probe "$root/tenant"
        printf private > "$root/private/trust"
        printf ledger > "$root/private/ledger"
        printf unit > "$root/manager/unit.service"
        printf 'passwd: files\n' > "$root/config/nsswitch.conf"
        printf loader > "$root/store/loader"
        chmod 0755 "$root" "$root/owner" "$root/tenant"
        chmod 0700 "$root/private" "$root/manager" "$root/config" "$root/store"
        chcon system_u:object_r:aos_sandbox_guest_anchor_t:s0 "$root"
        chcon -R system_u:object_r:aos_sandbox_guest_private_t:s0 "$root/private" "$root/manager"
        chcon -R system_u:object_r:aos_sandbox_guest_config_t:s0 "$root/config"
        chcon -R system_u:object_r:aos_sandbox_guest_store_t:s0 "$root/store"
        chcon system_u:object_r:aos_sandbox_guest_owner_exec_t:s0 "$root/owner"
        chcon system_u:object_r:aos_sandbox_guest_tenant_data_t:s0 "$root/tenant"
        # UID zero retains DAC_OVERRIDE. Passing denials cannot be credited to
        # DAC or Yama; no new production capability or service is introduced.
        ${pkgs.util-linux}/bin/setpriv \
          --bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+kill,+setgid,+setuid \
          "$root/owner" enter </dev/null >/dev/null 2>&1
        test "$(cat /sys/fs/selinux/enforce)" = 1
        test "$(cat /sys/fs/cgroup/aos-guest-owner-fixture/cgroup.events | sed -n 's/^populated //p')" = 0
      '';
    }
