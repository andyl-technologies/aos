# tests/fleet/apm-system-upgrade.nix — Live, in-place `apm upgrade --system`.
#
# End-to-end proof for the apm system-upgrade refactor (v2): `apm upgrade
# --system` must reconfigure the *running* system without a reboot — swap the
# /etc overlay to the new generation (P1's activate script) AND reconcile the
# running daemons against the new unit set (the hidden activate pre/post split,
# driven by P2's diff engine over P3's X-* unit contract). The fleet harness
# boots a server image with a direct upgrade fixture and full systemd + dbus,
# which is what the reconciler needs.
#
# Single machine (N=1): the live upgrade is entirely local to the target — the
# new generation's closure is pre-staged on its disk (extraClosures) and the
# upgrade downloads nothing, so no registry/cache peer is needed. (Registry git
# sync over the L2 is already covered by apm-e2e.nix.)
#
# Generation pairing:
#   gen-1 = systems.server + fixture
#                                 (seeded into state.json at first boot by
#                                  aos-seed-profiles.service: package "aos",
#                                  version "0.1.0", registry "seed").
#   gen-2 = systems/server-2.nix   (imports server.nix; bumps the version,
#                                   adds an environment.etc marker, and gives
#                                   the upgrade HTTP fixture a new port, a
#                                   sysctl, a new oneshot unit, and one
#                                   removed gen-1 oneshot unit).
# The target boots a gen-1 system with that same direct fixture. The upgrade
# then introduces the fixture's gen-2 deltas as a *live* update — exactly the
# reconciliation surface under test, without depending on legacy role modules.
#
# ── Why the upgrade needs no network ───────────────────────────────────
# `extraClosures` pre-stages the entire server-2 closure onto the target's
# disk, so `apm upgrade --system` finds every store path present and downloads
# nothing. Two details are handled here:
#   1. The full image ships `/aos-registration`, and aos-nix-db.service loads it
#      at boot. That makes the pre-staged server-2 closure visible to
#      `nix-store --check-validity` without manual test seeding.
#   2. `apm upgrade --system` reads SYSTEM-scope registries
#      (/etc/apm/registries.d for config, /var/lib/apm/remote for the synced
#      packages — types.rs), NOT the user scope that `apm registry add` /
#      `apm update` write. So we stage the registry directly in system scope
#      (same shape as tests/vm/apm/system.nix's mkSystemPreamble) rather than
#      going through `apm update` (which has no `--system` flag).
#
# File bodies (the package TOML) are shipped as base64 and decoded on the
# guest. `${pkgs...}` / `${...Top}` are Nix interpolations resolved at eval time.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  fleetSystem = evaluated: {
    # Re-expose extendModules so the new-path harness can bake per-VM identity.
    inherit (evaluated) config options extendModules;
    build = {
      toplevel = evaluated.config.system.build.toplevel;
      kernel = evaluated.config.system.build.kernel;
      initrd = evaluated.config.system.build.initrd;
      image = evaluated.config.system.build.image;
    };
    checks = evaluated.config.system.build.checks;
  };

  # server-test restores `nft` (and the other fleet CLI tools) on PATH; the
  # test inspects the live firewall ruleset with `nft list set`, which image
  # slimming dropped from the server profile.
  server1 = fleetSystem (mkSystem [
    ../../systems/server-test.nix
    (import ../../systems/_upgrade-http-fixture.nix {
      inherit lib pkgs;
      generation = 1;
    })
  ]);

  # gen-2's toplevel. Pre-staged on the target via `extraClosures`; the
  # registry entry's `store_path` names this exact path.
  server2Top = systems.server-2.config.system.build.toplevel;

  # Package TOML for the sysroot package "aos" at version "test-2", pointing at
  # the pre-staged server-2 toplevel. Mirrors apm-e2e.nix's packageTomlSkeleton,
  # parametrised over a real system toplevel and with `sysroot = true`
  # (upgrade_system only considers entries with that flag).
  #
  #   - name MUST equal systems.server's `aos.system.name` (default "aos") —
  #     upgrade_system looks up `reg.packages.get(&current_gen.package_name)`,
  #     and gen-1's package_name is "aos".
  #   - version "test-2" matches systems/server-2.nix's aos.system.version.
  #   - references are the real direct reference hashes from Nix's structured
  #     exportReferencesGraph metadata.
  #   - nar_hash is a placeholder: with nothing to download there is no verify
  #     step, so the value is never inspected.
  serverPkgToml = pkgs.mkDerivation {
    pname = "apm-system-upgrade-server2-registry-entry";
    version = "0";
    src = null;

    __structuredAttrs = true;
    exportReferencesGraph.server2 = [server2Top];

    buildDeps = [
      pkgs.jq
      pkgs.coreutils
    ];

    dontStrip = true;
    dontNukeRefs = true;

    SERVER2_TOP = builtins.toString server2Top;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          mkdir -p "$out"

          references=$(
            jq -r --arg path "$SERVER2_TOP" '
              [
                .server2[]
                | select(.path == $path)
                | .references[]
                | split("/")[-1]
                | split("-")[0]
              ]
              | @json
            ' < "$NIX_ATTRS_JSON_FILE"
          )

          {
            printf '%s\n' '[package]'
            printf '%s\n' 'name = "aos"'
            printf '%s\n' 'description = "Upgrade test fixture (server-2 toplevel)"'
            printf '%s\n' 'license = "MIT"'
            printf '%s\n' 'maintainer = "test"'
            printf '%s\n' 'sysroot = true'
            printf '\n'
            printf '%s\n' '[[versions]]'
            printf '%s\n' 'version = "test-2"'
            printf '\n'
            printf '%s\n' '[versions.platforms.x86_64-linux]'
            printf 'store_path = "%s"\n' "$SERVER2_TOP"
            printf '%s\n' 'nar_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"'
            printf '%s\n' 'nar_size = 0'
            printf '%s\n' 'closure_size = 0'
            printf '%s\n' 'source_drv = ""'
            printf '%s\n' 'source_nar_hash = ""'
            printf 'references = %s\n' "$references"
          } > "$out/aos.toml"
        '';
      }
    ];
  };
in {
  name = "apm-system-upgrade";
  # One VM boot + fixture activation + a live generation switch (overlay swap +
  # daemon reconcile) + rollback. Generous budget for sandbox CPU/IO contention.
  timeout = 600;

  machines = {
    # Python global `target`.
    target = {
      system = server1;
      # Pre-stage gen-2's full closure so `apm upgrade --system` fetches
      # nothing over the network (see the header note).
      extraClosures = [server2Top];
    };
  };

  testScript =
    # python
    ''
      import base64
      import json
      import pathlib

      # ── 1. Target is on gen-1 with the test fixture already active ───
      target.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      target.wait_until_succeeds(
          "systemctl is-active test-http-server.service", timeout=120
      )

      target.succeed("test -L /var/lib/profiles/system/current")
      gen_before = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_before == "gen-1", f"expected gen-1, got {gen_before!r}"

      # Fixture baseline. gen-1 opens port 8000 in the base nftables ruleset
      # but does not yet add tcp_keepalive_time to the kernel sysctl drop-in.
      nftd_before = target.succeed(
          "cat /etc/nftables.conf"
      )
      assert "8443" not in nftd_before, "gen-1 should not yet open port 8443"
      sysctld_before = target.succeed("cat /etc/sysctl.d/10-aos-kernel.conf")
      assert "tcp_keepalive_time" not in sysctld_before, sysctld_before

      # gen-2-only surfaces are absent on gen-1.
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      target.wait_until_succeeds(
          "systemctl is-active aos-upgrade-removed.service", timeout=120
      )
      target.fail("test -e /run/removed-stop-ran")

      # gen-1 has no tcp_keepalive_time drop-in → the kernel default (7200).
      baseline_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert baseline_keepalive == "7200", (
          f"unexpected baseline keepalive {baseline_keepalive!r}"
      )

      # Record test-http-server's MainPID — its unit file is byte-identical
      # across gen-1 and gen-2, so the reconciler must leave it untouched.
      # Asserted after the upgrade.
      http_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())

      # Record dbus's MainPID. gen-2 perturbs dbus.service (a serviceConfig
      # limit), so the reconciler MUST act on it — but because dbus.service is
      # reloadIfChanged it must *reload* (same daemon, same PID, live bus
      # preserved), never restart. A restart would tear down the very bus the
      # reconciler drives itself over and hang (the bug this guards). Asserted
      # after the upgrade.
      dbus_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value dbus.service"
      ).strip())
      assert dbus_pid_before > 0, "dbus.service has no MainPID before upgrade"

      # ── 2. Stage the registry in SYSTEM scope ───────────────────────
      # /etc/apm/registries.d/<name>.toml for the config + the package TOML in
      # the system cache dir /var/lib/apm/remote/<name>/packages/<letter>/.
      # (apm reads system-scope registries from these paths; package "aos" →
      # letter dir "a".) /var/lib is persistent; /etc/apm is the live overlay,
      # written before the upgrade reads it.
      package_toml_b64 = base64.b64encode(
          pathlib.Path("${serverPkgToml}/aos.toml").read_bytes()
      ).decode()

      # The registry config (registries.d/*.toml) is simple, shell-safe text —
      # write it with a quoted heredoc. Its url is never fetched (the package is
      # pre-staged in the cache dir) but it must be `enabled` so
      # `config.enabled_registries()` surfaces it.
      target.succeed(
          "set -eu\n"
          "mkdir -p /etc/apm/registries.d /var/lib/apm/remote/test-reg/packages/a\n"
          "cat > /etc/apm/registries.d/test-reg.toml <<'EOF'\n"
          "[registry]\n"
          'name = "test-reg"\n'
          'url = "file:///var/lib/apm/remote/test-reg"\n'
          "priority = 500\n"
          "enabled = true\n"
          "\n"
          "[registry.signing]\n"
          "required = false\n"
          "EOF\n"
          f"echo {package_toml_b64} | base64 -d > /var/lib/apm/remote/test-reg/packages/a/aos.toml\n"
      )

      # ── 3. The boot-time DB seed covers the pre-staged toplevel ────────
      target.succeed(
          "systemctl is-active aos-nix-db.service\n"
          "test -L /nix/var/nix/gcroots/aos-profiles\n"
          "${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'\n",
          timeout=120,
      )

      # ── 4. Dry-run surfaces the available upgrade ───────────────────
      # upgrade_system prints "Current sysroot: aos 0.1.0 ..." and "Upgrade
      # available: aos 0.1.0 -> test-2"; both version strings are the
      # unambiguous signal the test-2 entry was recognised.
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface the test-2 target: {out!r}"
      assert "0.1.0" in out, f"dry-run did not name the current 0.1.0 gen: {out!r}"

      # ── 5. The actual upgrade ───────────────────────────────────────
      # --yes for non-interactive; default kernel mode (no kernel change in
      # this gen delta, so the kernel handler is a no-op).
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=300,
      )
      print("=== apm upgrade --system output ===\n" + out)

      # ── 6. Generation bookkeeping ───────────────────────────────────
      gen_after = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_after == "gen-2", f"expected gen-2, got {gen_after!r}"

      state = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert state["current"] == 2, state
      assert len(state["generations"]) == 2, state

      # ── 7. Live /etc reflects gen-2 (overlay swap succeeded) ─────────
      # The marker file is symlink-mode environment.etc → baked into gen-2's
      # EROFS metadata image, and the var-seed never writes under /etc/aos/, so
      # its appearance is a clean proof the EROFS lower was swapped to gen-2.
      target.succeed("test -f /etc/aos/upgrade-test/marker.conf")
      marker = target.succeed(
          "cat /etc/aos/upgrade-test/marker.conf"
      ).strip()
      assert marker == "marker = 1", f"unexpected marker content: {marker!r}"

      # os-release reflects gen-2's version. The harness no longer seeds
      # /var/etc/os-release (it would shadow the gen's EROFS os-release — see
      # lib/testing/vm.nix), so the active generation's VERSION_ID surfaces.
      osrel = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" in osrel, osrel

      # ── 8. Base /etc policy reflects the gen-2 fixture ──────────────
      nftd = target.succeed("cat /etc/nftables.conf")
      assert "8443" in nftd, "new nftables ruleset missing port 8443"

      sysctld = target.succeed(
          "cat /etc/sysctl.d/10-aos-kernel.conf"
      )
      assert "tcp_keepalive_time = 300" in sysctld, sysctld

      # ── 9. Reconciliation acted on the drop-in changes ──────────────
      # systemd-sysctl restarted (no ExecReload → restart) via its
      # X-Reload-Triggers on /etc/sysctl.d, re-applying every sysctl — the
      # kernel's runtime keepalive must now reflect the new drop-in.
      post_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert post_keepalive == "300", (
          f"sysctl was not re-applied; keepalive is {post_keepalive!r}"
      )

      # nftables reloaded (it has ExecReload → reload) via its X-Reload-Triggers
      # on /etc/nftables.conf — port 8443 is now allowed.
      nft_dump = target.succeed("nft list set inet filter allowed_tcp")
      assert "8443" in nft_dump, nft_dump

      # ── 10. The newly-added unit was installed and started ──────────
      target.succeed("systemctl is-active aos-upgrade-test-marker.service")

      # ── 11. The removed unit was stopped before its old definition vanished ─
      target.fail("systemctl is-active aos-upgrade-removed.service")
      target.fail("test -e /etc/systemd/system/aos-upgrade-removed.service")
      target.succeed("test -f /run/removed-stop-ran")

      # ── 12. The unchanged unit was NOT restarted (diff stayed precise) ─
      http_pid_after = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())
      assert http_pid_before == http_pid_after, (
          "test-http-server.service was restarted unnecessarily: PID "
          f"{http_pid_before} -> {http_pid_after}"
      )

      # ── 12b. The perturbed dbus.service was RELOADED, not restarted ──
      # This is the regression guard for the dbus-self-restart hang. gen-2
      # changed dbus.service's unit text, so the reconciler had to act on it.
      # Because dbus.service is reloadIfChanged with an ExecReload, it must be
      # reloaded in place: the daemon keeps running (same MainPID) and the
      # system bus the reconciler drives itself over is never torn down. A
      # restart would change the PID — and, over the bus, would have hung the
      # whole `apm upgrade` (which is exactly the bug we fixed). The bus must
      # still be live and dbus still active.
      target.succeed("systemctl is-active dbus.service")
      target.succeed("test -S /run/dbus/system_bus_socket")
      dbus_pid_after = int(target.succeed(
          "systemctl show -p MainPID --value dbus.service"
      ).strip())
      assert dbus_pid_before == dbus_pid_after, (
          "dbus.service was RESTARTED instead of reloaded (the self-restart "
          f"hang regressed): PID {dbus_pid_before} -> {dbus_pid_after}"
      )
      # And the reconcile plan itself classified dbus as a reload, not a
      # restart — belt-and-suspenders against a future X-* regression.
      assert "restarting dbus.service" not in out, (
          "reconcile scheduled a dbus.service RESTART:\n" + out
      )
      assert "reloading  dbus.service" in out, (
          "reconcile did not reload dbus.service as expected:\n" + out
      )

      # ── 13. No failed units after the reconcile ─────────────────────
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after upgrade: {failed!r}"

      # ── 14. Rollback reverses the live switch ───────────────────────
      target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm rollback --system --yes 2>&1",
          timeout=300,
      )
      gen_rolled = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_rolled == "gen-1", f"expected gen-1 after rollback, got {gen_rolled!r}"

      # The marker file is gone (EROFS swapped back to gen-1).
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      # The added unit is torn down with gen-2.
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      # os-release is back to gen-1's version (no longer the gen-2 "test-2").
      osrel_back = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" not in osrel_back, osrel_back

      # /run/etc bookkeeping: the active system lower points back at system-1,
      # and Phase C tore down gen-2's mounts.
      assert target.succeed("readlink /run/etc/system").strip() == "system-1"
      target.fail("test -d /run/etc/system-2")
    '';
}
