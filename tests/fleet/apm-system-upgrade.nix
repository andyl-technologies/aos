# tests/fleet/apm-system-upgrade.nix - Refuse incomplete A/B system upgrades.
#
# RFC-0011 retired live, single-axis sysroot activation. `apm upgrade --system`
# now accepts only an authenticated raw OTA payload and stages it into the
# inactive A/B slot; host configuration changes use the evaluator/activation
# transaction instead. This test preserves the old pre-staged-toplevel fixture
# as an explicit fail-closed case: catalog metadata without an OTA payload must
# not create a configuration generation or change the running system.
#
# Single machine (N=1): the attempted upgrade is entirely local to the target.
# Its closure is pre-staged on disk, so no registry/cache peer is needed and the
# failure can be attributed specifically to incomplete image metadata.
#
# The target boots image generation 1 with no evaluated configuration yet.
# The registry advertises a different sysroot version and a valid toplevel
# closure, but deliberately omits `versions.platforms.*.images`. Dry-run may
# report the candidate; the real operation must reject it before mutation.
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
    # Re-expose extendModules so the harness can bake per-VM identity.
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
  # One VM boot plus a complete pre-staged closure and fail-closed attempt.
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

      # -- Initial two-axis state and running-system baseline -----------------
      target.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      target.wait_until_succeeds(
          "systemctl is-active test-http-server.service", timeout=120
      )

      image_before = json.loads(
          target.succeed("cat /var/lib/profiles/image/state.json")
      )
      assert image_before["running"] == 1, image_before
      assert image_before["default"] == 1, image_before
      # This direct-kernel harness does not pass through sd-boot, so it cannot
      # produce boot-success evidence that clears the seeded pending marker.
      assert image_before.get("pending") == 1, image_before
      assert len(image_before["generations"]) == 1, image_before

      config_before = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert config_before == {
          "current": 0,
          "next": 1,
          "generations": [],
      }, config_before
      target.fail("test -e /var/lib/profiles/system/current")

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

      http_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())
      dbus_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value dbus.service"
      ).strip())
      assert dbus_pid_before > 0, "dbus.service has no MainPID before upgrade"

      # -- Stage deliberately incomplete system registry metadata -------------
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

      # The closure is valid and present, isolating the refusal to missing OTA
      # metadata rather than a download or Nix database failure.
      target.succeed(
          "systemctl is-active aos-nix-db.service\n"
          "${pkgs.util-linux}/bin/mountpoint -q /nix/var/nix/gcroots/aos-profiles\n"
          "test \"$(${pkgs.coreutils}/bin/stat -c %d:%i /var/lib/profiles)\" = "
          "\"$(${pkgs.coreutils}/bin/stat -c %d:%i /nix/var/nix/gcroots/aos-profiles)\"\n"
          "${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'\n",
          timeout=120,
      )

      # -- Dry-run resolves the different image version -----------------------
      # upgrade_system prints "Current sysroot: aos 0.1.0 ..." and "Upgrade
      # available: aos 0.1.0 -> test-2"; both version strings are the
      # unambiguous signal the test-2 entry was recognised.
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface the test-2 target: {out!r}"
      assert "0.1.0" in out, f"dry-run did not name the current 0.1.0 gen: {out!r}"

      # -- Real operation refuses the incomplete image before mutation --------
      target.succeed(
          "if HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --yes "
          "> /tmp/apm-system-upgrade.out 2>&1; then exit 1; fi",
          timeout=300,
      )
      out = target.succeed("cat /tmp/apm-system-upgrade.out")
      print("=== rejected apm upgrade --system output ===\n" + out)
      assert "no authenticated raw OTA image" in out, out

      image_after = json.loads(
          target.succeed("cat /var/lib/profiles/image/state.json")
      )
      config_after = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert image_after == image_before, (image_before, image_after)
      assert config_after == config_before, (config_before, config_after)
      target.fail("test -e /var/lib/profiles/system/current")

      # No live configuration surface or daemon changed as a side effect.
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      target.succeed("systemctl is-active aos-upgrade-removed.service")
      target.fail("test -e /run/removed-stop-ran")
      assert target.succeed("cat /etc/nftables.conf") == nftd_before
      assert target.succeed("cat /etc/sysctl.d/10-aos-kernel.conf") == sysctld_before
      assert target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip() == baseline_keepalive
      assert int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip()) == http_pid_before
      assert int(target.succeed(
          "systemctl show -p MainPID --value dbus.service"
      ).strip()) == dbus_pid_before
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after rejected upgrade: {failed!r}"
    '';
}
