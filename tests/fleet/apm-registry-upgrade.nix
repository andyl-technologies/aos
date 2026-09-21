# tests/fleet/apm-registry-upgrade.nix - Refuse a downloaded incomplete image.
#
# The networked counterpart of apm-system-upgrade.nix publishes a signed
# sysroot package and full static cache, then resolves, downloads, verifies,
# and imports the generation delta through the normal registry porcelain.
# The catalog deliberately omits an authenticated raw OTA image. Image-based
# systems must reject this incomplete candidate without creating a config
# generation, changing boot selection, or activating any live system policy.
# Full A/B upgrade and rollback behavior is covered by system-image-rollback.
#
# The target begins without the candidate closure. Store validity checks,
# download output, and HTTP NAR requests prove the network transfer completed
# before the exact missing-image rejection is accepted.
#
# Machines (lexicographic order: registry=192.168.50.10, target=192.168.50.11):
#   registry: aos-registry-server package (gitd :9418, cache :15000)
#             + static-cache package (:8000)
#             + extraClosures = [server2Top] (the producer owns the
#             closure) + a /var big enough for the compressed full-closure
#             static cache (~540 MiB).
#   target:   direct upgrade HTTP fixture (same reconcile surface as
#             apm-system-upgrade.nix so its refusal assertions carry over). No
#             extraClosures; the delta must come off the wire, but a
#             /var big enough for the NAR cache + imported store paths
#             (the /nix overlay upper lives on the var partition).
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

  # Both machines boot with a baked /var, so the
  # guest agent rides the /var seed; identity + the seeded package list are
  # baked into /etc. They hand-seed the registry (git) and probe HTTP/firewall
  # (curl/nft).
  # server-test provides the bundled agent + those CLI tools (the production
  # server keeps both out of the slim image). The registry additionally
  # re-bundles its fixtures.
  registrySystem = fleetSystem (mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
      # The static server binds this directory before publication fills it.
      environment.etc."tmpfiles.d/fleet-registry-cache.conf".text = ''
        d /var/lib/sysreg-cache 0755 root root - -
      '';
    }
  ]);

  targetSystem = fleetSystem (mkSystem [
    ../../systems/server-test.nix
    (import ../../systems/_upgrade-http-fixture.nix {
      inherit lib pkgs;
      generation = 1;
    })
  ]);

  server2Top = systems.server-2.config.system.build.toplevel;
in {
  name = "apm-registry-upgrade";
  # Two VM boots + fixture/package activation + full-closure static cache generation
  # (zstd over ~1.6 GB) + ~270 MiB cross-VM NAR transfer, verified import,
  # and unchanged-state assertions. Allow sandbox CPU/IO contention.
  timeout = 1800;
  # Guest initialization and metadata reconciliation precede the scenario.
  bootTimeout = 600;
  systemReadyTimeout = 300;

  machines = {
    registry = {
      system = registrySystem;
      packages = ["aos-registry-server" "test-static-cache-server"];
      metadata."host.nix" = ''
        {
          aos.networking.hostName = "registry";
          aos.apm.desiredPackages = ["aos-registry-server" "test-static-cache-server"];
          "aos-registry-server".enable = true;
          "test-static-cache-server".enable = true;
        }
      '';
      extraClosures = [server2Top pkgs.aos.apr];
      # `apr cache generate` rewrites the FULL ~1.5 GiB system closure into
      # the registry store under /var/lib AND writes the compressed static
      # cache (~540 MiB) alongside it, so /var needs well over 1.5 GiB free.
      # 1536 MiB (the old baked size) overflowed mid-generation; 3072 MiB
      # matches install-from-image.nix's headroom for the same workload.
      # Identity is baked into /etc and /var into the per-machine
      # disk at this size (baking identity already forks the image per machine,
      # so a shared var-less base buys nothing here).
      varSizeMiB = 3072;
      varProvisioning = "baked";
    };

    target = {
      system = targetSystem;
      # The download lands twice on /var: the NAR cache under
      # /var/lib/apm/cache (~270 MiB compressed for the gen-2 delta)
      # AND the imported store paths (the /nix overlay upper lives on
      # the var partition). Sized to match the registry for headroom.
      varSizeMiB = 3072;
      varProvisioning = "baked";
    };
  };

  testScript =
    # python
    ''
      import json
      import textwrap

      # -- 1. Both machines up; registry packages active -----------------
      registry.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      target.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=120)
      registry.wait_for_unit("aos-pkg-aos-registry-server-firewall.service", timeout=120)
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-aos-registry-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-test-static-cache-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active test-static-cache-server.socket", timeout=120
      )
      target.wait_until_succeeds(
          "systemctl is-active test-http-server.service", timeout=120
      )

      # -- 2. Target preconditions: gen-1, closure absent, baselines -----
      target.succeed("test -L /var/lib/profiles/system/current")
      gen_before = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_before == "gen-1", f"expected gen-1, got {gen_before!r}"

      image_before = json.loads(target.succeed("cat /var/lib/profiles/image/state.json"))
      config_before = json.loads(target.succeed("cat /var/lib/profiles/system/state.json"))
      boot_before = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      os_release_before = target.succeed("cat /etc/os-release")
      etc_before = target.succeed("readlink /run/etc/system").strip()

      # The Nix DB must be seeded before a check-validity failure is
      # meaningful (an absent DB also fails the check).
      target.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      # The miss is intentional; keep nix-store's expected error off the
      # serial console so unexpected warnings remain visible.
      target.fail(
          "${pkgs.nix}/bin/nix-store --check-validity '${server2Top}' "
          "> /tmp/server2-validity-precheck.out 2>&1"
      )

      # gen-2-only surfaces absent; gen-1 baselines (same as
      # apm-system-upgrade.nix).
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      target.wait_until_succeeds(
          "systemctl is-active aos-upgrade-removed.service", timeout=120
      )
      target.fail("test -e /run/removed-stop-ran")
      baseline_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert baseline_keepalive == "7200", (
          f"unexpected baseline keepalive {baseline_keepalive!r}"
      )
      nftd_before = target.succeed(
          "cat /etc/nftables.conf"
      )
      assert "8443" not in nftd_before, "gen-1 should not yet open port 8443"
      sysctld_before = target.succeed("cat /etc/sysctl.d/10-aos-kernel.conf")
      assert "tcp_keepalive_time" not in sysctld_before, sysctld_before

      # A rejected image must not restart the running service.
      http_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())

      # -- 3. Producer: publish the gen-2 closure to the registry --------
      # One bash block: registry create, sysroot
      # publish against the real /nix/store, full-closure static cache into
      # /var/lib/sysreg-cache (served on :8000), commit+tag+push to the gitd origin.
      # `apr publish` shells out to `nix path-info` (a nix-command CLI), so
      # a writable conf dir enables the feature, same as tests/vm/apm's
      # setupNixEnv. Generous timeout: the cache step zstd-compresses the
      # ~1.6 GB closure.
      registry.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      registry.succeed(textwrap.dedent("""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'

          # Privileged sysroot provenance names a signer in the registry roster.
          ${pkgs.aos.apr}/bin/apr keys generate release --registry sysreg \\
            > /tmp/sysreg-keygen.out 2>&1
          PUBLIC_KEY=$(${pkgs.gawk}/bin/awk '/Public key:/ {print $NF; exit}' /tmp/sysreg-keygen.out)
          SIGNING_KEY=$HOME/.config/apm/keys/sysreg-release.key
          ${pkgs.aos.apr}/bin/apr create sysreg \\
            --trust-key "$PUBLIC_KEY" --trust-key-id release --key "$SIGNING_KEY"
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/sysreg.toml" <<EOF
          [registry]
          name = "sysreg"
          url = "file://$HOME/.local/share/apm/registries/sysreg"

          [registry.signing_keys]
          release = "$SIGNING_KEY"
          EOF
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"

          ${pkgs.aos.apr}/bin/apr publish '${server2Top}' \\
            --name aos \\
            --version test-2 \\
            --description 'registry upgrade fixture' \\
            --license MIT \\
            --maintainer test \\
            --sysroot \\
            --no-ca \\
            --registry sysreg \\
            --key-id release \\
            --no-commit
          ${pkgs.aos.apr}/bin/apr verify --registry sysreg

          ${pkgs.aos.apr}/bin/apr cache generate \\
            --registry sysreg \\
            --output /var/lib/sysreg-cache \\
            --cache-url http://registry:8000/sysreg-cache \\
            --priority 46 \\
            --no-commit
          chmod -R a+rX /var/lib/sysreg-cache

          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" commit -m 'release: aos test-2'
          git -C "$REG_DIR" tag v1.0.0
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          # Resolve ownership through the daemon's idmapped state directory.
          git_pid=$(systemctl show -p MainPID --value aos-registry-server-gitd.service)
          test "$git_pid" -gt 0
          git_owner=$(id -u aos-gitd):$(id -g aos-gitd)
          ${pkgs.util-linux}/bin/nsenter --target "$git_pid" --mount --root --wd=/ ${pkgs.coreutils}/bin/chown -R "$git_owner" "$ORIGIN"
      """), timeout=1200)

      # Cache reachable from the target over the fleet L2.
      registry.wait_until_succeeds(
          "curl -sf --max-time 5 http://127.0.0.1:8000/sysreg-cache/nix-cache-info",
          timeout=60,
      )
      target.wait_until_succeeds(
          "curl -sf --max-time 5 http://registry:8000/sysreg-cache/nix-cache-info",
          timeout=60,
      )

      # -- 4. Consumer: stage the registry in SYSTEM scope ---------------
      # Use the durable catalog porcelain, including its normal Git runtime.
      branch = registry.succeed(
          "git -C /tmp/.local/share/apm/registries/sysreg symbolic-ref --short HEAD"
      ).strip()
      target.succeed(
          "HOME=/tmp USER=root ${pkgs.aos.apm}/bin/apm registry --system add "
          "--no-verify git://registry:9418/sysreg --name sysreg --priority 500 "
          f"--branch {branch}",
          timeout=120,
      )
      target.succeed(
          "HOME=/tmp USER=root ${pkgs.aos.apm}/bin/apm update --system "
          "--registry sysreg 2>&1",
          timeout=120,
      )

      # -- 5. Dry-run surfaces the upgrade -------------------------------
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos.apm}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface the test-2 target: {out!r}"
      assert "0.1.0" in out, f"dry-run did not name the current 0.1.0 gen: {out!r}"

      # -- 6. Download and import succeed; missing OTA metadata is rejected ---
      target.succeed(
          "if HOME=/tmp ${pkgs.aos.apm}/bin/apm upgrade --system --yes "
          "> /tmp/apm-registry-upgrade.out 2>&1; then exit 1; fi",
          timeout=900,
      )
      out = target.succeed("cat /tmp/apm-registry-upgrade.out")
      print("=== rejected apm upgrade --system output ===\n" + out)
      assert "Downloading" in out, (
          f"upgrade did not download anything - closure leaked onto the "
          f"target some other way: {out!r}"
      )
      assert "no authenticated raw OTA image" in out, out
      target.succeed("${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'")

      # The registry's http.server logged NAR GETs from the target;
      # network-transfer proof on the serving side.
      journal = registry.succeed("journalctl -u test-static-cache-server --no-pager")
      assert "GET /sysreg-cache/nar/" in journal, (
          "no NAR fetch logged by the registry's static cache server"
      )

      # -- 7. Image, configuration, and every live policy surface are unchanged ---
      image_after = json.loads(target.succeed("cat /var/lib/profiles/image/state.json"))
      config_after = json.loads(target.succeed("cat /var/lib/profiles/system/state.json"))
      assert image_after == image_before, (image_before, image_after)
      assert config_after == config_before, (config_before, config_after)
      assert target.succeed("readlink /var/lib/profiles/system/current").strip() == gen_before
      assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_before
      assert target.succeed("cat /etc/os-release") == os_release_before
      assert target.succeed("readlink /run/etc/system").strip() == etc_before
      assert target.succeed("cat /etc/nftables.conf") == nftd_before
      assert target.succeed("cat /etc/sysctl.d/10-aos-kernel.conf") == sysctld_before
      assert target.succeed("cat /proc/sys/net/ipv4/tcp_keepalive_time").strip() == baseline_keepalive
      assert "8443" not in target.succeed("nft list set inet filter allowed_tcp")
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      target.succeed("systemctl is-active aos-upgrade-removed.service")
      target.fail("test -e /run/removed-stop-ran")
      assert int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip()) == http_pid_before
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after rejected upgrade: {failed!r}"
    '';
}
