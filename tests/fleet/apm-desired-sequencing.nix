# tests/fleet/apm-desired-sequencing.nix - Desired add+prune ordering.
#
# Regression coverage for RFC-0001 P5 desired reconciliation: when a desired
# run both installs a package that needs generated config and prunes another
# package, exposed systemd reconciliation must happen after config
# materialization. If pruning starts the new package target too early, the
# config-gated service is skipped and a later start of the already-active
# target does not retry it.
{
  mkSystem,
  pkgs,
  ...
}: let
  system = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.desired-config-test = {
        package = pkgs.desired-config-test;
        bundle = true;
        preset = false;
      };
      aos.packages.desired-prune-test = {
        package = pkgs.desired-prune-test;
        bundle = true;
        preset = false;
      };
    }
  ];
in {
  name = "apm-desired-sequencing";
  timeout = 420;

  machines = {
    vm = {
      inherit system;
      # Package activation measures PCR 15, including the seed profile.
      tpm = true;
      # Seed only the package that the desired file will prune. The config
      # package is present in the image and registry fixture, but is not in the
      # package profile until `apm install --system --from` installs it.
      packages = ["desired-prune-test"];
    };
  };

  testScript =
    # python
    ''
      import textwrap

      vm.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      vm.wait_for_unit("aos-seed-baked-packages.service", timeout=120)
      vm.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      vm.succeed("${pkgs.nix}/bin/nix-store --check-validity '${pkgs.desired-config-test}'")
      vm.succeed("${pkgs.nix}/bin/nix-store --check-validity '${pkgs.desired-config-test.expose}'")
      vm.wait_until_succeeds(
          "systemctl is-active --quiet desired-prune-test.service", timeout=120
      )
      vm.succeed("test -f /var/lib/aos-pkg-desired-prune-test/started")
      vm.fail("test -e /etc/systemd/system.attached/desired-config-test.service")

      vm.succeed(
          textwrap.dedent("""
          set -eux

          export HOME=/tmp/desired-publisher
          export GIT_AUTHOR_NAME=Test
          export GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test
          export GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\n' > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.aos}/bin/apr create desired-reg
          ${pkgs.aos}/bin/apr publish '${pkgs.desired-config-test}' \
            --name desired-config-test \
            --version 1.0.0 \
            --description 'desired sequencing fixture' \
            --license MIT \
            --maintainer test \
            --expose-manifest '${pkgs.desired-config-test.expose}/manifest.json' \
            --registry desired-reg \
            --no-commit

          rm -rf /var/lib/apm/registries/desired-reg /var/lib/apm/remote/desired-reg
          mkdir -p /var/lib/apm/registries /var/lib/apm/remote /etc/apm/registries.d
          cp -a "$HOME/.local/share/apm/registries/desired-reg" /var/lib/apm/registries/desired-reg
          ln -sfn /var/lib/apm/registries/desired-reg /var/lib/apm/remote/desired-reg
          cat > /etc/apm/registries.d/desired-reg.toml <<'EOF'
          [registry]
          name = "desired-reg"
          url = "file:///nonexistent/desired-reg"
          priority = 500
          enabled = true

          [registry.signing]
          required = false
          EOF

          mkdir -p /etc/aos/packages.d
          cat > /etc/aos/packages.d/desired.toml <<'EOF'
          packages = ["desired-config-test"]

          [config.desired-config-test.env]
          TOKEN = "desired-token"
          EOF
          """),
          timeout=180,
      )

      out = vm.succeed(
          "HOME=/tmp/desired-run ${pkgs.aos}/bin/apm install --system "
          "--from /etc/aos/packages.d/desired.toml --yes 2>&1",
          timeout=240,
      )
      print("=== desired reconciliation output ===\\n" + out)
      assert "desired-config-test" in out, out

      env = vm.succeed("cat /etc/aos/packages/desired-config-test/config.env")
      assert "TOKEN=desired-token" in env, env
      vm.wait_until_succeeds(
          "systemctl is-active --quiet desired-config-test.service", timeout=60
      )
      marker = vm.succeed(
          "cat /var/lib/aos-pkg-desired-config-test/started"
      ).strip()
      assert marker == "desired-token", marker

      vm.succeed("test -L /etc/systemd/system.attached/desired-config-test.service")
      vm.fail("test -e /etc/systemd/system.attached/desired-prune-test.service")
      vm.fail("systemctl is-active --quiet desired-prune-test.service")
      vm.succeed(
          "grep -R '\"name\"[[:space:]]*:[[:space:]]*\"desired-config-test\"' "
          "/var/lib/profiles/system-packages/current/meta"
      )
      vm.fail(
          "grep -R '\"name\"[[:space:]]*:[[:space:]]*\"desired-prune-test\"' "
          "/var/lib/profiles/system-packages/current/meta"
      )
    '';
}
