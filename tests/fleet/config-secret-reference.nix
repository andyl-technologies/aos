# Runtime secretRef acceptance.
{
  pkgs,
  systems,
  ...
}: let
  secretSystem = systems.server-test.extendModules {
    modules = [
      {
        aos.packages.aos-secret-reference-test = {
          package = pkgs.aos-secret-reference-test;
          bundle = true;
          preset = false;
        };
        # The in-guest publisher needs both registry-only artifacts. The
        # runtime package is bundled separately above.
        environment.systemPackages = [
          pkgs.aos-secret-reference-test.expose
          pkgs.aos-secret-reference-test.config
        ];
      }
    ];
  };
in {
  name = "config-secret-reference";
  timeout = 1200;

  machines.target = {
    system = secretSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent" "aos-secret-reference-test"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
      }
    '';
    extraModules = [
      {
        systemd.services.secret-reference-system-credential = {
          description = "Provide the platform system credential";
          wantedBy = ["sysinit.target"];
          before = ["aos-eval.service"];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            set -eu
            mkdir -p /run/credentials/@system
            printf '%s' secret-reference-test-alpha \
              > /run/credentials/@system/bootstrap-token
            chmod 0600 /run/credentials/@system/bootstrap-token
          '';
        };

        systemd.services.aos-eval = {
          requires = ["secret-reference-system-credential.service"];
          after = ["secret-reference-system-credential.service"];
        };
      }
    ];
  };

  testScript =
    # python
    ''
      import base64
      import json
      import textwrap

      APM = "${pkgs.aos}/bin/apm"
      JQ = "${pkgs.jq}/bin/jq"
      SOURCE = "/run/credstore/secret-reference-test/join-token"
      STATE = "/var/lib/aos-pkg-aos-secret-reference-test"
      ALPHA = "secret-reference-test-alpha"
      BETA = "secret-reference-test-beta"


      def current_generation():
          return int(target.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def assert_no_plaintext(generation, *values):
          manifest = target.succeed("cat /run/aos/manifest.json")
          retained = target.succeed(
              f"cat /var/lib/profiles/system/gen-{generation}/manifest.json"
          )
          for value in values:
              assert value not in manifest, "plaintext credential leaked into live manifest"
              assert value not in retained, "plaintext credential leaked into retained manifest"
              target.succeed(f"""
                  if ${pkgs.grep}/bin/grep -R -F -- {value} \
                    /var/lib/profiles/system/gen-{generation}; then
                    echo 'plaintext credential leaked into generation files' >&2
                    exit 1
                  fi
              """)


      target.wait_until_succeeds("""
          systemctl is-active --quiet aos-graph-compile.service ||
            systemctl is-failed --quiet aos-eval.service ||
            systemctl is-failed --quiet aos-graph-compile.service
      """, timeout=300)
      graph_status = target.succeed(
          "systemctl is-active aos-graph-compile.service || true"
      ).strip()
      if graph_status != "active":
          diagnostics = target.succeed("""
              systemctl --no-pager --full status \
                aos-seed-baked-packages.service aos-eval.service \
                aos-graph-compile.service || true
              journalctl --no-pager -u aos-seed-baked-packages.service || true
              journalctl --no-pager -u aos-eval.service \
                -u aos-graph-compile.service || true
          """)
          raise AssertionError(
              f"configuration pipeline did not become active: {graph_status}\\n"
              f"{diagnostics}"
          )
      target.succeed("systemctl is-active --quiet aos-credential-recovery.service")
      recovery_before = target.succeed(
          "systemctl show -P Before aos-credential-recovery.service"
      ).split()
      assert "aos-eval.service" in recovery_before, recovery_before
      assert "sysinit.target" in recovery_before, recovery_before
      target.succeed(
          "test \"$(stat -c %a /var/lib/apm/credential-transactions)\" = 700"
      )

      # Runtime selection is registry-authenticated even when the exact output
      # is already bundled in the image. Publish the fixture, install the
      # signed registry snapshot, then drive the first secret-bearing
      # generation through the production switch path.
      target.succeed(textwrap.dedent(r"""
          set -eu
          export HOME=/tmp/secret-reference-test-publisher
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/secret-reference-test-nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\nsandbox = false\nbuild-users-group =\n' \
            > "$NIX_CONF_DIR/nix.conf"

          KEYGEN=$(${pkgs.aos}/bin/apr keys generate release \
            --registry secret-reference-test-reg 2>&1)
          printf '%s\n' "$KEYGEN"
          PUBKEY=
          while IFS= read -r line; do
            case "$line" in
              *'Public key: '*) PUBKEY=''${line##* } ;;
            esac
          done <<EOF
          $KEYGEN
          EOF
          test -n "$PUBKEY"
          KEY=$HOME/.config/apm/keys/secret-reference-test-reg-release.key
          ${pkgs.aos}/bin/apr create secret-reference-test-reg \
            --trust-key "$PUBKEY" \
            --trust-key-id release \
            --key "$KEY"
          REG_DIR=$HOME/.local/share/apm/registries/secret-reference-test-reg
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/secret-reference-test-reg.toml" <<EOF
          [registry]
          name = "secret-reference-test-reg"
          url = "file://$REG_DIR"

          [registry.signing_keys]
          release = "$KEY"
          EOF

          ${pkgs.aos}/bin/apr publish '${pkgs.aos-secret-reference-test}' \
            --name aos-secret-reference-test \
            --version 1.0.0 \
            --description 'Secret reference fixture' \
            --license MIT \
            --maintainer test \
            --expose-manifest '${pkgs.aos-secret-reference-test.expose}/manifest.json' \
            --config-module '${pkgs.aos-secret-reference-test.config}' \
            --config-base-lib '${secretSystem.config.aos.config.evalAtBoot.baseLib}' \
            --registry secret-reference-test-reg \
            --key-id release
          mkdir -p /var/lib/secret-reference-test-cache
          ${pkgs.aos}/bin/apr release 1.0.0 \
            --registry secret-reference-test-reg \
            --key-id release \
            --cache-url file:///var/lib/secret-reference-test-cache \
            --upload-url file:///var/lib/secret-reference-test-cache
          HOME=/tmp USER=root ${pkgs.aos}/bin/apm registry --system add \
            "file://$REG_DIR" \
            --name secret-reference-test-reg \
            --version '=1.0.0' \
            --trust-key "$PUBKEY"
          HOME=/tmp USER=root ${pkgs.aos}/bin/apm update \
            --system --registry secret-reference-test-reg
      """), timeout=1200)

      first_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-secret-reference-test\" ];
        \"aos-secret-reference-test\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"secret-reference-test-generation\".text = \"one\\n\";
      }
      """
      encoded = base64.b64encode(first_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/secret-reference-test-one.nix"
      )
      target.succeed(f"""
          if ! {APM} switch \
              --from /run/secret-reference-test-one.nix \
              --eval-root /run/secret-reference-test-first-switch; then
            systemctl --no-pager --full status \
              aos-config.target aos-fetch.target aos-config-render.target \
              aos-activate.service \
              'aos-pkg-fetch@aos-secret-reference-test.service' \
              'aos-pkg-install@aos-secret-reference-test.service' || true
            journalctl --no-pager -u aos-config.target -u aos-fetch.target \
              -u aos-config-render.target -u aos-activate.service \
              -u 'aos-pkg-fetch@aos-secret-reference-test.service' \
              -u 'aos-pkg-install@aos-secret-reference-test.service' || true
            exit 1
          fi
      """, timeout=300)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-secret-reference-test.service", timeout=120
      )
      first = current_generation()
      target.succeed(f"test \"$(cat {SOURCE})\" = {ALPHA}")
      target.succeed(f"test \"$(stat -c %a {SOURCE})\" = 600")
      target.succeed(f"test \"$(cat {STATE}/observed)\" = {ALPHA}")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 1")
      target.succeed(f"test \"$(cat {STATE}/attempt-count)\" = 1")
      # systemd mounted a private credential file before ExecStart; the
      # consumer records its delivery mode while the namespace exists.
      delivery_mode = target.succeed(f"cat {STATE}/delivery-mode").strip()
      assert delivery_mode == "440", delivery_mode

      manifest = json.loads(target.succeed("cat /run/aos/manifest.json"))
      reference = manifest["credentials"]["aos-secret-reference-test"]["join-token"]
      assert reference == {
          "name": "join-token",
          "source": SOURCE,
          "encrypted": False,
          "units": ["aos-secret-reference-test.service"],
          "ref": "system-credential:bootstrap-token",
      }, reference
      assert_no_plaintext(first, ALPHA)

      # Rotate only the platform system credential. A new host generation
      # causes the same secretRef to resolve again; changed bytes are written
      # atomically before the consumer is restarted exactly once.
      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      second_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-secret-reference-test\" ];
        \"aos-secret-reference-test\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"secret-reference-test-generation\".text = \"two\\n\";
      }
      """
      encoded = base64.b64encode(second_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/secret-reference-test-two.nix"
      )
      second_switch = target.succeed(f"""
          {APM} switch \
            --from /run/secret-reference-test-two.nix \
            --eval-root /run/secret-reference-test-switch
      """, timeout=300)

      second = current_generation()
      assert second != first, (first, second)
      target.succeed(f"test \"$(cat {SOURCE})\" = {BETA}")
      target.succeed(f"test \"$(stat -c %a {SOURCE})\" = 600")
      observed = target.succeed(f"cat {STATE}/observed").strip()
      if observed != BETA:
          diagnostics = target.succeed(f"""
              printf '%s\n' '--- consumer state ---'
              cat {STATE}/start-count {STATE}/attempt-count || true
              systemctl --no-pager --full status \
                aos-secret-reference-test.service || true
              journalctl --no-pager -u aos-secret-reference-test.service || true
              printf '%s\n' '--- current credential reference ---'
              {JQ} '.credentials."aos-secret-reference-test"."join-token"' \
                /run/aos/manifest.json || true
          """)
          raise AssertionError(
              f"consumer observed {observed!r}, expected {BETA!r}\n"
              f"switch output:\n{second_switch}\n{diagnostics}"
          )
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 2")
      target.succeed(f"test \"$(cat {STATE}/attempt-count)\" = 2")
      target.succeed("systemctl is-active --quiet aos-secret-reference-test.service")
      assert_no_plaintext(second, ALPHA, BETA)

      # A same-ABI retained-generation rollback must traverse the same
      # credential barrier. Rotate the platform source again without
      # re-evaluation, reactivate the retained generation, and prove that the
      # old direct path cannot leave the newer published bytes behind.
      target.succeed(f"""
          printf '%s' {ALPHA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
          {APM} rollback --system --generation {first}
      """, timeout=300)
      assert current_generation() == first
      target.succeed(f"test \"$(cat {SOURCE})\" = {ALPHA}")
      target.succeed(f"test \"$(cat {STATE}/observed)\" = {ALPHA}")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 3")
      target.succeed(f"test \"$(cat {STATE}/attempt-count)\" = 3")
      target.succeed("systemctl is-active --quiet aos-secret-reference-test.service")
      assert_no_plaintext(first, ALPHA, BETA)

      # Credential rotation never activates a stopped consumer. Removing the
      # authenticated handle then prunes the previously managed source while
      # leaving that consumer in its exact pre-transaction state.
      target.succeed("systemctl stop aos-secret-reference-test.service")
      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      inactive_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-secret-reference-test\" ];
        \"aos-secret-reference-test\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"secret-reference-test-generation\".text = \"inactive\\n\";
      }
      """
      encoded = base64.b64encode(inactive_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/secret-reference-test-inactive.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/secret-reference-test-inactive.nix \
            --eval-root /run/secret-reference-test-inactive-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-secret-reference-test.service")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 3")
      target.succeed(f"test \"$(cat {SOURCE})\" = {BETA}")

      removed_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-secret-reference-test\" ];
        environment.etc.\"secret-reference-test-generation\".text = \"removed\\n\";
      }
      """
      encoded = base64.b64encode(removed_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/secret-reference-test-removed.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/secret-reference-test-removed.nix \
            --eval-root /run/secret-reference-test-removed-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-secret-reference-test.service")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 3")
      target.succeed(f"test ! -e {SOURCE}")
    '';
}
