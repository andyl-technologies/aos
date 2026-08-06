# tests/fleet/rfc-0011-secret-ref.nix — runtime secretRef acceptance.
{
  pkgs,
  systems,
  ...
}: let
  secretSystem = systems.server-test.extendModules {
    modules = [
      {
        aos.packages.aos-rfc0011-secret = {
          package = pkgs.aos-rfc0011-secret;
          bundle = true;
          preset = false;
        };
        # The in-guest publisher needs both registry-only artifacts. The
        # runtime package is bundled separately above.
        environment.systemPackages = [
          pkgs.aos-rfc0011-secret.expose
          pkgs.aos-rfc0011-secret.config
        ];
      }
    ];
  };
in {
  name = "rfc-0011-secret-ref";
  timeout = 1200;

  machines.target = {
    system = secretSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent" "aos-rfc0011-secret"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
      }
    '';
    extraModules = [
      {
        systemd.services.rfc0011-system-credential = {
          description = "Provide the RFC-0011 platform system credential";
          wantedBy = ["sysinit.target"];
          before = ["aos-eval.service"];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            set -eu
            mkdir -p /run/credentials/@system
            printf '%s' rfc0011-secret-alpha \
              > /run/credentials/@system/bootstrap-token
            chmod 0600 /run/credentials/@system/bootstrap-token
          '';
        };

        systemd.services.aos-eval = {
          requires = ["rfc0011-system-credential.service"];
          after = ["rfc0011-system-credential.service"];
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
      SOURCE = "/run/credstore/rfc0011/join-token"
      STATE = "/var/lib/aos-pkg-aos-rfc0011-secret"
      ALPHA = "rfc0011-secret-alpha"
      BETA = "rfc0011-secret-beta"


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
          export HOME=/tmp/rfc0011-secret-publisher
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/rfc0011-secret-nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\nsandbox = false\nbuild-users-group =\n' \
            > "$NIX_CONF_DIR/nix.conf"

          KEYGEN=$(${pkgs.aos}/bin/apr keys generate release \
            --registry rfc0011-secret-reg 2>&1)
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
          KEY=$HOME/.config/apm/keys/rfc0011-secret-reg-release.key
          ${pkgs.aos}/bin/apr create rfc0011-secret-reg \
            --trust-key "$PUBKEY" \
            --trust-key-id release \
            --key "$KEY"
          REG_DIR=$HOME/.local/share/apm/registries/rfc0011-secret-reg
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/rfc0011-secret-reg.toml" <<EOF
          [registry]
          name = "rfc0011-secret-reg"
          url = "file://$REG_DIR"

          [registry.signing_keys]
          release = "$KEY"
          EOF

          ${pkgs.aos}/bin/apr publish '${pkgs.aos-rfc0011-secret}' \
            --name aos-rfc0011-secret \
            --version 1.0.0 \
            --description 'RFC-0011 secret reference fixture' \
            --license MIT \
            --maintainer test \
            --expose-manifest '${pkgs.aos-rfc0011-secret.expose}/manifest.json' \
            --config-module '${pkgs.aos-rfc0011-secret.config}' \
            --config-base-lib '${secretSystem.config.aos.config.evalAtBoot.baseLib}' \
            --registry rfc0011-secret-reg \
            --key-id release
          mkdir -p /var/lib/rfc0011-secret-cache
          ${pkgs.aos}/bin/apr release 1.0.0 \
            --registry rfc0011-secret-reg \
            --key-id release \
            --cache-url file:///var/lib/rfc0011-secret-cache \
            --upload-url file:///var/lib/rfc0011-secret-cache
          HOME=/tmp USER=root ${pkgs.aos}/bin/apm registry --system add \
            "file://$REG_DIR" \
            --name rfc0011-secret-reg \
            --version '=1.0.0' \
            --trust-key "$PUBKEY"
          HOME=/tmp USER=root ${pkgs.aos}/bin/apm update \
            --system --registry rfc0011-secret-reg
      """), timeout=1200)

      first_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        \"aos-rfc0011-secret\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"rfc0011-secret-generation\".text = \"one\\n\";
      }
      """
      encoded = base64.b64encode(first_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-one.nix"
      )
      target.succeed(f"""
          if ! {APM} switch \
              --from /run/rfc0011-secret-one.nix \
              --eval-root /run/rfc0011-secret-first-switch; then
            systemctl --no-pager --full status \
              aos-config.target aos-fetch.target aos-config-render.target \
              aos-activate.service \
              'aos-pkg-fetch@aos-rfc0011-secret.service' \
              'aos-pkg-install@aos-rfc0011-secret.service' || true
            journalctl --no-pager -u aos-config.target -u aos-fetch.target \
              -u aos-config-render.target -u aos-activate.service \
              -u 'aos-pkg-fetch@aos-rfc0011-secret.service' \
              -u 'aos-pkg-install@aos-rfc0011-secret.service' || true
            exit 1
          fi
      """, timeout=300)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-rfc0011-secret.service", timeout=120
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
      reference = manifest["credentials"]["aos-rfc0011-secret"]["join-token"]
      assert reference == {
          "name": "join-token",
          "source": SOURCE,
          "encrypted": False,
          "units": ["aos-rfc0011-secret.service"],
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
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        \"aos-rfc0011-secret\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"rfc0011-secret-generation\".text = \"two\\n\";
      }
      """
      encoded = base64.b64encode(second_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-two.nix"
      )
      second_switch = target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-two.nix \
            --eval-root /run/rfc0011-secret-switch
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
                aos-rfc0011-secret.service || true
              journalctl --no-pager -u aos-rfc0011-secret.service || true
              printf '%s\n' '--- current credential reference ---'
              {JQ} '.credentials."aos-rfc0011-secret"."join-token"' \
                /run/aos/manifest.json || true
          """)
          raise AssertionError(
              f"consumer observed {observed!r}, expected {BETA!r}\n"
              f"switch output:\n{second_switch}\n{diagnostics}"
          )
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 2")
      target.succeed(f"test \"$(cat {STATE}/attempt-count)\" = 2")
      target.succeed("systemctl is-active --quiet aos-rfc0011-secret.service")
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
      target.succeed("systemctl is-active --quiet aos-rfc0011-secret.service")
      assert_no_plaintext(first, ALPHA, BETA)

      # Credential rotation never activates a stopped consumer. Removing the
      # authenticated handle then prunes the previously managed source while
      # leaving that consumer in its exact pre-transaction state.
      target.succeed("systemctl stop aos-rfc0011-secret.service")
      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      inactive_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        \"aos-rfc0011-secret\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"rfc0011-secret-generation\".text = \"inactive\\n\";
      }
      """
      encoded = base64.b64encode(inactive_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-inactive.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-inactive.nix \
            --eval-root /run/rfc0011-secret-inactive-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-rfc0011-secret.service")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 3")
      target.succeed(f"test \"$(cat {SOURCE})\" = {BETA}")

      removed_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        environment.etc.\"rfc0011-secret-generation\".text = \"removed\\n\";
      }
      """
      encoded = base64.b64encode(removed_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-removed.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-removed.nix \
            --eval-root /run/rfc0011-secret-removed-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-rfc0011-secret.service")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 3")
      target.succeed(f"test ! -e {SOURCE}")
    '';
}
