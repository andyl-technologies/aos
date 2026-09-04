# Local maintainer package-update acceptance through the native AOS Hub.
#
# The maintainer receives the complete CLI and repository fixture as prebuilt
# store closures over read-only 9p. It then discovers a deterministic upstream
# tag through the test-only TLS edge, downloads candidate source bytes from the
# native Hub, and drives every local durable workflow boundary through the real
# `aos maintain` porcelain.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  releaseTool = pkgs.aos.testSupport;
  # The self-signed certificate is a public test trust anchor. Its matching
  # key is the repository's pre-existing release-fleet fixture key.
  caCertificate = builtins.readFile ../fixtures/maintainer-fleet-server.crt;
  styleHash = builtins.convertHash {
    hash = builtins.hashFile "sha256" ../../crates/aos-hub-core/src/web/static_assets/style.css;
    hashAlgo = "sha256";
    toHashFormat = "sri";
  };

  credentialFile = name: text:
    pkgs.writeTextFile {
      inherit name text;
      destination = "/value";
    };
  serverCertificate = credentialFile "maintainer-fleet-server-certificate" (builtins.readFile ../fixtures/maintainer-fleet-server.crt);
  serverPrivateKey = credentialFile "maintainer-fleet-server-private-key" (builtins.readFile ../fixtures/release-fleet-server.key);

  hubSystem = fixture.hubSystem.extendModules {
    modules = [
      {
        # The byte-forwarding test edge terminates TLS without minting trusted
        # transport evidence. Keep the native cleartext listener's authority
        # aligned with the Host header while clients exercise the HTTPS URL.
        aos.registry-hub.externalUrl = lib.mkForce "http://aos.andyl.org";
        aos.security.pki.certificates = [caCertificate];
        aos.firewall.allowedTCP = [443];
        environment.systemPackages = [releaseTool];

        systemd.services.maintainer-upstream-edge = {
          description = "Test-only native Hub edge and deterministic upstream";
          after = ["aos-hub.service"];
          serviceConfig = {
            Type = "simple";
            ExecStart = "${releaseTool}/bin/aos-release-fleet-fixture maintainer-upstream-proxy 0.0.0.0:443 127.0.0.1:8420 /run/credentials/maintainer-upstream-edge.service/certificate /run/credentials/maintainer-upstream-edge.service/private-key";
            LoadCredential = [
              "certificate:${serverCertificate}/value"
              "private-key:${serverPrivateKey}/value"
            ];
            DynamicUser = true;
            Restart = "on-failure";
            NoNewPrivileges = true;
            AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
            CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];
            PrivateTmp = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
          };
        };
      }
    ];
  };

  maintainerSystem = fixture.publisherSystem.extendModules {
    modules = [
      {
        aos.security.pki.certificates = [caCertificate];
      }
    ];
  };

  maintainerToolBundle = pkgs.mkDerivation {
    pname = "maintainer-update-e2e-tools";
    version = "1";
    src = null;
    runtimeDeps = [
      pkgs.aos
      pkgs.curl
      pkgs.git
      pkgs.jq
      pkgs.nix
      pkgs.util-linux
    ];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${pkgs.aos}/bin/aos "$out/bin/aos"
          ln -s ${pkgs.curl}/bin/curl "$out/bin/curl"
          ln -s ${pkgs.git}/bin/git "$out/bin/git"
          ln -s ${pkgs.jq}/bin/jq "$out/bin/jq"
          ln -s ${pkgs.nix}/bin/nix "$out/bin/nix"
          ln -s ${pkgs.nix}/bin/nix-build "$out/bin/nix-build"
          ln -s ${pkgs.nix}/bin/nix-instantiate "$out/bin/nix-instantiate"
          ln -s ${pkgs.nix}/bin/nix-store "$out/bin/nix-store"
          ln -s ${pkgs.util-linux}/bin/findmnt "$out/bin/findmnt"
          ln -s ${pkgs.util-linux}/bin/mount "$out/bin/mount"
        '';
      }
    ];
  };

  fixtureRepository = pkgs.mkDerivation {
    pname = "maintainer-update-e2e-repository";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/pkgs"
          cp ${../fixtures/maintainer-update-repo/default.nix} "$out/default.nix"
          cp ${../fixtures/maintainer-update-repo/pkgs/maintain-fixture.nix} \
            "$out/pkgs/maintain-fixture.nix"
          printf '%s\n' \
            '{' \
            '  bash = "${pkgs.bash}";' \
            '}' > "$out/fixture-inputs.nix"
        '';
      }
    ];
  };

  hostFixture = import ../fixtures/maintainer-update-repo/default.nix {
    bash = pkgs.bash;
  };
  mountedPackageDerivation = builtins.storePath (builtins.unsafeDiscardStringContext hostFixture.pkgs.maintain-fixture.drvPath);
  mountedSourceDerivation =
    builtins.storePath
    (builtins.unsafeDiscardStringContext
      (builtins.elemAt hostFixture.maintenanceInventory.units 0).components.main.sources.source.derivation);
  packageDerivationRecord = builtins.path {
    path = mountedPackageDerivation;
    name = "maintain-fixture-package-derivation-record";
  };
  sourceDerivationRecord = builtins.path {
    path = mountedSourceDerivation;
    name = "maintain-fixture-source-derivation-record";
  };

  mountedClosure = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = [
      fixtureRepository
      maintainerToolBundle
      packageDerivationRecord
      sourceDerivationRecord
    ];
    pname = "maintainer-update-e2e-closure-info";
  };
in {
  name = "maintainer-update-e2e";
  timeout = 2700;
  bootTimeout = 300;

  machines = {
    hub = {
      system = hubSystem;
      hostAliases = [
        "aos.andyl.org"
        "api.github.com"
      ];
      memoryMiB = 3072;
    };
    maintainer = {
      system = maintainerSystem;
      hostStoreMount = true;
      memoryMiB = 4096;
      varSizeMiB = 4096;
    };
  };

  testScript =
    # python
    ''
      import json
      import shlex
      import textwrap

      TOOLS = "${maintainerToolBundle}"
      AOS = TOOLS + "/bin/aos"
      CURL = TOOLS + "/bin/curl"
      CURL_CA = CURL + " --cacert /etc/ssl/certs/ca-certificates.crt"
      FINDMNT = TOOLS + "/bin/findmnt"
      GIT = TOOLS + "/bin/git"
      JQ = TOOLS + "/bin/jq"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      NIX = TOOLS + "/bin/nix --extra-experimental-features nix-command"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      CLOSURE_INFO = "${mountedClosure}"
      FIXTURE_REPOSITORY = "${fixtureRepository}"
      PACKAGE_DERIVATION = "${mountedPackageDerivation}"
      SOURCE_DERIVATION = "${mountedSourceDerivation}"
      PACKAGE_DERIVATION_RECORD = "${packageDerivationRecord}"
      SOURCE_DERIVATION_RECORD = "${sourceDerivationRecord}"
      REPOSITORY = "/var/lib/aos-maintainer/repository"
      STATE = "/var/lib/aos-maintainer/state"
      HOME = "/var/lib/aos-maintainer/home"
      EXPECTED_SOURCE_HASH = "${styleHash}"


      hub.wait_for_unit("multi-user.target", timeout=240)
      maintainer.wait_for_unit("multi-user.target", timeout=240)
      hub.succeed(textwrap.dedent("""
          systemctl is-active --quiet aos-hub.service
          systemctl start maintainer-upstream-edge.service
          systemctl is-active --quiet maintainer-upstream-edge.service
      """))

      # The dedicated tool and repository roots are absent before the 9p
      # import. The guest mounts the host store read-only, exposes the
      # registered tool closure and opaque package records at canonical paths,
      # and never builds those inputs.
      maintainer.fail(f"{NIX_STORE} --check-validity {TOOLS}")
      maintainer.fail(f"{NIX_STORE} --check-validity {FIXTURE_REPOSITORY}")
      maintainer.fail(f"test -e {PACKAGE_DERIVATION}")
      maintainer.fail(f"test -e {SOURCE_DERIVATION}")
      maintainer.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p /run/aos-host-store
          {MOUNT} -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \\
            aos-host-store /run/aos-host-store
          closure=/run/aos-host-store/$(basename {CLOSURE_INFO})
          test -r "$closure/registration"
          while IFS= read -r store_path; do
            if test ! -e "$store_path"; then
              source_path="/run/aos-host-store/$(basename "$store_path")"
              if test -L "$source_path"; then
                ln -s "$(readlink "$source_path")" "$store_path"
              elif test -d "$source_path"; then
                mkdir "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              elif test -f "$source_path"; then
                touch "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              else
                printf 'unsupported fixture store object: %s\n' "$source_path" >&2
                exit 1
              fi
            fi
          done < "$closure/store-paths"
          {NIX_STORE} --load-db < "$closure/registration"

          : > /tmp/derivation-registration
          register_derivation() {{
            derivation="$1"
            record="$2"
            source_path="/run/aos-host-store/$(basename "$record")"
            test -f "$source_path"
            touch "$derivation"
            {MOUNT} --bind "$source_path" "$derivation"
            printf '%s\n%s\n%s\n\n0\n' \
              "$derivation" \
              "$({NIX_STORE} --query --hash "$record")" \
              "$({NIX_STORE} --query --size "$record")" \
              >> /tmp/derivation-registration
          }}
          register_derivation {SOURCE_DERIVATION} {SOURCE_DERIVATION_RECORD}
          register_derivation {PACKAGE_DERIVATION} {PACKAGE_DERIVATION_RECORD}
          {NIX_STORE} --load-db < /tmp/derivation-registration

          {NIX_STORE} --check-validity {TOOLS}
          {NIX_STORE} --check-validity {FIXTURE_REPOSITORY}
          {NIX_STORE} --check-validity {PACKAGE_DERIVATION}
          {NIX_STORE} --check-validity {SOURCE_DERIVATION}
          {NIX} derivation show {PACKAGE_DERIVATION} | {JQ} -e '.derivations | length == 1'
          {NIX} derivation show {SOURCE_DERIVATION} | {JQ} -e '.derivations | length == 1'
          {FINDMNT} -rn -t 9p -o OPTIONS /run/aos-host-store | grep -qw ro
          ! touch {TOOLS}/host-store-write-must-fail
      """), timeout=240)

      # Both deterministic upstream discovery and candidate source retrieval
      # cross the TLS edge. The source route itself is served by the native Hub.
      maintainer.succeed(
          f"{CURL_CA} -fsS https://aos.andyl.org/healthz | grep -q ok"
      )
      maintainer.succeed(
          f"{CURL_CA} -fsS 'https://api.github.com/repos/andyl-technologies/maintain-fixture/tags?per_page=100&page=1' "
          "| grep -q 'v1.1.0'"
      )
      maintainer.succeed(
          f"{CURL_CA} -fsS https://aos.andyl.org/_assets/style.css -o /tmp/maintainer-style.css; "
          f"test \"$({NIX} hash file --sri /tmp/maintainer-style.css)\" = "
          f"{shlex.quote(EXPECTED_SOURCE_HASH)}"
      )

      maintainer.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p {REPOSITORY} {STATE} {HOME}
          cp -R {FIXTURE_REPOSITORY}/. {REPOSITORY}/
          chmod -R u+w {REPOSITORY}
          {GIT} -C {REPOSITORY} init -b main
          {GIT} -C {REPOSITORY} config user.name 'Fleet Maintainer'
          {GIT} -C {REPOSITORY} config user.email maintainer@example.test
          {GIT} -C {REPOSITORY} remote add origin \
            https://github.com/andyl-technologies/maintain-fixture
          {GIT} -C {REPOSITORY} add --all
          {GIT} -C {REPOSITORY} commit -m 'seed stale package fixture'
          {GIT} -C {REPOSITORY} update-ref refs/remotes/origin/main HEAD
          {GIT} -C {REPOSITORY} symbolic-ref \
            refs/remotes/origin/HEAD refs/remotes/origin/main
          test -z "$({GIT} -C {REPOSITORY} status --porcelain)"
          {NIX} config show sandbox | grep -qx true
      """), timeout=180)


      def invoke(arguments, expected="success", timeout=600):
          """Run one machine-readable maintainer command in the guest."""
          command = textwrap.dedent(f"""
              set -eu
              cd {REPOSITORY}
              export HOME={HOME}
              export USER=maintainer
              export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
              export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
              export NIX_CONFIG='experimental-features = nix-command'
              {AOS} maintain --state-dir {STATE} --json {arguments}
          """)
          status, stdout, stderr = maintainer.execute(command, timeout=timeout)
          try:
              result = json.loads(stdout)
          except json.JSONDecodeError as error:
              raise AssertionError((arguments, status, stdout, stderr)) from error
          assert result["schemaVersion"] == "aos.maintain.cli/v1", result
          assert result["disposition"] == expected, (arguments, result, stderr)
          assert result["exitCode"] == status, (arguments, result, stderr)
          return result


      def primary(result, name):
          """Return one named primary value from a maintainer completion."""
          matches = [
              value["value"]
              for value in result["primaryValues"]
              if value["name"] == name
          ]
          assert len(matches) == 1, (name, result)
          return matches[0]


      inventory = invoke("inventory --check", timeout=240)
      assert inventory["data"]["values"]["unitCount"] == "1", inventory
      assert inventory["data"]["values"]["fixedOutputsAudited"] == "1", inventory

      scan = invoke("scan", timeout=240)
      discovered = scan["data"]["discovery"]["units"]
      assert len(discovered) == 1, scan
      assert discovered[0]["decision"] == "update-available", discovered[0]
      component = discovered[0]["components"][0]
      assert component["decision"] == "update-available", component
      assert component["selected"]["comparisonVersion"] == "1.1.0", component

      plan = invoke("plan maintain-fixture-1")
      plan_id = primary(plan, "planId")
      plan_digest = plan["nextActions"][0]["boundContext"]
      assert plan["data"]["plan"]["quickGates"], plan
      assert plan["data"]["plan"]["finalGates"], plan

      started = invoke(
          "run --plan " + shlex.quote(plan_id)
          + " --confirm-plan " + shlex.quote(plan_digest)
          + " --until worktree-ready",
          timeout=240,
      )
      run_id = primary(started, "runId")
      assert started["data"]["run"]["state"] == "worktree-ready", started

      resumed = invoke(
          "resume " + shlex.quote(run_id) + " --until quick-gated",
          timeout=900,
      )
      assert resumed["data"]["run"]["state"] == "quick-gated", resumed
      assert resumed["data"]["values"]["resumedFrom"] == "worktree-ready", resumed
      worktree = resumed["data"]["run"]["worktree"]

      diff = invoke("diff " + shlex.quote(run_id))
      patch = diff["data"]["patch"]
      assert 'currentVersion = "1.1.0";' in patch, patch
      assert 'upstreamId = "v1.1.0";' in patch, patch
      assert EXPECTED_SOURCE_HASH in patch, patch

      acceptance = invoke("accept " + shlex.quote(run_id), "action-required")
      candidate_digest = acceptance["nextActions"][0]["boundContext"]
      accepted = invoke(
          "accept " + shlex.quote(run_id)
          + " --confirm " + shlex.quote(candidate_digest)
      )
      assert accepted["data"]["run"]["state"] == "candidate-accepted", accepted

      commit_preview = invoke("commit " + shlex.quote(run_id), "action-required")
      assert commit_preview["nextActions"][0]["effectClass"] == "human-decision"
      committed = invoke(
          "commit " + shlex.quote(run_id)
          + " --confirm " + shlex.quote(run_id)
      )
      assert committed["data"]["run"]["state"] == "committed", committed

      final = invoke("test " + shlex.quote(run_id) + " --final", timeout=900)
      assert final["data"]["run"]["state"] == "final-gated", final
      final_gates = final["data"]["gateResults"]
      assert len(final_gates) == 1 and final_gates[0]["phase"] == "final", final
      assert all(
          gate["outcome"] == "success"
          for gate in final_gates[0]["results"]
      ), final

      evidence = invoke("evidence " + shlex.quote(run_id))
      evidence_digest = primary(evidence, "evidenceDigest")
      dossier = evidence["data"]["evidence"]
      assert evidence["data"]["run"]["evidenceDigest"] == evidence_digest, evidence
      assert dossier["materialization"]["sources"][0]["finalUrl"] == \
          "https://aos.andyl.org/_assets/style.css", dossier
      assert dossier["materialization"]["confinement"]["nixSandboxVerified"], dossier
      assert dossier.get("repairAttempts", []) == [], dossier

      prepared = invoke("prepare-pr " + shlex.quote(run_id))
      draft = prepared["data"]["pullRequest"]
      assert draft["baseBranch"] == "main", draft
      assert draft["head"], draft
      assert draft["evidenceDigest"] == evidence_digest, draft
      assert "maintain-fixture-1" in draft["title"], draft

      inspected = invoke("inspect " + shlex.quote(run_id))
      assert inspected["data"]["run"]["evidenceDigest"] == evidence_digest, inspected
      active = invoke("status --active")
      assert active["data"]["runs"] == [], active

      maintainer.succeed(textwrap.dedent(f"""
          set -eu
          {GIT} -C {shlex.quote(worktree)} log -1 --format=%s \
            | grep -qx 'pkg: update maintain-fixture-1 to 1.1.0'
          test -z "$({GIT} -C {shlex.quote(worktree)} status --porcelain)"
          grep -q 'currentVersion = "1.1.0";' \
            {shlex.quote(worktree)}/pkgs/maintain-fixture.nix
          find {STATE} -type f -name journal.jsonl -exec \
            grep -q 'execute-final-gates' {{}} \\;
      """))
    '';
}
