##! Shared signed-package and runtime fixtures for native PostgreSQL abilities.
{
  lib,
  mkSystem,
  pkgs,
  guestTools ? false,
}: let
  packageSet = import ../abilities/reference-postgresql/package.nix {
    inherit lib;
    inherit (pkgs) bash coreutils jq mkDerivation postgresql writeTextFile;
    packageRuntime = pkgs.aos.packageRuntime;
  };

  stoppedPostgresqlSource = builtins.toFile "stopped-postgresql.c" ''
    #include <signal.h>
    #include <unistd.h>

    __attribute__((constructor)) static void stop_before_postgresql_main(void) {
      if (raise(SIGSTOP) != 0) {
        _exit(125);
      }
    }
  '';
  stoppedPostgresqlPreload = pkgs.mkDerivation {
    pname = "ability-reference-postgresql-stopped-preload";
    version = "1.0.0";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib"
          "$CC" -shared -fPIC -Wall -Wextra -Werror \
            ${stoppedPostgresqlSource} \
            -o "$out/lib/stopped-postgresql.so"
        '';
      }
    ];
  };

  orderedPackages =
    [
      {
        name = "ability-reference-postgresql-consumer";
        package = packageSet.consumer;
      }
      {
        name = "ability-reference-postgresql";
        package = packageSet.suite;
      }
      {
        name = "ability-reference-postgresql-upgrade";
        package = packageSet.upgradeSuite;
      }
    ]
    ++ map (faultPoint: {
      name = "ability-reference-postgresql-fault-${faultPoint}";
      package = packageSet.faultSuites.${faultPoint};
    }) (builtins.attrNames packageSet.faultSuites);

  packageRoots = lib.concatMap (entry: [entry.package entry.package.abilities]) orderedPackages;

  runtimeModules = [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.grep
        pkgs.nftables
        pkgs.postgresql
        pkgs.socat
      ];
    }
  ];
  runtimeSystem = mkSystem runtimeModules;

  qualificationSetupBody = ''
    environment.systemPackages = [
      pkgs.iproute2
      pkgs.grep
      pkgs.nftables
      pkgs.postgresql
      pkgs.socat
    ];
  '';
  qualificationExtraClosures =
    packageRoots
    ++ [
      pkgs.aos.testSupport
      pkgs.coreutils
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.iproute2
      pkgs.jq
      pkgs.nftables
      pkgs.nix
      pkgs.postgresql
      pkgs.socat
      pkgs.util-linux
      stoppedPostgresqlPreload
    ];
  qualificationCandidateRuntimeCompanions = map (entry: {
    inherit (entry) name;
    primary = entry.package;
    abilities = entry.package.abilities;
    originalRuntime = pkgs.aos.packageRuntime;
  }) (builtins.filter (entry: entry.name != "ability-reference-postgresql-consumer") orderedPackages);
in {
  inherit
    orderedPackages
    packageRoots
    packageSet
    qualificationExtraClosures
    qualificationCandidateRuntimeCompanions
    qualificationSetupBody
    runtimeModules
    runtimeSystem
    ;

  extraClosures =
    if guestTools
    then qualificationExtraClosures
    else
      qualificationExtraClosures
      ++ [
        pkgs.aos
        pkgs.aos.apm
        pkgs.aos.apr
      ];

  testPrelude =
    # python
    ''
      import base64
      import hashlib
      import json
      import shlex
      import textwrap

      AOS = ${
        if guestTools
        then ''runtime.guest_tool("aos")''
        else builtins.toJSON "${pkgs.aos}/bin/aos"
      }
      APM = ${
        if guestTools
        then ''runtime.guest_tool("apm")''
        else builtins.toJSON "${pkgs.aos.apm}/bin/apm"
      }
      APR = ${
        if guestTools
        then ''runtime.guest_tool("apr")''
        else builtins.toJSON "${pkgs.aos.apr}/bin/apr"
      }
      COREUTILS = "${pkgs.coreutils}/bin"
      FIND = "${pkgs.findutils}/bin/find"
      FIXTURE = "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture"
      GIT = "${pkgs.git}/bin/git"
      GREP = "${pkgs.grep}/bin/grep"
      IP = "${pkgs.iproute2}/sbin/ip"
      JQ = "${pkgs.jq}/bin/jq"
      NFT = "${pkgs.nftables}/sbin/nft"
      NIX_BIN = "${pkgs.nix}/bin"
      NIX_INSTANTIATE = "${pkgs.nix}/bin/nix-instantiate"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      PACKAGE_RUNTIME = "${pkgs.aos.packageRuntime}"
      PG_ISREADY = "${pkgs.postgresql}/bin/pg_isready"
      PSQL = "${pkgs.postgresql}/bin/psql"
      PRLIMIT = "${pkgs.util-linux}/bin/prlimit"
      SETPRIV = "${pkgs.util-linux}/bin/setpriv"
      SOCAT = "${pkgs.socat}/bin/socat"
      STOPPED_POSTGRESQL_PRELOAD = "${stoppedPostgresqlPreload}/lib/stopped-postgresql.so"

      REFERENCE_PACKAGES = ${
        if guestTools
        then "runtime.candidate_handler_packages("
        else ""
      }${builtins.toJSON (map (entry: {
          inherit (entry) name;
          package = builtins.toString entry.package;
          abilities = builtins.toString entry.package.abilities;
        })
        orderedPackages)}${
        if guestTools
        then ")"
        else ""
      }


      def publish_postgresql_packages():
          package_arguments = " ".join(
              " ".join(
                  shlex.quote(value)
                  for value in (entry["name"], entry["package"], entry["abilities"])
              )
              for entry in REFERENCE_PACKAGES
          )
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
              export GIT_AUTHOR_NAME='Ability Fleet Fixture'
              export GIT_AUTHOR_EMAIL=ability-fleet@example.test
              export GIT_COMMITTER_NAME='Ability Fleet Fixture'
              export GIT_COMMITTER_EMAIL=ability-fleet@example.test
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/ability-nix-conf
              export XDG_CONFIG_HOME=/tmp/ability-user-config
              export XDG_DATA_HOME=/tmp/ability-user-data
              mkdir -p "$NIX_CONF_DIR"
              printf 'experimental-features = nix-command\\nsandbox = false\\n' \\
                > "$NIX_CONF_DIR/nix.conf"

              {APR} keys generate release --registry ability-reg \\
                > /tmp/ability-keygen.out 2>&1
              PUBKEY=$(${pkgs.gawk}/bin/awk \\
                '/Public key:/ {{print $NF; exit}}' /tmp/ability-keygen.out)
              KEY="$XDG_CONFIG_HOME/apm/keys/ability-reg-release.key"
              {APR} create ability-reg \\
                --trust-key "$PUBKEY" \\
                --trust-key-id release \\
                --key "$KEY"

              SOURCE="$XDG_DATA_HOME/apm/registries/ability-reg"
              BASE_COMMIT=$({GIT} -C "$SOURCE" rev-parse HEAD)
              {FIXTURE} ability-registry \\
                "$SOURCE" \\
                /var/lib/ability-reference-registry \\
                ability-reg \\
                reference/ability-reg \\
                1.0.0 \\
                sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\
                "$BASE_COMMIT" \\
                release \\
                "$PUBKEY" \\
                "$KEY" \\
                {package_arguments}

              {APM} registry --system add \\
                file:///var/lib/ability-reference-registry \\
                --name ability-reg \\
                --version '=1.0.0' \\
                --trust-key "$PUBKEY" \\
                --no-clone
              printf 'root_owner_signers = ["release"]\\n' \\
                >> /var/lib/apm/config/registries.d/ability-reg.toml
              {APM} update --system --registry ability-reg
          """), timeout=1200)


      def assert_postgresql_packages_installed():
          installed = runtime.succeed(f"{APM} list --system --installed 2>&1")
          for entry in REFERENCE_PACKAGES:
              assert entry["name"] in installed, installed
              runtime.succeed(
                  f"{JQ} -se --arg name {shlex.quote(entry['name'])} "
                  "'map(select(.name == $name)) "
                  "| length == 1 "
                  "and (.[0].ability.activation_mode == \"structured-effects\" "
                  "or .[0].ability.activation_mode == \"contracts-only\")' "
                  "/var/lib/profiles/system-packages/current/meta/*.json"
              )


      def generate_postgresql_activation(
          output,
          database,
          role,
          credential_version,
          configuration,
          authority_staging,
          lifecycle="full",
          fault=None,
          postgresql_artifact="baseline",
          additional=None,
      ):
          runtime.succeed(
              f"{COREUTILS}/rm -rf {shlex.quote(output)} "
              f"{shlex.quote(authority_staging)}"
          )
          runtime.succeed(
              f"{COREUTILS}/mkdir -p {shlex.quote(output)} "
              f"{shlex.quote(authority_staging)}"
          )
          optional = ""
          if lifecycle != "full":
              optional += f" --lifecycle {shlex.quote(lifecycle)}"
          if fault is not None:
              optional += f" --fault {shlex.quote(fault)}"
          optional += (
              " --postgresql-artifact "
              + shlex.quote(postgresql_artifact)
          )
          for entry in additional or []:
              (
                  additional_database,
                  additional_role,
                  additional_version,
                  additional_configuration,
              ) = entry
              optional += " --additional-postgresql " + " ".join(
                  shlex.quote(value)
                  for value in (
                      additional_database,
                      additional_role,
                      additional_version,
                      additional_configuration,
                  )
              )
          runtime.succeed(
              f"PATH={NIX_BIN}:{COREUTILS} "
              f"AOS_NIX_INSTANTIATE={NIX_INSTANTIATE} "
              f"AOS_PRLIMIT={PRLIMIT} "
              f"AOS_TEST_ABILITY_CACHE=/var/cache/aos-ability-evaluator-fixture "
              f"{FIXTURE} postgresql-activation {shlex.quote(output)} "
              f"{shlex.quote(database)} {shlex.quote(role)} "
              f"{shlex.quote(credential_version)} "
              f"--configuration {shlex.quote(configuration)}"
              f"{optional} --operator-authority-output "
              f"{shlex.quote(authority_staging)}",
              timeout=1200,
          )
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(output + '/activation.json')}"
          ))


      def generate_postgresql_trust_activation(
          output,
          database,
          role,
          configuration,
          authority_staging,
      ):
          runtime.succeed(
              f"{COREUTILS}/rm -rf {shlex.quote(output)} "
              f"{shlex.quote(authority_staging)}"
          )
          runtime.succeed(
              f"{COREUTILS}/mkdir -p {shlex.quote(output)} "
              f"{shlex.quote(authority_staging)}"
          )
          runtime.succeed(
              f"PATH={NIX_BIN}:{COREUTILS} "
              f"AOS_NIX_INSTANTIATE={NIX_INSTANTIATE} "
              f"AOS_PRLIMIT={PRLIMIT} "
              f"AOS_TEST_ABILITY_CACHE=/var/cache/aos-ability-evaluator-fixture "
              f"{FIXTURE} postgresql-terminal-activation "
              f"{shlex.quote(output)} {shlex.quote(database)} "
              f"{shlex.quote(role)} --auth trust "
              f"--configuration {shlex.quote(configuration)} "
              f"--operator-authority-output {shlex.quote(authority_staging)}",
              timeout=1200,
          )
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(output + '/activation.json')}"
          ))


      def provision_postgresql_authority(activation, authority_staging):
          document_digest = activation[
              "authenticated_policy_set"
          ]["document_sha256"]
          assert document_digest.startswith("sha256:"), document_digest
          digest_hex = document_digest.removeprefix("sha256:")
          assert len(digest_hex) == 64 and all(
              character in "0123456789abcdef" for character in digest_hex
          ), digest_hex
          source = f"{authority_staging}/policy/{digest_hex}.json"
          destination = (
              "/var/lib/aos/ability-authority/policy-sets/"
              f"{digest_hex}.json"
          )
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              test -f {shlex.quote(source)}
              {FIXTURE} postgresql-authority-provision \\
                {shlex.quote(authority_staging)}
              test -f {shlex.quote(destination)}
          """))
          return destination


      def write_postgresql_host(path, activation):
          activation_json = json.dumps(activation, separators=(",", ":"))
          desired_packages = " ".join(
              json.dumps(entry["name"]) for entry in REFERENCE_PACKAGES
          )
          host_module = (
              "{ lib, ... }: {\n"
              "  aos.apm.desiredPackages = [ "
              + desired_packages
              + " ];\n"
              "  aos.abilities.activationInput = builtins.fromJSON "
              + json.dumps(activation_json)
              + ";\n"
              + "}\n"
          )
          encoded = base64.b64encode(host_module.encode()).decode()
          runtime.succeed(
              f"printf '%s' {shlex.quote(encoded)} | base64 -d "
              f"> {shlex.quote(path)}"
          )


      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def switch_postgresql_host(host, label, succeed=True):
          command = (
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/postgresql-eval-{label}"
          )
          if succeed:
              runtime.succeed(command, timeout=1200)
              generation = current_generation()
              runtime.succeed(
                  f"test \"$(readlink /var/lib/profiles/system/current)\" "
                  f"= gen-{generation}"
              )
              return generation
          return runtime.fail(command, timeout=1200)


      def native_policy_document(activation):
          sidecar = activation["authenticated_policy_set"]
          path = f"{sidecar['store_path']}/{sidecar['document']}"
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(path)}"
          ))


      def native_resource_map(activation):
          return native_policy_document(activation)["native_resource_map"]
    '';
}
