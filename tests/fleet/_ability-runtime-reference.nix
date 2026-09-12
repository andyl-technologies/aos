##! Shared production-registry and HTTP fixtures for native ability activation.
{
  lib,
  mkSystem,
  pkgs,
  guestTools ? false,
}: let
  packageSet = import ../abilities/reference-nginx/package.nix {
    inherit lib;
    inherit (pkgs) mkDerivation;
    credentialRuntime = pkgs.aos.packageRuntime;
    managedConfigurationRuntime = pkgs.aos.packageRuntime;
    nginxRuntime = pkgs.nginx;
    systemdRuntime = pkgs.aos.packageRuntime;
  };

  orderedPackages = [
    {
      name = "ability-reference-nginx-consumer";
      package = packageSet.consumer;
    }
    {
      name = "ability-reference-nginx";
      package = packageSet.nginx;
    }
    {
      name = "ability-reference-managed-configuration";
      package = packageSet.managed-configuration;
    }
    {
      name = "ability-reference-credential";
      package = packageSet.credential;
    }
    {
      name = "ability-reference-systemd";
      package = packageSet.systemd;
    }
  ];

  packageRoots = lib.concatMap (entry: [entry.package entry.package.abilities]) orderedPackages;

  reloadWrapper = pkgs.writeShellScriptBin "ability-nginx-reload" ''
    set -eu

    instance=$1
    printf '%s\n' "$instance" >> /run/ability-nginx-reload.calls
    if [ "$instance" = nginx-secondary ] \
        && [ -e /run/ability-force-native-reload-failure ]; then
      echo "deliberate native reload failure for $instance" >&2
      exit 70
    fi

    exec ${pkgs.nginx}/bin/nginx \
      -c "/var/lib/aos/ability-reference/$instance.conf" \
      -p "/var/lib/aos/ability-reference/$instance" \
      -s reload
  '';

  runtimeModules = [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.nginx pkgs.openssl reloadWrapper];
      environment.etc."tmpfiles.d/ability-reference.conf".text = ''
        d /var/lib/aos 0700 root root - -
        d /var/lib/aos/ability-reference 0700 root root - -
        d /var/lib/aos/ability-reference/nginx-main 0700 root root - -
        d /var/lib/aos/ability-reference/nginx-secondary 0700 root root - -
        d /var/lib/aos/ability-runtime 0700 root root - -
        d /var/lib/aos/ability-runtime/managed-configuration 0700 root root - -
        d /var/lib/aos/ability-runtime/managed-configuration/candidates 0700 root root - -
        d /var/lib/aos/ability-runtime/managed-configuration/revisions 0700 root root - -
        d /var/lib/aos/ability-runtime/nginx 0700 root root - -
        d /var/lib/aos/ability-runtime/nginx/candidates 0700 root root - -
        d /var/lib/aos/ability-runtime/nginx/validations 0700 root root - -
        d /var/lib/aos/ability-runtime/nginx/associations 0700 root root - -
        d /var/lib/aos/ability-runtime/nginx/sandbox 0700 root root - -
      '';
    }
  ];
  runtimeSystem = mkSystem runtimeModules;
  qualificationSetupBody = ''
    environment.etc."tmpfiles.d/ability-reference.conf".text = ${builtins.toJSON ''
      d /var/lib/aos 0700 root root - -
      d /var/lib/aos/ability-reference 0700 root root - -
      d /var/lib/aos/ability-reference/nginx-main 0700 root root - -
      d /var/lib/aos/ability-reference/nginx-secondary 0700 root root - -
      d /var/lib/aos/ability-runtime 0700 root root - -
      d /var/lib/aos/ability-runtime/managed-configuration 0700 root root - -
      d /var/lib/aos/ability-runtime/managed-configuration/candidates 0700 root root - -
      d /var/lib/aos/ability-runtime/managed-configuration/revisions 0700 root root - -
      d /var/lib/aos/ability-runtime/nginx 0700 root root - -
      d /var/lib/aos/ability-runtime/nginx/candidates 0700 root root - -
      d /var/lib/aos/ability-runtime/nginx/validations 0700 root root - -
      d /var/lib/aos/ability-runtime/nginx/associations 0700 root root - -
      d /var/lib/aos/ability-runtime/nginx/sandbox 0700 root root - -
    ''};
  '';
  qualificationExtraClosures =
    packageRoots
    ++ [
      pkgs.aos.testSupport
      pkgs.coreutils
      pkgs.curl
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.jq
      pkgs.nginx
      pkgs.nix
      pkgs.openssl
      pkgs.util-linux
      reloadWrapper
    ];
  qualificationCandidateRuntimeCompanions =
    map (name: let
      entry = builtins.head (builtins.filter (candidate: candidate.name == name) orderedPackages);
    in {
      inherit (entry) name;
      primary = entry.package;
      abilities = entry.package.abilities;
      originalRuntime = pkgs.aos.packageRuntime;
    }) [
      "ability-reference-managed-configuration"
      "ability-reference-systemd"
    ];
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
      CURL = "${pkgs.curl}/bin/curl"
      FIXTURE = "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture"
      FIND = "${pkgs.findutils}/bin/find"
      GIT = "${pkgs.git}/bin/git"
      GREP = "${pkgs.grep}/bin/grep"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_BIN = "${pkgs.nix}/bin"
      NIX_INSTANTIATE = "${pkgs.nix}/bin/nix-instantiate"
      NGINX = "${pkgs.nginx}/bin/nginx"
      OPENSSL = "${pkgs.openssl}/bin/openssl"
      PRLIMIT = "${pkgs.util-linux}/bin/prlimit"
      RELOAD_WRAPPER = "${reloadWrapper}/bin/ability-nginx-reload"

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


      def publish_reference_packages():
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


      def assert_reference_packages_installed():
          installed = runtime.succeed(
              f"{APM} list --system --installed 2>&1"
          )
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


      def generate_activation_fixture(
          output,
          primary_response,
          secondary_response,
          authority_staging,
          lifecycle="full",
          tls_version=None,
          tls_bundle=None,
      ):
          tls_arguments = ""
          if tls_version is not None or tls_bundle is not None:
              assert tls_version is not None and tls_bundle is not None, (
                  tls_version,
                  tls_bundle,
              )
              tls_arguments = (
                  f" --tls-version {shlex.quote(tls_version)}"
                  f" --tls-bundle {shlex.quote(tls_bundle)}"
              )
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
              f"{FIXTURE} ability-activation {shlex.quote(output)} "
              f"{shlex.quote(primary_response)} "
              f"{shlex.quote(secondary_response)} --operator-authority-output "
              f"{shlex.quote(authority_staging)} --lifecycle "
              f"{shlex.quote(lifecycle)}{tls_arguments}",
              timeout=1200,
          )
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(output + '/activation.json')}"
          ))


      def create_tls_bundle(root, common_name, serial):
          runtime.succeed(f"{COREUTILS}/rm -rf {shlex.quote(root)}")
          runtime.succeed(f"{COREUTILS}/mkdir -p {shlex.quote(root)}")
          key = f"{root}/server.key"
          certificate = f"{root}/server.crt"
          bundle = f"{root}/server.pem"
          runtime.succeed(
              f"{OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 30 "
              f"-set_serial {serial} -subj {shlex.quote('/CN=' + common_name)} "
              "-addext "
              f"{shlex.quote('subjectAltName=DNS:alpha.example,DNS:beta.example,DNS:gamma.example')} "
              f"-keyout {shlex.quote(key)} -out {shlex.quote(certificate)}"
          )
          runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(certificate)} {shlex.quote(key)} "
              f"> {shlex.quote(bundle)}"
          )
          fingerprint = runtime.succeed(
              f"{OPENSSL} x509 -in {shlex.quote(certificate)} -noout "
              "-fingerprint -sha256"
          ).strip().split("=", 1)[1].replace(":", "").lower()
          return bundle, certificate, fingerprint


      def provision_operator_authority(activation, authority_staging):
          document_digest = activation[
              "authenticated_policy_set"
          ]["document_sha256"]
          assert document_digest.startswith("sha256:"), document_digest
          digest_hex = document_digest.removeprefix("sha256:")
          assert len(digest_hex) == 64 and all(
              character in "0123456789abcdef" for character in digest_hex
          ), digest_hex
          source = f"{authority_staging}/{digest_hex}.json"
          destination = (
              "/var/lib/aos/ability-authority/policy-sets/"
              f"{digest_hex}.json"
          )
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              {COREUTILS}/install -d -o root -g root -m 0700 \\
                /var/lib/aos/ability-authority \\
                /var/lib/aos/ability-authority/policy-sets
              {FIXTURE} ability-authority-provision {shlex.quote(source)}
          """))
          return destination


      def write_activation_host(path, activation, extra_module=""):
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
              + extra_module
              + "  systemd.services.nginx-nginx-main = {\n"
              "    description = \"Reference ability nginx service\";\n"
              "    after = [ \"local-fs.target\" ];\n"
              "    serviceConfig = {\n"
              "      Type = \"simple\";\n"
              f"      ExecStart = \"{NGINX} -c "
              "/var/lib/aos/ability-reference/nginx-main.conf -p "
              "/var/lib/aos/ability-reference/nginx-main "
              "-g 'daemon off;'\";\n"
              f"      ExecReload = \"{RELOAD_WRAPPER} nginx-main\";\n"
              "      Restart = \"on-failure\";\n"
              "    };\n"
              "  };\n"
              "  systemd.services.nginx-nginx-secondary = {\n"
              "    description = \"Secondary reference ability nginx service\";\n"
              "    after = [ \"local-fs.target\" ];\n"
              "    serviceConfig = {\n"
              "      Type = \"simple\";\n"
              f"      ExecStart = \"{NGINX} -c "
              "/var/lib/aos/ability-reference/nginx-secondary.conf -p "
              "/var/lib/aos/ability-reference/nginx-secondary "
              "-g 'daemon off;'\";\n"
              f"      ExecReload = \"{RELOAD_WRAPPER} nginx-secondary\";\n"
              "      Restart = \"on-failure\";\n"
              "    };\n"
              "  };\n"
              + "}\n"
          )
          encoded = base64.b64encode(host_module.encode()).decode()
          runtime.succeed(
              f"printf '%s' {shlex.quote(encoded)} | base64 -d "
              f"> {shlex.quote(path)}"
          )


      def route_body(host, port):
          return runtime.succeed(
              f"{CURL} --fail --silent "
              f"-H {shlex.quote('Host: ' + host)} http://127.0.0.1:{port}/"
          )


      def assert_route(host, port, identity, content):
          body = route_body(host, port)
          assert body == f"{identity}:{content}\n", (host, body)


      def assert_route_absent(host, port):
          runtime.fail(
              f"{CURL} --fail --silent "
              f"-H {shlex.quote('Host: ' + host)} http://127.0.0.1:{port}/"
          )


      def tls_route_body(host, port, certificate):
          return runtime.succeed(
              f"{CURL} --fail --silent --cacert {shlex.quote(certificate)} "
              f"--resolve {shlex.quote(f'{host}:{port}:127.0.0.1')} "
              f"{shlex.quote(f'https://{host}:{port}/')}"
          )


      def assert_tls_route_absent(host, port):
          runtime.fail(
              f"{CURL} --fail --silent --insecure "
              f"--resolve {shlex.quote(f'{host}:{port}:127.0.0.1')} "
              f"{shlex.quote(f'https://{host}:{port}/')}"
          )


      def served_certificate_fingerprint(host, port):
          command = (
              f"{OPENSSL} s_client -connect 127.0.0.1:{port} "
              f"-servername {shlex.quote(host)} </dev/null 2>/dev/null "
              f"| {OPENSSL} x509 -noout -fingerprint -sha256"
          )
          return runtime.succeed(command).strip().split("=", 1)[1].replace(
              ":", ""
          ).lower()


      def assert_consumer_observation(activation):
          policy_sidecar = activation["authenticated_policy_set"]
          policy_path = (
              f"{policy_sidecar['store_path']}/{policy_sidecar['document']}"
          )
          policy = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(policy_path)}"
          ))
          service_mappings = [
              mapping
              for mapping in policy["native_resource_map"]["entries"]
              if mapping["qualification"]["kind"] == "systemd-service"
          ]
          assert len(service_mappings) == 2, service_mappings
          observations = [
              mapping["qualification"]["consumer_observation"]
              for mapping in service_mappings
          ]
          assert {
              observation["endpoint"] for observation in observations
          } == {"127.0.0.1:18081", "127.0.0.1:18082"}, observations

          for expected in observations:
              response = runtime.succeed(
                  f"{CURL} --fail --silent --show-error --http1.0 "
                  "--dump-header - --output /dev/null "
                  f"-H {shlex.quote('Host: ' + expected['authority'])} "
                  f"http://{expected['endpoint']}{expected['path']}"
              )
              lines = response.splitlines()
              assert lines and lines[0].split()[1] == "204", lines

              evidence = {}
              expected_headers = {
                  "x-aos-consumer-instance",
                  "x-aos-consumer-controller-revision",
                  "x-aos-consumer-content-revision",
              }
              for line in lines[1:]:
                  if not line:
                      break
                  name, value = line.split(":", 1)
                  name = name.lower()
                  if name in expected_headers:
                      assert name not in evidence, (name, lines)
                      evidence[name] = value.strip()

              assert set(evidence) == expected_headers, evidence
              assert json.loads(evidence["x-aos-consumer-instance"]) == (
                  expected["expected_instance"]
              ), (evidence, expected)
              assert evidence["x-aos-consumer-controller-revision"] == (
                  expected["expected_controller_revision"]
              ), (evidence, expected)
              assert evidence["x-aos-consumer-content-revision"] == (
                  expected["expected_content_revision"]
              ), (evidence, expected)


      def assert_managed_configuration_selected(activation, instance):
          policy_sidecar = activation["authenticated_policy_set"]
          policy_path = (
              f"{policy_sidecar['store_path']}/{policy_sidecar['document']}"
          )
          policy = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(policy_path)}"
          ))
          destination = f"/var/lib/aos/ability-reference/{instance}.conf"
          mappings = [
              mapping
              for mapping in policy["native_resource_map"]["entries"]
              if mapping["qualification"]["kind"] == "managed-configuration"
              and mapping["qualification"]["destination"] == destination
          ]
          assert len(mappings) == 1, mappings
          mapping = mappings[0]

          marker_paths = runtime.succeed(
              f"{FIND} /var/lib/aos/ability-runtime/managed-configuration/revisions "
              "-mindepth 1 -maxdepth 1 -type f -print"
          ).splitlines()
          markers = [
              json.loads(runtime.succeed(
                  f"{COREUTILS}/cat {shlex.quote(path)}"
              ))
              for path in marker_paths
          ]
          selected = [
              marker for marker in markers
              if marker["destination"] == destination
          ]
          assert len(selected) == 1, (destination, markers)
          marker = selected[0]
          assert marker["schema"] == (
              "aos.ability.managed-configuration-revision/v2"
          ), marker
          assert marker["resource"] == mapping["resource"], (marker, mapping)
          assert marker["revision"] == mapping["revision"], (marker, mapping)
          content_digest = runtime.succeed(
              f"{COREUTILS}/sha256sum {shlex.quote(destination)}"
          ).split()[0]
          assert marker["content"] == f"sha256:{content_digest}", marker
          content = runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(destination)}"
          )
          return mapping, content
    '';
}
