##! Shared production-registry and HTTP fixtures for native ability activation.
{
  lib,
  mkSystem,
  pkgs,
  guestTools ? false,
  effectQualification ? false,
  providerStateQualification ? false,
}: let
  packageSet = import ../abilities/reference-nginx/package.nix {
    inherit (pkgs) bash coreutils mkDerivation nginx python3 service-management;
  };

  orderedPackages = [
    {
      name = "ability-reference-nginx-consumer";
      package = packageSet.consumer;
    }
    {
      name = "ability-reference-nginx-backend-consumer";
      package = packageSet.backend-consumer;
    }
    {
      name = "ability-reference-http-backend-registry";
      package = packageSet.backend-registry;
    }
    {
      name = "ability-reference-runtime-services";
      package = packageSet.runtime-services;
    }
    {
      name = pkgs.nginx.pname;
      package = pkgs.nginx;
    }
    {
      name = pkgs.aos.pname;
      package = pkgs.aos;
    }
    {
      name = pkgs.systemd.pname;
      package = pkgs.systemd;
    }
  ];

  packageRoots = lib.concatMap (entry: [entry.package entry.package.deploymentArtifact entry.package.documentationArtifact]) orderedPackages;

  runtimeModules = [
    ../../systems/server-test.nix
    ./_reference-native-configuration.nix
    {
      environment.systemPackages = [pkgs.openssl];
      aos.packages = lib.listToAttrs (map (entry: {
          inherit (entry) name;
          value = {
            package = entry.package;
            bundle = true;
          };
        })
        orderedPackages);
    }
  ];
  selectedFixture = import ./_native-fixture-selection.nix {inherit lib;} {
    inherit runtimeSystem;
    scenarioSources = [./_reference-native-configuration.nix];
  };
  runtimeSystem = mkSystem (runtimeModules
    ++ [
      {
        aos.activation.stages.host.configuration = selectedFixture.sources;
      }
    ]);
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
      pkgs.python3
      pkgs.util-linux
    ];
  qualificationCandidateRuntimeCompanions = selectedFixture.qualification.candidateRuntimeCompanions;
in {
  inherit
    orderedPackages
    packageRoots
    packageSet
    qualificationExtraClosures
    qualificationCandidateRuntimeCompanions
    runtimeModules
    runtimeSystem
    ;

  qualificationSelectedEvaluation = selectedFixture.qualification.selectedEvaluation;

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
      import re
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
      OPENSSL = "${pkgs.openssl}/bin/openssl"
      PRLIMIT = "${pkgs.util-linux}/bin/prlimit"

      PROFILE = "/var/lib/profiles/system"
      REFERENCE_BUNDLE = "${runtimeSystem.config.system.build.hostDeploymentBundle}"


      def write_reference_worktree(path, settings=None, extra_module=""):
          """Authors ordinary native operator options for the admitted image closure."""
          settings = settings or {}
          source = (
              "{ lib, ... }: { config = lib.mkMerge [ (builtins.fromJSON "
              + json.dumps(json.dumps(settings, separators=(",", ":")))
              + ") { " + extra_module + " } ]; }\n"
          )
          encoded = base64.b64encode(source.encode()).decode()
          runtime.succeed(f"{COREUTILS}/install -d -m 0700 {shlex.quote(path)}")
          runtime.succeed(
              f"printf '%s' {shlex.quote(encoded)} | {COREUTILS}/base64 -d "
              f"> {shlex.quote(path + '/reference.nix')}"
          )
          runtime.succeed(f"{COREUTILS}/chmod 0600 {shlex.quote(path + '/reference.nix')}")
          return path


      def apply_reference(worktree, label):
          """Uses source snapshot admission and the authoritative native profile journal."""
          runtime.succeed(
              f"{APM} switch --worktree {shlex.quote(worktree)} "
              f"--eval-root /var/lib/aos/native-evaluations/{shlex.quote(label)}",
              timeout=1200,
          )


      def current_reference_graph():
          """Reads the desired graph from the checked committed generation."""
          target = runtime.succeed(f"{COREUTILS}/readlink {PROFILE}/current").strip()
          generation = int(target.rsplit('gen-', 1)[1])
          diagnostic = json.loads(runtime.succeed(
              f"{AOS} ability diagnostic {PROFILE} {generation} --audience deployment"
          ))
          assert diagnostic["liveStateVerified"] is False, diagnostic
          return diagnostic["desired"]["graph"]


      def inspect_reference_journal():
          """Reads checksum-validated native state without repair or dispatch."""
          return json.loads(runtime.succeed(
              f"{AOS} ability journal {PROFILE}/deployment/effects.journal --format json"
          ))


      def assert_reference_admission():
          """Checks the retained native transaction and package metadata are present."""
          runtime.succeed(f"test -s {PROFILE}/current/native-deployment.json")
          runtime.succeed(f"test -s {PROFILE}/current/evaluation.json")
          graph = current_reference_graph()
          assert graph["schema"] == "aos.activation.graph", graph
          assert any(node["identity"][-3:-1] == ["referenceNginx", "bind"] for node in graph["nodes"].values()), graph
          return graph


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


      def route_body(host, port):
          return runtime.succeed(
              f"{CURL} --fail --silent "
              f"-H {shlex.quote('Host: ' + host)} http://127.0.0.1:{port}/"
          )


      def backend_body(application, port):
          body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:{port}/"
          )
          assert body.startswith(f"{application}:"), body
          return body


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


    '';
}
