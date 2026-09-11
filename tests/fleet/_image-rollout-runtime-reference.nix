##! Authenticated package and activation helpers for the image rollout VM.
{
  lib,
  pkgs,
}: let
  package = import ../abilities/reference-image-rollout/package.nix {
    inherit lib;
    inherit (pkgs) mkDerivation;
    rolloutRuntime = pkgs.aos.packageRuntime;
  };
  orderedPackages = [
    {
      name = "ability-reference-image-rollout";
      inherit package;
    }
  ];
  packageRoots = [package package.abilities];
in {
  inherit orderedPackages package packageRoots;

  extraClosures =
    packageRoots
    ++ [
      pkgs.aos.testSupport
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.jq
      pkgs.nix
      pkgs.util-linux
    ];

  testPrelude =
    # python
    ''
      import base64
      import json
      import shlex
      import textwrap

      APM = "${pkgs.aos.apm}/bin/apm"
      APR = "${pkgs.aos.apr}/bin/apr"
      COREUTILS = "${pkgs.coreutils}/bin"
      FIXTURE = "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture"
      GIT = "${pkgs.git}/bin/git"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_BIN = "${pkgs.nix}/bin"
      NIX_INSTANTIATE = "${pkgs.nix}/bin/nix-instantiate"
      PRLIMIT = "${pkgs.util-linux}/bin/prlimit"
      ROLLOUT_PACKAGES = ${builtins.toJSON (map (entry: {
          inherit (entry) name;
          package = builtins.toString entry.package;
          abilities = builtins.toString entry.package.abilities;
        })
        orderedPackages)}


      def publish_rollout_package():
          package_arguments = " ".join(
              " ".join(
                  shlex.quote(value)
                  for value in (entry["name"], entry["package"], entry["abilities"])
              )
              for entry in ROLLOUT_PACKAGES
          )
          target.succeed(textwrap.dedent(f"""
              set -eu
              export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
              export GIT_AUTHOR_NAME='Image Rollout Fixture'
              export GIT_AUTHOR_EMAIL=image-rollout@example.test
              export GIT_COMMITTER_NAME='Image Rollout Fixture'
              export GIT_COMMITTER_EMAIL=image-rollout@example.test
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/rollout-nix-conf
              export XDG_CONFIG_HOME=/tmp/rollout-user-config
              export XDG_DATA_HOME=/tmp/rollout-user-data
              mkdir -p "$NIX_CONF_DIR"
              printf 'experimental-features = nix-command\\nsandbox = false\\n' \\
                > "$NIX_CONF_DIR/nix.conf"

              {APR} keys generate release --registry rollout-reg \\
                > /tmp/rollout-keygen.out 2>&1
              PUBKEY=$(${pkgs.gawk}/bin/awk \\
                '/Public key:/ {{print $NF; exit}}' /tmp/rollout-keygen.out)
              KEY="$XDG_CONFIG_HOME/apm/keys/rollout-reg-release.key"
              {APR} create rollout-reg \\
                --trust-key "$PUBKEY" \\
                --trust-key-id release \\
                --key "$KEY"

              SOURCE="$XDG_DATA_HOME/apm/registries/rollout-reg"
              BASE_COMMIT=$({GIT} -C "$SOURCE" rev-parse HEAD)
              {FIXTURE} ability-registry \\
                "$SOURCE" \\
                /var/lib/image-rollout-reference-registry \\
                rollout-reg \\
                reference/rollout-reg \\
                1.0.0 \\
                sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \\
                "$BASE_COMMIT" \\
                release \\
                "$PUBKEY" \\
                "$KEY" \\
                {package_arguments}

              {APM} registry --system add \\
                file:///var/lib/image-rollout-reference-registry \\
                --name rollout-reg \\
                --version '=1.0.0' \\
                --trust-key "$PUBKEY" \\
                --no-clone
              printf 'root_owner_signers = ["release"]\\n' \\
                >> /var/lib/apm/config/registries.d/rollout-reg.toml
              {APM} update --system --registry rollout-reg
          """), timeout=1200)


      def generate_rollout_activation(request, mode, label):
          root = f"/var/lib/aos-test/rollout-activation-{label}"
          output = f"{root}/output"
          authority = f"{root}/authority"
          request_path = f"{root}/request.json"
          request_bytes = json.dumps(
              request, sort_keys=True, separators=(",", ":")
          ).encode()
          encoded = base64.b64encode(request_bytes).decode()
          target.succeed(
              f"{COREUTILS}/rm -rf {shlex.quote(root)}; "
              f"{COREUTILS}/mkdir -p {shlex.quote(output)} "
              f"{shlex.quote(authority)}; "
              f"printf %s {shlex.quote(encoded)} | "
              f"{COREUTILS}/base64 -d > {shlex.quote(request_path)}"
          )
          target.succeed(
              f"PATH={NIX_BIN}:{COREUTILS} "
              f"AOS_NIX_INSTANTIATE={NIX_INSTANTIATE} "
              f"AOS_PRLIMIT={PRLIMIT} "
              f"AOS_TEST_ABILITY_CACHE=/var/cache/aos-rollout-evaluator-fixture "
              f"{FIXTURE} rollout-activation {shlex.quote(output)} "
              f"{shlex.quote(request_path)} --operator-authority-output "
              f"{shlex.quote(authority)} --mode {shlex.quote(mode)}",
              timeout=1200,
          )
          activation = json.loads(target.succeed(
              f"{COREUTILS}/cat {shlex.quote(output + '/activation.json')}"
          ))
          digest = activation["authenticated_policy_set"]["document_sha256"]
          assert digest.startswith("sha256:"), digest
          digest_hex = digest.removeprefix("sha256:")
          source = f"{authority}/{digest_hex}.json"
          target.succeed(textwrap.dedent(f"""
              set -eu
              {COREUTILS}/install -d -o root -g root -m 0700 \\
                /var/lib/aos/ability-authority \\
                /var/lib/aos/ability-authority/policy-sets
              {FIXTURE} ability-authority-provision {shlex.quote(source)}
          """))
          return activation


      def write_rollout_host(path, activation, extra_module):
          activation_json = json.dumps(activation, separators=(",", ":"))
          module = (
              "{ lib, ... }: {\n"
              "  aos.apm.desiredPackages = [ \"aos-test-agent\" \"ability-reference-image-rollout\" ];\n"
              "  aos.abilities.activationInput = builtins.fromJSON "
              + json.dumps(activation_json)
              + ";\n"
              + extra_module
              + "}\n"
          )
          encoded = base64.b64encode(module.encode()).decode()
          target.succeed(
              f"printf %s {shlex.quote(encoded)} | "
              f"{COREUTILS}/base64 -d > {shlex.quote(path)}"
          )
    '';
}
