##! Checks native retained source roots and the admitted module library identity.
{
  pkgs,
  system,
}: let
  bundle = system.config.system.build.hostDeploymentBundle;
in
  pkgs.mkDerivation {
    pname = "aos-native-module-roots-check";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.jq];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          ${pkgs.jq}/bin/jq -e --slurpfile transaction ${bundle}/transaction.json \
            --slurpfile admission ${bundle}/admission.json '
            .schema == "aos.package.evaluation-input" and
            .scope == $transaction[0].scope and
            .packages.system == $transaction[0].system and
            .packages.artifacts == $transaction[0].artifacts and
            .packages.modules == $transaction[0].packages and
            (. as $input | (.library | split("/") | .[0:4] | join("/")) as $library |
              any($admission[0].roots[]; .storePath == $library and .narHash == $input.libraryNarHash)) and
            all(.packages.modules[]; .configRoot as $source |
              ($transaction[0].inputs | index($source)) != null and
              any($admission[0].roots[]; .storePath == $source)) and
            all((.configuration + (.runtimeConfiguration // []))[];
              (split("/") | .[0:4] | join("/")) as $source |
              ($transaction[0].inputs | index($source)) != null and
              any($admission[0].roots[]; .storePath == $source))
          ' ${bundle}/evaluation.json > /dev/null
          digest=$(sha256sum ${bundle}/admission.json)
          test "sha256:''${digest%% *}" = "$(cat ${bundle}/admission-sha256)"
          receipt_root=$(readlink -f ${bundle}/admission.json)
          digest_root=$(dirname "$(readlink -f ${bundle}/admission-sha256)")
          test "$receipt_root" != "$digest_root"
          test -f "$receipt_root"
          case "$receipt_root" in
            /nix/store/*/*) exit 1 ;;
            /nix/store/*) ;;
            *) exit 1 ;;
          esac
          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
