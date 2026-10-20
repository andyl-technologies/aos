# SPDX-License-Identifier: MIT
#
# Ported from nixpkgs for use in AOS.
#   Upstream path: pkgs/build-support/remove-references-to/{default.nix,remove-references-to}
#   Upstream rev:  6c9a78c09ff4d6c21d0319114873508a6ec01655
#
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.
#
# AOS adaptations:
#   - Built via writeShellScriptBin (AOS's ported trivial builder) rather
#     than replaceVarsWith — the shebang pointing at the AOS-built bash is
#     injected by writeShellScriptBin; storeDir is interpolated at Nix
#     eval time from builtins.storeDir.
#   - The darwin signingUtils branch is dropped — AOS targets Linux only.
#
# Usage:
#   remove-references-to -t <storePath> [-t <storePath> ...] <file> [<file> ...]
#
# Replaces the 32-char hash of each `-t` target with
# eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee in-place in every file argument. The
# path string stays syntactically valid (so consumers that expect a path
# see a parseable one) but Nix's reference scanner no longer sees the
# target as a closure edge. Works on text files and on ELF DT_RUNPATH
# byte strings alike — the replacement is byte-for-byte length-preserving.
{
  lib,
  writeShellScriptBin,
  sed,
}:
(writeShellScriptBin "remove-references-to" ''
  set -e

  # References to remove
  targets=()
  while getopts t: o; do
    case "$o" in
      t)
        storeId=$(echo "$OPTARG" | ${sed}/bin/sed -n "s|^${builtins.storeDir}/\([a-z0-9]\{32\}\)-.*|\1|p")
        if [ -z "$storeId" ]; then
          echo "remove-references-to: -t argument must be a Nix store path, got: $OPTARG" >&2
          exit 1
        fi
        targets+=("$storeId")
        ;;
    esac
  done
  shift $(($OPTIND - 1))

  # Files to remove the references from
  regions=()
  for i in "$@"; do
    if [ ! -L "$i" ] && [ -f "$i" ]; then
      regions+=("$i")
    fi
  done

  if [ ''${#regions[@]} -eq 0 ]; then
    exit 0
  fi

  for target in "''${targets[@]}"; do
    ${sed}/bin/sed -i -e "s|$target|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|g" "''${regions[@]}"
  done
'')
.overrideAttrs (_: {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
    target = [];
    role = "public-package";
  };
  qualification.packageProbe = let
    qualification = lib.qualification;
    text = qualification.text;
    inputHash = "0123456789abcdfghijklmnpqrsvwxyz";
    replacementHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    # Keep the fixture's synthetic store path out of the package contract.
    storePath = hash:
      qualification.template [
        (qualification.literal "/nix")
        (qualification.literal "/store/${hash}-target")
      ];
  in
    qualification.packageProbe {
      primary = qualification.operation {
        artifacts = [
          (qualification.sha256Artifact {
            path = "reference.txt";
            digest = "sha256:${builtins.hashString "sha256" "dependency=${builtins.storeDir}/${replacementHash}-target\n"}";
          })
        ];
        expected = "The selected store hash is replaced with the fixed non-reference marker.";
        files."reference.txt" = qualification.template [
          (qualification.literal "dependency=")
          (qualification.literal "/nix")
          (qualification.literal "/store/${inputHash}-target\n")
        ];
        input = "A text file containing the hash portion of a syntactically valid Nix store path.";
        operation = "Scrub that store reference in place.";
        steps = [
          (qualification.step {
            argv = [
              (qualification.template [(qualification.artifactPath {path = "bin/remove-references-to";})])
              (text "-t")
              (storePath inputHash)
              (text "reference.txt")
            ];
            exit_code = 0;
            stderr = text "";
            stdout = text "";
          })
        ];
      };
      badInput = qualification.operation {
        artifacts = [(qualification.textArtifact {path = "reference.txt"; text = "answer=42\n";})];
        expected = "The tool rejects the target before changing the input file.";
        files."reference.txt" = text "answer=42\n";
        input = "A target argument outside the Nix store path grammar.";
        operation = "Attempt to select the malformed target for reference removal.";
        steps = [
          (qualification.step {
            argv = [
              (qualification.template [(qualification.artifactPath {path = "bin/remove-references-to";})])
              (text "-t")
              (text "not-a-store-path")
              (text "reference.txt")
            ];
            exit_code = 1;
            observes_rejection = true;
            stderr = text "remove-references-to: -t argument must be a Nix store path, got: not-a-store-path\n";
            stdout = text "";
          })
        ];
      };
    };
  passthru.evidenceSources = [./remove-references-to.nix];

  meta = {
    description = "Remove selected Nix store references from files";
    license = "MIT";
  };
})
