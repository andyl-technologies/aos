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
{writeShellScriptBin}:
(writeShellScriptBin "remove-references-to" ''
  set -e

  # References to remove
  targets=()
  while getopts t: o; do
    case "$o" in
      t)
        storeId=$(echo "$OPTARG" | sed -n "s|^${builtins.storeDir}/\([a-z0-9]\{32\}\)-.*|\1|p")
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
    sed -i -e "s|$target|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|g" "''${regions[@]}"
  done
'')
.overrideAttrs (_: {
  meta = {
    description = "Remove selected Nix store references from files";
    license = "MIT";
  };
})
