# SPDX-License-Identifier: MIT
#
# Ported from nixpkgs for use in AOS.
#   Upstream path: pkgs/build-support/trivial-builders/default.nix
#   Upstream rev:  6c9a78c09ff4d6c21d0319114873508a6ec01655
#
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.
#
# AOS adaptations (summary):
#   - Only the four primitives needed by the systemd library are ported:
#     writeTextFile, writeShellScriptBin, runtimeShell, runCommand.
#   - runCommand is a thin shim over AOS's mkDerivation that relies on the
#     stdenv setup.sh to create $out and to put initialPath on PATH, so the
#     shim itself does not need to declare coreutils/findutils/etc.
#   - writeShellScriptBin sets meta.mainProgram = name so lib.getExe resolves
#     directly to "$out/bin/<name>" without an AOS-specific divergence inside
#     the ported systemd-lib.makeJobScript.
#   - The shellcheck / writeShellApplication branch is not ported (no Haskell
#     toolchain), which lets us drop the `checkPhase` argument's dependency
#     on a shellcheck binary.
#
# Top-level signature takes the minimal set of AOS-built tools it needs.
# The file is auto-discovered by pkgs/default.nix and exposes its outputs as
# `pkgs.trivial-builders`; pkgs/default.nix then re-inherits the four
# primitives into the flat package set so that consumers can say
# `pkgs.writeTextFile` / `pkgs.runCommand` directly.
{
  lib,
  mkDerivation,
  bash,
  buildPackages,
}: let
  # ---------------------------------------------------------------------------
  # runtimeShell — absolute path to the AOS-built bash binary.
  # ---------------------------------------------------------------------------
  #
  # Matches nixpkgs' `pkgs.runtimeShell`. Consumers (including the ported
  # makeJobScript) use this as the shebang for generated scripts instead of
  # hard-coding `/bin/sh` or `/bin/bash`, keeping generated shell artifacts
  # inside the hermetic store closure.
  runtimeShell = "${bash}/bin/bash";

  # Cross outputs retain the target Bash shebang above, but syntax validation
  # happens during the build and therefore must use a build-platform Bash.
  # These paths are identical for native package sets, preserving derivation
  # identity outside cross builds.
  buildShell = "${buildPackages.bash}/bin/bash";

  # ---------------------------------------------------------------------------
  # writeTextFile — write a text file into a derivation output.
  # ---------------------------------------------------------------------------
  #
  # Produces a derivation whose output contains a file with the given text.
  # The destination inside the output is controlled by the `destination`
  # argument; when empty, the text lives directly at `$out`.
  #
  # Arguments:
  #   name         — derivation name.
  #   text         — the file's textual contents.
  #   destination  — relative path inside $out (e.g. "/bin/hi"). Must start
  #                  with a slash when non-empty so the parent directory can
  #                  be derived via `dirname`. Empty means "$out is the file".
  #   executable   — whether to `chmod +x` the file.
  #   checkPhase   — optional shell snippet run after the file is written;
  #                  useful for e.g. `bash -n` syntax checks.
  #   meta         — derivation metadata. writeShellScriptBin uses this to
  #                  set meta.mainProgram so lib.getExe resolves correctly.
  #   allowSubstitutes / preferLocalBuild — forwarded to the derivation.
  writeTextFile = {
    name,
    text,
    destination ? "",
    executable ? false,
    checkPhase ? "",
    meta ? {},
    allowSubstitutes ? false,
    preferLocalBuild ? true,
  }: let
    # `passAsFile` tells Nix to write the `text` env var to a temporary
    # file and expose its path as `$textPath`. This avoids shell-quoting
    # issues in the builder script for arbitrarily long or funky text.
    hasDestination = destination != "";
  in
    mkDerivation {
      inherit name meta;
      src = null;

      text = text;
      passAsFile = ["text"];

      # Forwarded as-is to builtins.derivation via mkDerivation's extraArgs
      # spread. These are Nix-level scheduling hints, not build inputs.
      inherit allowSubstitutes preferLocalBuild;

      # writeTextFile (and writeShellScriptBin built on top of it) materializes
      # *exactly* the text Nix interpolated, store-path references and all.
      # Every `${foo}/bin/bar` substitution in `text` is intentional — that's
      # the whole API contract. Letting scrubPhase rewrite those hashes would
      # turn every generated wrapper script into a runtime exec failure
      # (regression observed: nix-overlay-setup-start invoked
      #  /nix/store/eeee…-util-linux-2.41/bin/mount and exited 127, leaving
      # the initrd unable to switch root).
      dontNukeRefs = true;

      phases = [
        {
          name = "build";
          script =
            (
              if hasDestination
              then ''
                target="$out${destination}"
                mkdir -p "$(dirname "$target")"
              ''
              else ''
                target="$out"
              ''
            )
            + ''
              cp "$textPath" "$target"
            ''
            + (lib.optionalString executable ''
              chmod +x "$target"
            '')
            + (lib.optionalString (checkPhase != "") ''
              ${checkPhase}
            '');
        }
      ];
    };

  # ---------------------------------------------------------------------------
  # writeShellScriptBin — write an executable shell script to $out/bin/<name>.
  # ---------------------------------------------------------------------------
  #
  # Wraps the text in a shebang pointing at the AOS-built bash, installs it
  # as an executable at `$out/bin/<name>`, and runs the build-platform
  # `bash -n` on the result so syntactically broken scripts fail at build time
  # rather than at boot.
  #
  # Sets `meta.mainProgram = name` so `lib.getExe result` resolves directly
  # to `$out/bin/<name>`. This is what lets the ported systemd-lib.makeJobScript
  # end in `lib.getExe out` without an AOS-specific divergence.
  writeShellScriptBin = name: text:
    writeTextFile {
      inherit name;
      executable = true;
      destination = "/bin/${name}";
      text = ''
        #!${runtimeShell}
        ${text}
      '';
      checkPhase = ''
        ${buildShell} -n "$target"
      '';
      meta = {
        mainProgram = name;
      };
    };

  # ---------------------------------------------------------------------------
  # runCommand — build a derivation that runs a single shell command.
  # ---------------------------------------------------------------------------
  #
  # Signature matches nixpkgs: `runCommand name env buildCommand`.
  #   name         — derivation name.
  #   env          — attrs spread into the derivation (e.g. preferLocalBuild,
  #                  allowSubstitutes, passAsFile, passthru data).
  #   buildCommand — shell script body; runs with setup.sh sourced (so $out
  #                  is pre-created and initialPath is on PATH).
  #
  # The shim does not declare buildDeps: AOS's stdenv.mkDerivation appends
  # initialPath (coreutils, findutils, gnumake, gawk, grep, sed, tar, gzip,
  # xz, bzip2, diffutils, patch, bash, patchelf) to buildDeps automatically,
  # so common shell builtins and text tools are always available inside the
  # buildCommand body.
  #
  # Because we pass an explicit single-phase list, no fixup phase runs —
  # symlink trees and plain-text files pass through untouched (no stripping,
  # no shebang patching, no `.la` removal).
  runCommand = name: env: buildCommand:
    mkDerivation (
      {
        inherit name;
        src = null;
        # Same rationale as writeTextFile above: callers (the systemd-lib
        # generators, the cmdline / os-release composers, etc.) interpolate
        # store paths into the buildCommand body and into the produced files,
        # and they want those interpolations to survive verbatim. Opt out of
        # scrubPhase so the produced output isn't byte-rewritten on the way
        # to $out. Callers that need scrubbing can override.
        dontNukeRefs = true;
        phases = [
          {
            name = "build";
            script = buildCommand;
          }
        ];
      }
      // env
    );
in {
  inherit
    writeTextFile
    writeShellScriptBin
    runtimeShell
    runCommand
    ;
}
