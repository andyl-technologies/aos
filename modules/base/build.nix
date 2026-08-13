##! modules/base/build.nix — System build outputs module
##!
##! Declares the core options that the image builder and deploy bundle depend on:
##!   - environment.systemPackages  — runtime packages accumulated by all modules
##!   - environment.etc             — files to install in /etc
##!   - system.build.toplevel       — the top-level system derivation
##!   - system.build.kernel         — the kernel derivation
##!   - system.build.initrd         — the initrd derivation
##!
##! systemd unit / timer / socket / etc. definitions now live in
##! modules/systemd/system.nix under the typed `systemd.*` option tree.
##! The toplevel links `system.build.systemdSystemUnits`, a thin builder-side
##! materialization of the systemd entries in `system.build.configManifest`.
{
  config,
  pkgs,
  lib,
  provenance,
  aosStructuredErrors ? false,
  ...
}: let
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  # --- composefs / EROFS inputs (spec v12 §5.3) ---
  #
  # Mirror the upstream nixpkgs etc.nix derivation set:
  #   etc'         = every enabled environment.etc entry.
  #   etcHardlinks = the subset with an octal mode — those need their
  #                  content materialised in the basedir (the rest
  #                  ship as composefs symlinks pointing directly into
  #                  /nix/store from the metadata image).
  etc' = lib.filter (e: e.enable) (lib.attrValues config.environment.etc);
  etcHardlinks =
    lib.filter (e: e.mode != "symlink" && e.mode != "direct-symlink") etc';

  makeBinPath = pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") pkgsList);
  makeSbinPath = pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/sbin") pkgsList);
in {
  options = {
    ## Assertions checked during system build. If any assertion is
    ## false, evaluating `system.build.toplevel` throws with every
    ## failing assertion's message. The config itself is still
    ## inspectable — only *building* the system fails — so `aos repl`,
    ## `aos show`, and similar introspection tools can still work on a
    ## broken config to help debug the problem.
    assertions = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          assertion = lib.mkOption {
            type = lib.types.bool;
            description = "The predicate; false means the assertion failed.";
          };
          message = lib.mkOption {
            type = lib.types.str;
            description = "Error message displayed when the assertion fails.";
          };
        };
      });
      default = [];
      description = ''
        List of `{ assertion = bool; message = str; }` records. Every
        record whose `assertion` is false is collected and reported
        via a `throw` at `system.build.toplevel` construction time,
        with each failing message on its own line.
      '';
    };

    ## Warning messages reported during system build. Emitted via
    ## `builtins.trace` when `system.build.toplevel` is forced, so they
    ## surface during any evaluation that reaches the toplevel
    ## (including `checks.eval` and actual image builds).
    warnings = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        List of warning messages. Each is traced to stderr when
        `system.build.toplevel` is evaluated. Warnings do not prevent
        the system from building.
      '';
    };

    ## Packages that appear in the system profile PATH.
    environment.systemPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      apply = lib.unique;
      description = ''
        The set of packages that appear in the system profile. These packages
        are made available in the system PATH and are included in the Nix store
        closure of the system toplevel.
      '';
    };

    ## Files to install in /etc.
    #
    # SPDX-License-Identifier: MIT
    # Ported from nixpkgs:
    #   nixos/modules/system/etc/etc.nix:120-235.
    # Copyright (c) 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
    #
    # AOS port differs from upstream: the user/group string fields are
    # omitted (the composefs dump consumes numeric uid/gid only); the
    # mode type catches typos (`"sym-link"`, `"0o644"`) at eval time.
    environment.etc = lib.mkOption {
      default = {};
      type = lib.types.attrsOf (lib.types.submodule ({
        name,
        config,
        ...
      }: {
        options = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              Whether this `/etc` entry is generated. Allows a
              downstream module to suppress an upstream-declared entry.
            '';
          };
          target = lib.mkOption {
            type = lib.types.str;
            default = name;
            description = ''
              Path under `/etc` at which the entry appears. Defaults
              to the attribute name; the explicit form is useful when
              the attribute name can't be a valid path (e.g. when
              keying by a sanitised identifier).
            '';
          };
          text = lib.mkOption {
            type = lib.types.nullOr lib.types.lines;
            default = null;
            description = ''
              Inline file content. When `text` is set, `source` is
              derived from it via `pkgs.writeTextFile`. If neither
              `text` nor `source` is set, evaluation fails with the
              standard module-system error "option `source' is not
              defined". Setting both is unsupported (the derived
              `source` and the user-provided `source` would merge via
              `lib.types.path`'s `lastValue` semantics; the result is
              well-defined but rarely what you want).
            '';
          };
          source = lib.mkOption {
            type = lib.types.path;
            description = ''
              On-disk path that the entry materialises. Typically a
              `/nix/store` path produced by a derivation. Behaviour at
              build time depends on `mode` and on whether `source` is
              a regular file or a directory — see `mode` below.
            '';
          };
          runtimeCertificateBundle = lib.mkOption {
            type = lib.types.nullOr (lib.types.listOf (lib.types.submodule {
              options = {
                source = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "Authenticated store file containing PEM certificates.";
                };
                text = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "Inline PEM certificate bytes.";
                };
              };
            }));
            default = null;
            internal = true;
            description = ''
              Ordered certificate-only PEM inputs concatenated by the runtime
              configuration materializer. Exactly one of `source` or `text`
              must be set for each part. This avoids derivation builders in
              the eval-only host configuration path.
            '';
          };
          mode = lib.mkOption {
            type =
              lib.types.either
              (lib.types.enum ["symlink" "direct-symlink"])
              (lib.types.strMatching "[0-7]{3,4}");
            default = "symlink";
            description = ''
              How the entry is materialised in the system EROFS image
              that AOS uses as the bottom lower of the `/etc` overlay.

              - `"symlink"` (default): when `source` is a regular file,
                emit a single composefs symlink at `target` pointing
                at `source`. When `source` is a directory, recurse:
                `target` becomes a real directory in the EROFS image
                and every descendant becomes its own composefs entry.
                The recursion is what allows another lower (e.g.
                per-generation configuration writes) to merge files into
                the same directory at runtime — overlayfs can only
                merge two directory inodes, not a directory and a
                symlink.
              - `"direct-symlink"`: always emit a single composefs
                symlink entry, regardless of `source`'s on-disk type
                — no recursion. Use this only when you explicitly
                want `target` to be a symlink-to-directory in the
                EROFS image.
              - `"0xxx"` / `"0xxxx"` (3- or 4-digit octal): copy the
                source into the EROFS image's content basedir at
                build time, embed only the metadata (mode, uid, gid)
                in the EROFS image itself, and serve content from the
                basedir via overlayfs's metacopy machinery. Use this
                when you need a specific file mode — e.g. `"0600"`
                for a PAM secret.
            '';
          };
          uid = lib.mkOption {
            type = lib.types.int;
            default = 0;
            description = ''
              Numeric owner UID encoded in the EROFS metadata image.
              Takes effect only for octal `mode` values; symlink
              entries ignore ownership.
            '';
          };
          gid = lib.mkOption {
            type = lib.types.int;
            default = 0;
            description = ''
              Numeric owner GID encoded in the EROFS metadata image.
              Same caveats as `uid`.
            '';
          };
        };
        config = let
          safe = "etc-" + lib.replaceStrings ["/"] ["-"] name;
          basename = baseNameOf name;
        in {
          # When `text` is set, derive `source` from it via writeTextFile.
          # AOS's writeTextFile produces a directory output (stdenv/setup.sh
          # pre-creates $out as a dir, then cp puts the file inside), so use
          # destination="/<basename>" and reference the inner path.
          #
          # The mkIf condition and the `text == null` guard are deliberately
          # redundant: `collectDefsAtPath` forces every mkIf def's value to WHNF
          # during option collection — even for the FALSE branch (it can't drop
          # the dead branch without forcing the condition early, which would
          # create fixpoint cycles). So a bare `mkIf (text != null) "${textDrv}…"`
          # would build `writeTextFile` for EVERY entry, including the many
          # store-sourced ones whose `text` is null. That faults under the
          # On-host evaluation uses a `pkgs` value without builder functions. The inner
          # guard keeps the dead-branch value a plain string so WHNF never
          # constructs the derivation; the live branch is byte-identical.
          source = lib.mkIf (config.text != null) (
            if config.text == null
            then "/var/empty"
            else "${pkgs.writeTextFile {
              name = safe;
              text = config.text;
              destination = "/${basename}";
            }}/${basename}"
          );
        };
      }));
      description = ''
        Set of files to be installed in `/etc`. Each entry is keyed
        by its target path under `/etc` and carries a typed submodule
        — see `target` / `source` / `text` / `mode` / `uid` / `gid`.
      '';
    };

    # `systemd.services` / `systemd.timers` and the rest of the
    # typed systemd.* option tree live in modules/systemd/system.nix
    # now (spec v3.1 stage 4). The stage-3 `systemdNew.*` alias has
    # been renamed back to `systemd.*` in the same commit.

    system.build = {
      ## The top-level system derivation (image builder entry point).
      toplevel = lib.mkOption {
        type = lib.types.package;
        description = ''
          The top-level system derivation. Contains /etc, systemd units,
          and symlinks to all system packages. This is what the image builder
          and update system reference.
        '';
      };

      ## Pure-data `aos.config-manifest/v1` contract.
      configManifest = lib.mkOption {
        type = lib.types.attrs;
        readOnly = true;
        description = ''
          The `aos.config-manifest/v1` value: a pure attrset (no
          derivations forced, no secrets) describing the rendered `/etc`
          tree, systemd reconcile actions, F2-A job-script texts, users,
          presets, pinned store paths, the module ABI, and the five
          content-addressed eval inputs. This is the data contract the on-host
          evaluator emits and the imperative materializer consumes
          (architecture.md §"The manifest"). The builder-side systemd unit
          directory is materialized from this value as the parity path for
          on-host generation assembly.

          The image-build value records the image base/evaluator, an empty
          config-module closure, the empty host module, and default facts. The
          on-host resolver replaces those inputs with the authenticated host,
          facts, and resolved config-module closure.
        '';
      };

      ## The `${toplevel}/activate <gen>` script.
      activateScript = lib.mkOption {
        type = lib.types.package;
        description = ''
          A single executable bash script, shipped as
          `''${toplevel}/activate`. Invoked by apm during install /
          upgrade / rollback as `activate <gen-number>`: it rebuilds
          this generation's `/etc` composefs overlay on the live
          system, runs daemon reconciliation, and swaps the new `/etc`
          in atomically. Built from `modules/base/activate.sh.in` with
          its `@tool@` placeholders substituted for store paths.
        '';
      };

      ## The kernel derivation providing bzImage.
      kernel = lib.mkOption {
        type = lib.types.package;
        description = "The kernel derivation providing bzImage.";
      };

      ## The initrd derivation providing initrd.img.
      initrd = lib.mkOption {
        type = lib.types.package;
        description = "The initrd derivation providing initrd.img.";
      };

      ## Colon-joined PATH derived from `environment.systemPackages`.
      systemPath = lib.mkOption {
        type = lib.types.str;
        readOnly = true;
        description = ''
          The system PATH built by joining `bin` and `sbin` directories of
          every package in `environment.systemPackages`. Other modules (PAM
          environment, /etc/profile) reference this so a single source of
          truth governs the system search path.
        '';
      };

      ## EROFS data-only content basedir for octal-mode environment.etc
      ## entries. Mounted as the `datadir+=` source under the /etc
      ## overlay (spec v12 §5.3). Symlink-mode entries are not
      ## materialised here — they ship as composefs symlinks pointing
      ## directly into /nix/store from the metadata image.
      etcBasedir = lib.mkOption {
        type = lib.types.package;
        description = ''
          The data-only lower of the `/etc` composefs overlay. Holds
          file content for every `environment.etc` entry whose `mode`
          is a 3- or 4-digit octal value (i.e. needs custom
          permissions). Mounted at `/run/etc/system-<gen>/content`
          via overlayfs `datadir+=`.
        '';
      };

      ## composefs-dump(5) text describing the EROFS metadata image's
      ## inode table. First-class output so checks can inspect it as
      ## plain text without mounting the EROFS in the Nix sandbox.
      etcDump = lib.mkOption {
        type = lib.types.package;
        description = ''
          The composefs-dump(5) text describing the EROFS metadata
          image: one line per inode (path + filetype/mode + uid + gid
          + payload). Consumed by `etcMetadataImage`. Plain text, no
          privileged mount required.
        '';
      };

      ## EROFS image that becomes the system metadata lower of /etc.
      etcMetadataImage = lib.mkOption {
        type = lib.types.package;
        description = ''
          The EROFS image carrying the metadata (modes, ownership,
          symlink targets, directory structure) of every
          `environment.etc` entry. Mounted read-only at
          `/run/etc/system-<gen>/metadata` and stacked above
          `etcBasedir` via overlayfs `metacopy=on` + `redirect_dir=on`.
        '';
      };
    };
  };

  config = {
    # --- composefs lower for /etc (spec v12 §5.3) --------------------
    #
    # `etcBasedir` materialises octal-mode entries as regular files
    # under a flat tree. Symlink-mode entries don't appear here — the
    # composefs metadata image embeds those as symlinks pointing
    # directly into /nix/store. Mirrors nixos/modules/system/etc/
    # etc.nix:367-388 (MIT, Eelco Dolstra et al.).
    system.build.etcBasedir = pkgs.runCommand "etc-basedir" {} ''
      set -euo pipefail

      makeEtcEntry() {
        src="$1"
        target="$2"

        mkdir -p "$out/$(dirname "$target")"
        cp "$src" "$out/$target"
      }

      mkdir -p "$out"
      ${lib.concatMapStringsSep "\n" (
          entry:
            lib.escapeShellArgs [
              "makeEtcEntry"
              "${entry.source}"
              entry.target
            ]
        )
        etcHardlinks}
    '';

    # `etcDump` runs build-composefs-dump.py against the JSON
    # description of every enabled entry. Plain text output so the
    # merge-safety check (§5.7) can inspect it without mounting EROFS.
    system.build.etcDump = let
      etcJson = pkgs.writeTextFile {
        name = "etc-json";
        text = builtins.toJSON etc';
        destination = "/etc.json";
      };
    in
      pkgs.runCommand "etc-dump" {} ''
        # AOS stdenv pre-creates $out as a directory (stdenv/setup.sh).
        # The dump is a single text file, so drop the dir and write
        # straight to $out.
        rmdir "$out"
        ${pkgs.python3}/bin/python3 \
          ${../../pkgs/system/build-composefs-dump.py} \
          ${etcJson}/etc.json > $out
      '';

    # `etcMetadataImage` is the EROFS image consumed by overlayfs
    # `lowerdir+=`. The `fsck.erofs` sanity check is wired in once
    # `pkgs.erofs-utils` lands (delegated to a separate task; see
    # spec v12 step 3).
    system.build.etcMetadataImage = pkgs.runCommand "etc-metadata.erofs" {} ''
      # AOS stdenv pre-creates $out as a directory; the EROFS image is
      # a single file, so drop the dir first.
      rmdir "$out"
      ${pkgs.composefs}/bin/mkcomposefs --from-file ${config.system.build.etcDump} $out
      ${pkgs.erofs-utils}/bin/fsck.erofs $out
    '';

    # Enforce `config.assertions` and surface `config.warnings` at
    # `system.build.toplevel` construction time. Matches the nixpkgs
    # convention (`nixos/modules/system/activation/top-level.nix`):
    # a broken config is still inspectable via `config.*` — only
    # forcing `system.build.toplevel` triggers the assertion throw,
    # which lets `aos repl` / `aos show` / debugging tools still work
    # on a config that would refuse to build.
    system.build.toplevel = let
      failedAssertions = builtins.filter (a: !a.assertion) config.assertions;
      assertionCheck =
        if failedAssertions == []
        then null
        else if aosStructuredErrors
        then
          throw (builtins.toJSON {
            __aosEvalError = {
              kind = "assertion";
              msg = (builtins.head failedAssertions).message;
              file = null;
            };
          })
        else
          throw ''
            Failed assertions:
            ${lib.concatStringsSep "\n" (builtins.map (a: "  - ${a.message}") failedAssertions)}
          '';
      # Emit every warning via `builtins.trace` in a single fold. The
      # trace writes to stderr during evaluation and returns its second
      # argument unchanged, so the chain produces a sentinel value we
      # can `seq` against the derivation construction.
      warningTrace = builtins.foldl' (acc: w: builtins.trace "warning: ${w}" acc) null config.warnings;
    in
      # `seq` forces both sides of the checks before the derivation
      # is constructed. If `assertionCheck` throws, the toplevel
      # derivation is never built.
      builtins.seq assertionCheck (
        builtins.seq warningTrace (pkgs.mkDerivation {
          name = "aos-system-toplevel";
          src = null;

          buildDeps = [pkgs.coreutils];

          phases = [
            {
              name = "build-toplevel";
              # Named-output layout per spec v12 §1. No more
              # `${toplevel}/etc` tree — the system /etc content lives
              # entirely in the composefs metadata image plus basedir,
              # mounted as the bottom lower of the /etc overlay at
              # boot. Consumers read named-output paths directly:
              #   etc-metadata.erofs, etc-basedir/, etc-dump,
              #   systemd-units/, os-release,
              #   meta/{package-name,version}, kernel, initrd.
              # `activate` is the live install/upgrade/rollback driver
              # (`activate <gen>`); apm invokes it after swinging the
              # `current → gen-N` profile pointer.
              script = ''
                mkdir -p $out/meta $out/nix-support

                ln -sfn ${config.system.build.etcMetadataImage} $out/etc-metadata.erofs
                ln -sfn ${config.system.build.etcBasedir} $out/etc-basedir
                ln -sfn ${config.system.build.etcDump} $out/etc-dump
                ln -sfn ${config.system.build.systemdSystemUnits} $out/systemd-units
                ln -sfn ${config.system.build.systemdSystemPresets} $out/systemd-presets
                ln -sfn ${config.environment.etc."os-release".source} $out/os-release
                ln -sfn ${config.system.build.kernel} $out/kernel
                ln -sfn ${config.system.build.initrd} $out/initrd
                ln -sfn ${config.system.build.activateScript} $out/activate
                ln -sfn ${config.aos.config.evalAtBoot.baseLib} $out/base-lib
                ln -sfn ${config.system.build.aosPackageProfileSeed} $out/package-profile-seed

                # `aos-seed-profiles.service` reads these on first boot
                # to populate `state.json`. Plain text — `read_meta`
                # in the service script strips the trailing newline.
                printf '%s' "${config.aos.system.name}" > $out/meta/package-name
                printf '%s' "${config.aos.system.version}" > $out/meta/version
                printf '%s' "${toString config.aos.system.moduleAbi}" > $out/meta/module-abi
                printf '%s' "sha256:${builtins.hashString "sha256" (toString config.aos.config.evalAtBoot.baseLib)}" > $out/meta/baselib-digest
                printf '%s' "EFI/Linux/aos-generation-0000000001${lib.optionalString (config.aos.boot.bootCountingTries != null) "+${toString config.aos.boot.bootCountingTries}"}.efi" > $out/meta/uki-path
                printf '%s' ${lib.escapeShellArg config.aos.filesystems.espDevice} > $out/meta/esp-device
                printf '%s\n' ${lib.escapeShellArg (builtins.toJSON {
                  backend = config.aos.boot.storage.backend;
                  espDevices = config.aos.boot.storage.espDevices;
                  devices = config.aos.boot.storage.resolvedDevices;
                })} > $out/meta/boot-storage.json

                # Closure tracking: list every systemPackage as a
                # /nix/store path so Nix's reference scanner pulls
                # them into the toplevel's closure (and thereby the
                # rootfs's, via `allClosures = [toplevel kernel] ++
                # extraClosures` in lib/build/rootfs.nix).
                ${lib.concatStringsSep "\n" (
                  builtins.map (
                    p: "echo ${builtins.toString p} >> $out/nix-support/system-packages"
                  )
                  config.environment.systemPackages
                )}
              '';
            }
          ];

          meta = {
            description = "AOS system toplevel";
          };
        })
      );

    # Substitute the `@tool@` placeholders in activate.sh.in for store
    # paths. AOS's stdenv has no `substituteAll`, so this uses the
    # `pkgs.runCommand` + `pkgs.sed` idiom. The body is kept in a
    # committed `.sh.in` file (not an inline Nix string) so the script's
    # shell `${N}` / `${prev_gen:-}` expansions don't collide with Nix's
    # own `${…}` interpolation. `@apm@` resolves to `pkgs.aos` (the apm
    # binary); this does not create a cycle since `pkgs.aos` is a Rust
    # binary that does not depend on the toplevel.
    # The activate script is an image-fixed artifact (it just
    # substitutes pkgs store paths into activate.sh.in). Reference the resolved
    # artifact; register the source guarded on frozenArtifacts so the stage-2
    # frozen pkgs (no `runCommand`) never evaluates it.
    system.build.activateScript = config.aos.config.artifacts.aos-activate;
    aos.config._artifactSources.aos-activate =
      if config.aos.config.frozenArtifacts ? "aos-activate"
      then null
      else
        pkgs.runCommand "aos-activate" {} ''
          # AOS stdenv pre-creates $out as a directory; this output is a
          # single executable file, so drop the dir and write to $out.
          rmdir "$out"
          ${pkgs.sed}/bin/sed \
            -e "s|@bash@|${pkgs.bash}|g" \
            -e "s|@coreutils@|${pkgs.coreutils}|g" \
            -e "s|@util-linux@|${pkgs.util-linux}|g" \
            -e "s|@erofs-utils@|${pkgs.erofs-utils}|g" \
            -e "s|@apm@|${pkgs.aos}|g" \
            -e "s|@systemd@|${pkgs.systemd}|g" \
            ${./activate.sh.in} > "$out"
          chmod +x "$out"
        '';

    # --- aos.config-manifest/v1 (pure data) ----------------------------
    #
    # The builder-side toplevel consumes these same systemd entries through the
    # thin materializer in `lib/modules/systemd/lib.nix`; there is no parallel
    # derivation-bearing unit assembly path.
    system.build.configManifest = let
      jobScripts = config.system.build.systemdJobScripts;

      isOctal = m: builtins.match "[0-7]{3,4}" m != null;

      # `/etc` entries contributed by `environment.etc`, minus the
      # `systemd/system` directory (expanded per-unit below).
      renderEtc = e:
        if e.runtimeCertificateBundle != null
        then {
          kind = "certificate-bundle";
          mode =
            if isOctal e.mode
            then e.mode
            else "0644";
          parts = builtins.map (part:
            if part.source != null && part.text == null
            then {
              kind = "store-file";
              path = part.source;
            }
            else if part.source == null && part.text != null
            then {
              kind = "text";
              inherit (part) text;
            }
            else throw "runtimeCertificateBundle parts must set exactly one of source or text")
          e.runtimeCertificateBundle;
        }
        else if e.text != null
        then {
          kind = "text";
          text = e.text;
          mode =
            if isOctal e.mode
            then e.mode
            else "0644";
        }
        else if isOctal e.mode
        then {
          # Octal-mode, store-sourced: content lives in the EROFS basedir;
          # v1 manifest pins the source path (the materializer recovers
          # mode/uid/gid from the metadata image). Documented limitation.
          kind = "store-symlink";
          target = builtins.toString e.source;
        }
        else {
          kind = "store-symlink";
          target = builtins.toString e.source;
        };
      pathString = value: builtins.unsafeDiscardStringContext (builtins.toString value);
      systemPackageOwners = lib.unique (builtins.map
        (package: provenance.ownerOfListString ["environment" "systemPackages"] (pathString package))
        config.environment.systemPackages);
      sessionVariableOwners = lib.unique (lib.concatMap
        (name: provenance.dependencyOwnersOfAttr ["environment" "sessionVariables"] name)
        (builtins.attrNames config.environment.sessionVariables));
      # The login environment is rendered by image modules, but its bytes are
      # a projection of shared operator configuration. A package must not make
      # one of these global artifacts survive after that package is removed,
      # so package-owned contributions fail closed instead of being promoted
      # to host ownership.
      sharedArtifactOwner = description: owners: let
        uniqueOwners = lib.unique owners;
        packageOwners = builtins.filter (owner: !builtins.elem owner ["@base" "@host"]) uniqueOwners;
      in
        if packageOwners != []
        then throw "config manifest shared artifact ${description} depends on package owner(s): ${lib.concatStringsSep ", " packageOwners}"
        else if builtins.elem "@host" uniqueOwners
        then "@host"
        else "@base";
      artifactOwner = path: name: let
        owners = provenance.dependencyOwnersOfAttr path name;
      in
        if path == ["environment" "etc"] && name == "profile"
        then sharedArtifactOwner "environment.etc.profile" (owners ++ systemPackageOwners)
        else if path == ["environment" "etc"] && name == "pam/environment"
        then sharedArtifactOwner "environment.etc.pam/environment" (owners ++ systemPackageOwners ++ sessionVariableOwners)
        else if builtins.length owners == 1
        then builtins.head owners
        else if owners == []
        then "@base"
        else throw "config manifest artifact ${builtins.concatStringsSep "." path}.${name} depends on multiple owners: ${lib.concatStringsSep ", " owners}";
      envEtcRecords = lib.concatLists (lib.mapAttrsToList (name: e:
        lib.optional (e.enable && e.target != "systemd/system") {
          path = e.target;
          value = renderEtc e;
          owner =
            if e.runtimeCertificateBundle != null
            then config.aos.security.pki._runtimeBundleOwner
            else artifactOwner ["environment" "etc"] name;
        })
      config.environment.etc);
      envEtcTargets = builtins.map (record: record.path) envEtcRecords;
      pathsOverlap = left: right:
        left
        == right
        || lib.hasPrefix "${left}/" right
        || lib.hasPrefix "${right}/" left;
      duplicateEnvEtcTargets =
        builtins.filter
        (target: builtins.length (builtins.filter (candidate: pathsOverlap target candidate) envEtcTargets) > 1)
        (lib.unique envEtcTargets);
      envEtc =
        if duplicateEnvEtcTargets != []
        then throw "environment.etc entries collide at final /etc target(s): ${lib.concatStringsSep ", " duplicateEnvEtcTargets}"
        else
          builtins.listToAttrs (builtins.map (record:
            lib.nameValuePair record.path record.value)
          envEtcRecords);
      envEtcOwnership = builtins.listToAttrs (builtins.map (record:
        lib.nameValuePair record.path record.owner)
      envEtcRecords);
      systemdEtcOwnership =
        systemdLib.unitsToOwnership
        config.system.build.systemdUnitBodies
        config.system.build.systemdUnitOwners;

      etcCollisions =
        builtins.filter
        (target:
          builtins.any
          (systemdTarget: pathsOverlap target systemdTarget)
          (builtins.attrNames config.system.build.systemdEtcEntries))
        (builtins.attrNames envEtc);
      etc =
        if etcCollisions != []
        then throw "environment.etc and systemd entries collide at final /etc target(s): ${lib.concatStringsSep ", " etcCollisions}"
        else envEtc // config.system.build.systemdEtcEntries;
      etcOwnership = envEtcOwnership // systemdEtcOwnership;

      # Users from `aos.users.*` (best-effort; `or` fallbacks keep this
      # robust if the users module isn't imported by a given variant).
      users = lib.mapAttrsToList (uname: u: {
        name = uname;
        uid = u.uid;
        group = u.group;
        gid = config.aos.users.groups.${u.group}.gid or null;
        home = u.home;
        shell = u.shell;
        system = u.uid < 1000;
        description = u.description or "";
        supplementaryGroups = u.extraGroups or [];
      }) (config.aos.users.users or {});
      userDependencyOwners = user: let
        userOwners = provenance.dependencyOwnersOfAttr ["aos" "users" "users"] user.name;
        groupNames = lib.unique ([user.group] ++ user.supplementaryGroups);
        groupOwners = lib.concatLists (builtins.map
          (group: provenance.dependencyOwnersOfAttr ["aos" "users" "groups"] group)
          groupNames);
      in
        lib.unique (userOwners ++ groupOwners);
      userOwnership = builtins.listToAttrs (builtins.map (user: let
        owners = userDependencyOwners user;
      in
        if builtins.length owners == 1
        then lib.nameValuePair user.name (builtins.head owners)
        else throw "config manifest user ${user.name} depends on multiple owners (including referenced groups): ${lib.concatStringsSep ", " owners}")
      users);

      # Presets parsed from the image preset rules ("<policy> <unit>").
      presetRecords = builtins.filter (p: p != null) (builtins.map (rule: let
        parts = lib.splitString " " rule;
        owner = provenance.ownerOfListString ["systemd" "systemPresetRules"] rule;
        source =
          if owner == "@base"
          then "image"
          else if owner == "@host"
          then "host.nix"
          else owner;
      in
        if builtins.length parts >= 2
        then {
          value = {
            unit = builtins.elemAt parts 1;
            policy = builtins.head parts;
            inherit source;
          };
          inherit owner;
        }
        else null)
      (config.systemd.systemPresetRules or []));
      presets = builtins.map (record: record.value) presetRecords;
      presetOwnership = builtins.listToAttrs (builtins.map (record:
        lib.nameValuePair "${record.value.unit}:${record.value.source}" record.owner)
      presetRecords);

      # Find every canonical store root embedded in an emitted manifest string.
      # Runtime role modules deliberately reference their tools by absolute
      # path instead of adding them to environment.systemPackages, so their
      # unit bodies and job scripts are closure-bearing artifacts too. Keep
      # this pattern byte-for-byte aligned with the accepted store-name
      # alphabet in the Rust manifest validator.
      storeRootsInString = value:
        lib.concatLists (builtins.map
          (part:
            if builtins.isList part
            then builtins.filter (match: match != null) part
            else [])
          (builtins.split
            "(/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+)"
            (pathString value)));
      storeRecordsInString = owner: value:
        builtins.map (path: {inherit path owner;}) (storeRootsInString value);
      storeRoot = target: let
        parts = lib.splitString "/" target;
      in
        if builtins.length parts >= 4 && builtins.elemAt parts 1 == "nix" && builtins.elemAt parts 2 == "store"
        then "/nix/store/${builtins.elemAt parts 3}"
        else throw "config manifest store-symlink target is outside /nix/store: ${target}";
      packageStoreRecords =
        builtins.map (package: let
          path = pathString package;
        in {
          inherit path;
          owner = provenance.ownerOfListString ["environment" "systemPackages"] path;
        })
        config.environment.systemPackages;
      etcStoreRecords = lib.concatMap (record:
        if record.value.kind == "store-symlink"
        then [
          {
            path = storeRoot record.value.target;
            inherit (record) owner;
          }
        ]
        else if record.value.kind == "certificate-bundle"
        then
          builtins.map (part: {
            path = storeRoot part.path;
            inherit (record) owner;
          }) (builtins.filter (part: part.kind == "store-file") record.value.parts)
        else [])
      envEtcRecords;
      emittedEtcStoreRecords = lib.concatMap (path: let
        entry = etc.${path};
        owner = etcOwnership.${path};
        strings =
          if entry.kind == "text"
          then [entry.text]
          else if entry.kind == "store-symlink"
          then [entry.target]
          else if entry.kind == "certificate-bundle"
          then
            builtins.map
            (part:
              if part.kind == "store-file"
              then part.path
              else part.text)
            entry.parts
          else [];
      in
        lib.concatMap (storeRecordsInString owner) strings)
      (builtins.attrNames etc);
      emittedJobStoreRecords = lib.concatMap (key:
        storeRecordsInString jobScriptOwnership.${key} jobScripts.${key}.text)
      (builtins.attrNames jobScripts);
      emittedUserStoreRecords = lib.concatMap (user:
        storeRecordsInString userOwnership.${user.name} "${user.home}\n${user.shell}")
      users;
      emittedProjectionStoreRecords = lib.concatLists (lib.mapAttrsToList (package: binding:
        storeRecordsInString package (builtins.toJSON {
          inherit (binding) desired credentials;
        }))
      exposeProjectionBindings);
      storeRecords =
        packageStoreRecords
        ++ etcStoreRecords
        ++ emittedEtcStoreRecords
        ++ emittedJobStoreRecords
        ++ emittedUserStoreRecords
        ++ emittedProjectionStoreRecords;
      storePaths =
        builtins.sort (a: b: a < b)
        (lib.unique (builtins.map (record: record.path) storeRecords));
      storeOwner = path: let
        owners =
          lib.unique (builtins.map (record: record.owner)
            (builtins.filter (record: record.path == path) storeRecords));
        nonHostOwners = builtins.filter (owner: owner != "@host") owners;
      in
        # @base is the least-privileged classification: every authenticated
        # artifact may reference image-owned content. @host is the most
        # permissive artifact owner and therefore never overrides a more
        # constrained package owner merely because host.nix selected the
        # feature. Two unrelated package owners remain an ambiguity and fail
        # closed rather than silently laundering either package's closure.
        if builtins.elem "@base" owners
        then "@base"
        else if builtins.length nonHostOwners == 1
        then builtins.head nonHostOwners
        else if nonHostOwners == [] && owners == ["@host"]
        then "@host"
        else throw "config manifest store path ${path} has multiple package owners: ${lib.concatStringsSep ", " owners}";
      storeOwnership = builtins.listToAttrs (builtins.map (path:
        lib.nameValuePair path (storeOwner path))
      storePaths);
      unitOwnership = config.system.build.systemdUnitOwners;
      jobScriptOwner = key: let
        matchingUnits =
          builtins.filter
          (unit: lib.hasPrefix "${unit}:" key)
          (builtins.attrNames unitOwnership);
      in
        if builtins.length matchingUnits == 1
        then unitOwnership.${builtins.head matchingUnits}
        else throw "config manifest job-script key ${key} does not identify exactly one unit";
      jobScriptOwnership = lib.mapAttrs (key: _: jobScriptOwner key) jobScripts;
      hashIdentity = value: "sha256:${builtins.hashString "sha256" value}";
      baseLibPath = pathString config.aos.config.evalAtBoot.baseLib;
      evaluatorPath = pathString pkgs.aos;
      evaluatorStoreHash =
        "sha256:"
        + builtins.convertHash {
          hash = builtins.substring 0 32 (baseNameOf evaluatorPath);
          # A Nix store-path component is exactly 20 bytes. `convertHash`
          # needs an algorithm solely to select that width; the RFC wire label
          # remains `sha256:` for the store identity field.
          hashAlgo = "sha1";
          toHashFormat = "base16";
        };
      emptyHost = builtins.toFile "aos-empty-host.nix" "{}";
      emptyHostPath = pathString emptyHost;
      defaultFacts = builtins.toJSON (config.host.facts or {});
      defaultFactsFile = builtins.toFile "aos-default-instance-facts.json" defaultFacts;
      ownership = {
        etc = etcOwnership;
        units = unitOwnership;
        jobScripts = jobScriptOwnership;
        users = userOwnership;
        presets = presetOwnership;
        storePaths = storeOwnership;
      };
      exposeProjectionBindings = builtins.listToAttrs (lib.concatMap (package:
        if
          builtins.hasAttr package config
          && config.${package} ? _aosExposeConfigProjection
        then [
          (lib.nameValuePair package config.${package}._aosExposeConfigProjection)
        ]
        else [])
      provenance.packageNames);
    in ({
        schema = "aos.config-manifest/v1";
        inherit etc users presets storePaths;
        jobScripts = jobScripts;
        units = config.system.build.systemdUnitActions;
        module_abi = config.aos.system.moduleAbi or 1;
        inputs = {
          base_lib = {
            store_path = baseLibPath;
            abi_hash = config.aos.config.evalAtBoot.baseLibAbiHash;
            module_abi = config.aos.system.moduleAbi or 1;
          };
          evaluator = {
            store_path = evaluatorPath;
            store_hash = evaluatorStoreHash;
          };
          config_modules = {
            closure_hash = hashIdentity "[]";
            count = 0;
            store_paths = [];
            nar_hashes = [];
            package_names = [];
            origins = [];
            module_abi_compat = [];
          };
          host_nix = {
            content_hash = hashIdentity "{}";
            trust_mode = "image";
            platform = "image";
            signer_key = null;
            store_path = emptyHostPath;
          };
          instance_facts = {
            facts_hash = hashIdentity defaultFacts;
            platform = "image";
            store_path = pathString defaultFactsFile;
          };
        };
        packages = [];
        packageOutputs = {};
        graph.edges = {};
        config = builtins.mapAttrs (_: binding: binding.desired) exposeProjectionBindings;
        credentials = builtins.mapAttrs (_: binding: binding.credentials) exposeProjectionBindings;
        inherit ownership;
      }
      // lib.optionalAttrs (exposeProjectionBindings != {}) {
        configProjectionBindings = builtins.mapAttrs (_: binding:
          builtins.removeAttrs binding ["desired" "credentials"])
        exposeProjectionBindings;
      });

    # Route builder-side systemd assembly through the emitted manifest. The
    # systemd module's equivalent default exists only so its standalone test
    # does not need to import this full base-build module.
    system.build.systemdMaterializationData = {
      etc = config.system.build.configManifest.etc;
      jobScripts = config.system.build.configManifest.jobScripts;
    };

    system.build.kernel = pkgs.linux;
    system.build.systemPath =
      makeBinPath config.environment.systemPackages
      + ":"
      + makeSbinPath config.environment.systemPackages;

    # The minimal-distro baseline on the interactive PATH. This is the single
    # intentional place for it; feature modules must NOT add to systemPackages
    # (their services reference tools by absolute store path), so the login
    # PATH stays a deliberate core set rather than an accretion of every
    # feature's tools. Anything beyond this is an apm install.
    environment.systemPackages = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.grep
      pkgs.sed
      pkgs.gawk
      pkgs.util-linux
      pkgs.systemd
      pkgs.kmod
      pkgs.e2fsprogs
      pkgs.less
    ];

    environment.etc."profile" = {
      text = ''
        if [ -n "$__ETC_PROFILE_SOURCED" ]; then return; fi
        __ETC_PROFILE_SOURCED=1
        export __ETC_PROFILE_DONE=1

        export PATH="${config.system.build.systemPath}"
        export PAGER=less

        if [ -f /etc/profile.local ]; then
          . /etc/profile.local
        fi

        if [ -n "''${BASH_VERSION:-}" ]; then
          . /etc/bashrc
        fi
      '';
    };

    environment.etc."bashrc" = {
      text = ''
        if [ -z "$__ETC_PROFILE_DONE" ]; then
          . /etc/profile
        fi

        if [ -n "$PS1" ]; then
          if [ "$TERM" != "dumb" ]; then
            PROMPT_COLOR="1;31m"
            ((UID)) && PROMPT_COLOR="1;32m"
            PS1="\n\[\033[$PROMPT_COLOR\][\[\e]0;\u@\h: \w\a\]\u@\h:\w]\\$\[\033[0m\] "
            if [ "$TERM" = "xterm" ]; then
              PS1="\[\033]2;\h:\u:\w\007\]$PS1"
            fi
          fi

          alias ls='ls -NFh --group-directories-first --color=auto'
        fi
      '';
    };

    # `system.build.initrd` is set by modules/systemd/initrd.nix (tier ii):
    # it renders `boot.initrd.systemd.*` into a gzip+cpio initramfs via
    # modules/base/initrd-builder.nix.
  };
}
