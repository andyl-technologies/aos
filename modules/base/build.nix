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
##! The toplevel build script below pulls them in as a single
##! `ln -s ${config.system.build.systemdSystemUnits} $out/etc/systemd/system`
##! line — the derivation behind `systemdSystemUnits` is assembled by
##! the ported `generateUnits` function in lib/modules/systemd/lib.nix.
{
  config,
  pkgs,
  lib,
  ...
}: let
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
          presets, pinned store paths, the module ABI, and the eval-input
          provenance placeholder. This is the data contract the on-host
          evaluator emits and the imperative materializer consumes
          (architecture.md §"The manifest"). It is purely additive: the
          existing `system.build.toplevel` derivation does not consume it
          yet, so toplevel bytes are unchanged.

          P0 scope note: `etc`/`jobScripts`/`storePaths`/`module_abi` are
          populated from the live config; `units` reconcile actions and
          `inputs` provenance are P1 placeholders (the resolver and the
          attestation pipeline fill them on-host).
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

                # `aos-seed-profiles.service` reads these on first boot
                # to populate `state.json`. Plain text — `read_meta`
                # in the service script strips the trailing newline.
                printf '%s' "${config.aos.system.name}" > $out/meta/package-name
                printf '%s' "${config.aos.system.version}" > $out/meta/version

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
            -e "s|@apm@|${pkgs.aos}|g" \
            ${./activate.sh.in} > "$out"
          chmod +x "$out"
        '';

    # --- aos.config-manifest/v1 (pure data) ----------------------------
    #
    # Purely additive: assembled from the same pure render values the
    # toplevel derivation is built from, but as host-portable data. Not
    # consumed by `system.build.toplevel` (that path is unchanged), so it
    # cannot affect the byte-identical toplevel output.
    system.build.configManifest = let
      unitBodies = config.system.build.systemdUnitBodies;
      jobScripts = config.system.build.systemdJobScripts;

      isOctal = m: builtins.match "[0-7]{3,4}" m != null;

      # `/etc` entries contributed by `environment.etc`, minus the
      # `systemd/system` directory (expanded per-unit below).
      envEtc = builtins.listToAttrs (builtins.map (e:
        lib.nameValuePair e.target (
          if e.text != null
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
          }
        ))
      (builtins.filter (e: e.target != "systemd/system") etc'));

      # `/etc/systemd/system/<unit>` text entries plus the install-symlink
      # farm (.wants/.requires/.upholds + aliases) that `generateUnits`
      # materializes — mirrored here as pure data.
      unitTextEntries = lib.concatLists (lib.mapAttrsToList (unitName: u:
        if u.enable && u.text != null
        then [
          (lib.nameValuePair "systemd/system/${unitName}" {
            kind = "text";
            text = u.text;
            mode = "0644";
          })
        ]
        else if !u.enable
        then [
          (lib.nameValuePair "systemd/system/${unitName}" {
            kind = "symlink";
            target = "/dev/null";
          })
        ]
        else [])
      unitBodies);

      installSymlinks = lib.concatLists (lib.mapAttrsToList (unitName: u:
        builtins.map (a:
          lib.nameValuePair "systemd/system/${a}" {
            kind = "symlink";
            target = unitName;
          })
        u.aliases
        ++ builtins.map (w:
          lib.nameValuePair "systemd/system/${w}.wants/${unitName}" {
            kind = "symlink";
            target = "../${unitName}";
          })
        u.wantedBy
        ++ builtins.map (r:
          lib.nameValuePair "systemd/system/${r}.requires/${unitName}" {
            kind = "symlink";
            target = "../${unitName}";
          })
        u.requiredBy
        ++ builtins.map (h:
          lib.nameValuePair "systemd/system/${h}.upholds/${unitName}" {
            kind = "symlink";
            target = "../${unitName}";
          })
        u.upheldBy)
      unitBodies);

      etc =
        envEtc
        // builtins.listToAttrs (unitTextEntries ++ installSymlinks);

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

      # Presets parsed from the image preset rules ("<policy> <unit>").
      presets = builtins.filter (p: p != null) (builtins.map (rule: let
        parts = lib.splitString " " rule;
      in
        if builtins.length parts >= 2
        then {
          unit = builtins.elemAt parts 1;
          policy = builtins.head parts;
          source = "image";
        }
        else null)
      (config.systemd.systemPresetRules or []));

      storePaths =
        builtins.sort (a: b: a < b)
        (lib.unique (builtins.map builtins.toString config.environment.systemPackages));
    in {
      schema = "aos.config-manifest/v1";
      inherit etc users presets storePaths;
      jobScripts = jobScripts;
      # Per-unit reconcile actions are resolved on-host (P1); empty here.
      units = {};
      module_abi = config.aos.system.moduleAbi or 1;
      # The five content-addressed eval inputs are computed on-host by the
      # resolver/attestation pipeline (build-spec §inputs); P0 placeholder.
      inputs = {};
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
