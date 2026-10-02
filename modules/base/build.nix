##! modules/base/build.nix — System build outputs module
##!
##! Declares the core options that the image builder and deploy bundle depend on:
##!   - environment.systemPackages  — runtime packages accumulated by all modules
##!   - environment.etc             — files to install in /etc
##!   - system.build.toplevel       — the top-level system derivation
##!   - system.build.kernel         — the kernel derivation
##!   - system.build.initrd         — the initrd derivation
##!
##! The selected manager package projects its filesystem entries, executable
##! scripts, ownership, and opaque build output through `aos.manager.selected`.
##! This module incorporates that projection without importing the concrete
##! manager renderer.
{
  config,
  pkgs,
  lib,
  ...
}: let
  bootArtifactContract = pkgs.runCommand "aos-systemd-boot-artifact-contract" {} ''
    mkdir -p "$out"
    ${lib.optionalString (config.aos.apm.healthScript != null) ''
      install -m 0555 ${config.aos.apm.healthScript} "$out/health"
    ''}
    ${pkgs.jq}/bin/jq -n --arg health "$out/health" --argjson enabled ${
      if config.aos.apm.healthScript != null
      then "true"
      else "false"
    } '{
      schema:"aos.systemd.boot-artifact-contract/v1",
      "health-executable":(if $enabled then $health else null end),
      "health-arguments":[]
    }' > "$out/contract.json"
  '';
  etcTrees = config.aos.filesystems.etcTrees;
  treeTargets = builtins.map (entry: entry.target) etcTrees;
  uniqueTreeTargets = lib.unique treeTargets;
  uniquePackages = lib.uniqueBy (package: builtins.toString package);
  etcTreeEntries =
    if builtins.length treeTargets != builtins.length uniqueTreeTargets
    then throw "filesystem tree definitions must use distinct /etc target paths"
    else
      builtins.listToAttrs (builtins.map (entry: {
          name = entry.target;
          value.source = entry.source;
        })
        etcTrees);
  managerConfiguration = config.aos.manager.selected.configuration;
  managerFileEntries = lib.mapAttrs (_: entry:
    if entry.kind == "text"
    then {inherit (entry) text mode;}
    else {
      source = entry.target;
      mode = "direct-symlink";
    })
  managerConfiguration.filesystemEntries;
  managerConfigurationOutput = managerConfiguration.buildOutput {
    inherit (pkgs) runCommand writeTextFile;
  };
  managerInitrd = managerConfiguration.buildInitrd {
    inherit (pkgs) mkDerivation runCommand writeTextFile;
    inherit (pkgs) ociTools;
    packageSet = pkgs;
    buildTools = {
      inherit
        (pkgs.buildPackages)
        aos-ability-contract-validator
        coreutils
        findutils
        gzip
        jq
        mkDerivation
        tar
        ;
      packageRuntime = pkgs.buildPackages.aos.packageRuntime;
    };
    targetPlatform = {
      inherit (pkgs.stdenv.hostPlatform.constraints) os cpu abi features;
    };
  };
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
  imports = [./_filesystem-tree-options.nix];

  options = {
    ## Packages that appear in the system profile PATH.
    environment.systemPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      apply = uniquePackages;
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
      extensible = true;
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
            type = lib.types.either lib.types.path (lib.types.addCheck lib.types.str (_: config.mode == "direct-symlink"));
            description = ''
              On-disk path that the entry materialises. Typically a
              `/nix/store` path produced by a derivation. Behaviour at
              build time depends on `mode` and on whether `source` is
              a regular file or a directory — see `mode` below.
              Direct symlinks may instead carry a literal relative target.
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

    # Concrete manager packages own their typed configuration option trees.

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

      ## The boot contract retained by native image generations.
      bootArtifactContract = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        internal = true;
        description = "Immutable image-owned boot contract with the authored site health executable.";
      };

      ## The kernel artifact selected by the system composition.
      kernel = lib.mkOption {
        type = lib.types.package;
        description = "The kernel package selected by the system composition.";
      };

      ## The initrd derivation providing initrd.img.
      initrd = lib.mkOption {
        type = lib.types.package;
        description = "The initrd derivation providing initrd.img.";
      };

      managerConfiguration = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        internal = true;
        description = "Single package-owned materialization of the selected manager configuration.";
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

  config = lib.mkMerge [
    {
      environment.etc = managerFileEntries;
    }
    {
      environment.etc =
        etcTreeEntries
        // {
          "systemd/system".source = "${managerConfigurationOutput}/systemd-units";
        };
    }
    {
      system.build.initrd = managerInitrd.artifact;
      system.build.managerConfiguration = managerConfigurationOutput;

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

            buildDeps = [pkgs.coreutils pkgs.jq];

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
                script = ''
                  mkdir -p $out/meta $out/nix-support

                  ln -sfn ${config.system.build.etcMetadataImage} $out/etc-metadata.erofs
                  ln -sfn ${config.system.build.etcBasedir} $out/etc-basedir
                  ln -sfn ${config.system.build.etcDump} $out/etc-dump
                  for managerEntry in ${managerConfigurationOutput}/*; do
                    ln -sfn "$managerEntry" "$out/''${managerEntry##*/}"
                  done
                  ln -sfn ${config.environment.etc."os-release".source} $out/os-release
                  ln -sfn ${config.system.build.kernel} $out/kernel
                  ln -sfn ${config.system.build.initrd} $out/initrd
                  ln -sfn ${lib.packageModuleLibrary} $out/module-library
                  # These inputs inherit the image's authenticated authority.
                  ln -sfn ${config.system.build.hostDeploymentBundle} $out/host-deployment
                  ln -sfn ${config.system.build.initrdDeploymentBundle} $out/initrd-deployment
                  ${lib.optionalString (config.aos.apm.drainScript != null) ''
                    ln -sfn ${config.aos.apm.drainScript} $out/drain
                  ''}
                  ${lib.optionalString (config.aos.apm.healthScript != null) ''
                    ln -sfn ${config.aos.apm.healthScript} $out/health
                  ''}

                  # Resolve trusted booted-image commands through the immutable
                  # rootfs command farm. The absolute target deliberately adds no
                  # package closure to the toplevel; early boot authenticates the
                  # target and every rollout command before publishing
                  # `/run/current-system`.
                  ln -s /usr $out/sw

                  # `aos-seed-profiles.service` reads these on first boot
                  # to populate `state.json`. Plain text — `read_meta`
                  # in the service script strips the trailing newline.
                  printf '%s' ${lib.escapeShellArg (toString bootArtifactContract)} > $out/meta/boot-artifact-contract
                  ${lib.optionalString ((config.system.build.bootMetadataBinding or null) != null) ''
                    printf '%s' ${lib.escapeShellArg "${config.system.build.bootMetadataBinding}/binding.json"} > $out/meta/boot-metadata-binding
                  ''}
                  printf '%s' "${pkgs.systemd}/bin/aos-systemd-image-stage" > $out/meta/image-stage-executable
                  printf '%s' "${config.aos.system.name}" > $out/meta/package-name
                  printf '%s' "${config.aos.system.version}" > $out/meta/version
                  printf '%s' "${config.aos.system.stateVersion}" > $out/meta/state-version
                  printf '%s' "${pkgs.aos.packageRuntime}" > $out/meta/native-executor-ref
                  ${pkgs.jq}/bin/jq -e --arg library ${lib.escapeShellArg (toString lib.packageModuleLibrary)} '
                    [.roots[] | select(.storePath == $library)] |
                    if length == 1 then .[0] | {store_path:.storePath,nar_hash:.narHash,nar_size:.narSize}
                    else error("native module library absent from admitted image closure") end
                  ' ${config.system.build.hostDeploymentBundle}/admission.json > $out/meta/module-library.json
                  printf '%s' ${lib.escapeShellArg "${config.system.build.hostDeploymentBundle}/evaluation.json"} > $out/meta/evaluation-descriptor
                  printf '%s' ${lib.escapeShellArg (
                    if config.aos.image.platform == null
                    then ""
                    else config.aos.image.platform.normalArtifactPath
                  )} > $out/meta/uki-path
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

      system.build.kernel = config.aos.kernel.packageRoot;
      system.build.bootArtifactContract = bootArtifactContract;
      system.build.systemPath =
        "/run/wrappers/bin:"
        + makeBinPath config.environment.systemPackages
        + ":"
        + makeSbinPath config.environment.systemPackages;

      environment.etc."profile".text = import ../../pkgs/system/_aos-host-policy/profile-text.nix {
        inherit lib;
        path = config.system.build.systemPath;
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

      # The exactly selected manager package contributes `system.build.initrd`.
    }
  ];
}
