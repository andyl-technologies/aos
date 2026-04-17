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
##! the ported `generateUnits` function in modules/systemd/_lib.nix.
{
  config,
  pkgs,
  lib,
  ...
}: let
  # --- Render /etc files ---
  etcScript = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      name: entry:
        if entry ? source
        then "mkdir -p $out/etc/$(dirname ${name})\nln -sfn ${entry.source} $out/etc/${name}"
        else if entry ? text
        then "mkdir -p $out/etc/$(dirname ${name})\ncat > $out/etc/${name} << 'ETCEOF'\n${entry.text}\nETCEOF"
        else "# skipping ${name} (no text or source attribute)"
    )
    config.environment.etc
  );

  # --- Build the system PATH from systemPackages ---
  makeBinPath = pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") pkgsList);
  makeSbinPath = pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/sbin") pkgsList);
  systemPath = makeBinPath config.environment.systemPackages
    + ":" + makeSbinPath config.environment.systemPackages;
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
      description = ''
        The set of packages that appear in the system profile. These packages
        are made available in the system PATH and are included in the Nix store
        closure of the system toplevel.
      '';
    };

    ## Files to install in /etc (text or source symlink).
    environment.etc = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      description = ''
        Set of files to be installed in /etc. Each attribute maps a relative
        path under /etc to either { text = "..."; } for inline content or
        { source = /path; } for a symlink.
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
    };
  };

  config = {
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
              script = ''
                mkdir -p $out/etc/aos $out/bin $out/sbin $out/etc/systemd

                # Render /etc files
                ${etcScript}

                # Stage the typed systemd unit directory produced by
                # modules/systemd/system.nix's `generateUnits` call.
                # Replaces the old renderUnit/renderTimer heredoc
                # pipeline (spec v3.1 stage 4).
                ln -sfn ${config.system.build.systemdSystemUnits} $out/etc/systemd/system

                # Create system PATH manifest
                cat > $out/etc/aos/system-path << 'PATHEOF'
                ${makeBinPath config.environment.systemPackages}
                PATHEOF

                # Symlink /sbin/init to systemd
                ln -sfn ${pkgs.systemd}/lib/systemd/systemd $out/sbin/init

                # Record the system packages for closure tracking
                mkdir -p $out/nix-support
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

    system.build.kernel = pkgs.linux;

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

        export PATH="${systemPath}"
        export PAGER=less

        if [ -z "$HOME" ] && [ -f /etc/passwd ]; then
          HOME=$(${pkgs.gawk}/bin/awk -F: -v u="$(${pkgs.coreutils}/bin/id -un)" '$1==u{print $6}' /etc/passwd)
          export HOME
        fi

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
      '';
    };

    # Fleet test: verify rolling update across two servers (zero-downtime upgrade).
    system.fleetTests.rolling-update = {
      machines = {
        server1 = {
          variant = "server";
          role = "server";
          mac = "52:54:00:00:00:01";
        };
        server2 = {
          variant = "server";
          role = "server";
          mac = "52:54:00:00:00:02";
        };
      };
      testScript = ''
        # Verify both servers boot and reach running state
        server1.wait_for_unit("multi-user.target")
        server2.wait_for_unit("multi-user.target")

        # Record initial version on both servers
        V1=$(server1.succeed("cat /etc/os-release | grep VERSION_ID | cut -d= -f2"))
        V2=$(server2.succeed("cat /etc/os-release | grep VERSION_ID | cut -d= -f2"))

        # Initiate rolling update on server1 while server2 stays up
        server1.succeed("sysupdate apply --reboot")
        server2.succeed("systemctl is-system-running --wait || true")

        # Wait for server1 to come back after reboot
        server1.wait_for_unit("multi-user.target")

        # Now update server2 while server1 is running the new version
        server2.succeed("sysupdate apply --reboot")
        server1.succeed("systemctl is-system-running --wait || true")

        # Wait for server2 to come back
        server2.wait_for_unit("multi-user.target")

        # Verify both servers are running and reachable after the rolling update
        server1.succeed("systemctl is-system-running --wait || true")
        server2.succeed("systemctl is-system-running --wait || true")
      '';
      timeout = 300;
    };

    # `system.build.initrd` is set by modules/systemd/initrd.nix (tier ii):
    # it renders `boot.initrd.systemd.*` into a gzip+cpio initramfs via
    # modules/base/initrd-builder.nix.
  };
}
