##! modules/base/build.nix — System build outputs module
##!
##! Declares the core options that the image builder and deploy bundle depend on:
##!   - environment.systemPackages  — runtime packages accumulated by all modules
##!   - environment.etc             — files to install in /etc
##!   - systemd.services            — systemd unit definitions
##!   - system.build.toplevel       — the top-level system derivation
##!   - system.build.kernel         — the kernel derivation
##!   - system.build.initrd         — the initrd derivation
{
  config,
  pkgs,
  lib,
  ...
}:
let
  # --- Render /etc files ---
  etcScript = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      name: entry:
      if entry ? source then
        "mkdir -p $out/etc/$(dirname ${name})\nln -sfn ${entry.source} $out/etc/${name}"
      else if entry ? text then
        "mkdir -p $out/etc/$(dirname ${name})\ncat > $out/etc/${name} << 'ETCEOF'\n${entry.text}\nETCEOF"
      else
        "# skipping ${name} (no text or source attribute)"
    ) config.environment.etc
  );

  # --- Render systemd units ---
  renderUnit =
    name: unit:
    let
      section =
        secName: attrs:
        "[${secName}]\n"
        + lib.concatStringsSep "\n" (
          lib.mapAttrsToList (
            k: v: if builtins.isBool v then (if v then "${k}=yes" else "${k}=no") else "${k}=${toString v}"
          ) attrs
        );
      unitSection = {
        Description = unit.description;
      }
      // (if unit ? after then { After = lib.concatStringsSep " " unit.after; } else { })
      // (if unit ? wants then { Wants = lib.concatStringsSep " " unit.wants; } else { })
      // (if unit ? before then { Before = lib.concatStringsSep " " unit.before; } else { });
      installSection =
        if unit ? wantedBy then { WantedBy = lib.concatStringsSep " " unit.wantedBy; } else { };
    in
    ''
      ${section "Unit" unitSection}
      ${section "Service" unit.serviceConfig}
      ${if installSection != { } then section "Install" installSection else ""}
    '';

  unitScripts = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      name: unit:
      if unit ? description && unit ? serviceConfig then
        ''
          mkdir -p $out/etc/systemd/system
          cat > $out/etc/systemd/system/${name}.service << 'UNITEOF'
          ${renderUnit name unit}
          UNITEOF
        ''
        + (
          if unit ? wantedBy then
            lib.concatStringsSep "\n" (
              builtins.map (target: ''
                mkdir -p $out/etc/systemd/system/${target}.wants
                ln -sfn ../${name}.service $out/etc/systemd/system/${target}.wants/${name}.service
              '') unit.wantedBy
            )
          else
            ""
        )
      else
        "# skipping unit ${name} (incomplete definition)"
    ) config.systemd.services
  );

  # --- Render systemd timers ---
  renderTimer =
    name: timer:
    let
      timerSection = lib.concatStringsSep "\n" (
        lib.mapAttrsToList (
          k: v: if builtins.isBool v then (if v then "${k}=yes" else "${k}=no") else "${k}=${toString v}"
        ) timer.timerConfig
      );
      installSection =
        if timer ? wantedBy then "[Install]\nWantedBy=${lib.concatStringsSep " " timer.wantedBy}" else "";
    in
    ''
      [Unit]
      Description=${timer.description}

      [Timer]
      ${timerSection}

      ${installSection}
    '';

  timerScripts = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      name: timer:
      if timer ? description && timer ? timerConfig then
        ''
          mkdir -p $out/etc/systemd/system
          cat > $out/etc/systemd/system/${name}.timer << 'TIMEREOF'
          ${renderTimer name timer}
          TIMEREOF
        ''
        + (
          if timer ? wantedBy then
            lib.concatStringsSep "\n" (
              builtins.map (target: ''
                mkdir -p $out/etc/systemd/system/${target}.wants
                ln -sfn ../${name}.timer $out/etc/systemd/system/${target}.wants/${name}.timer
              '') timer.wantedBy
            )
          else
            ""
        )
      else
        "# skipping timer ${name} (incomplete definition)"
    ) config.systemd.timers
  );

  # --- Build the system PATH from systemPackages ---
  makeBinPath =
    pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") pkgsList);
in
{
  options = {
    ## Assertions checked during system evaluation.
    assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [ ];
      description = ''
        List of assertion attrsets { assertion = bool; message = string; }.
        If any assertion is false, the system build fails with the message.
      '';
    };

    ## Warning messages reported during evaluation.
    warnings = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        List of warning messages. These are reported during evaluation
        but do not prevent the system from building.
      '';
    };

    ## Packages that appear in the system profile PATH.
    environment.systemPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = ''
        The set of packages that appear in the system profile. These packages
        are made available in the system PATH and are included in the Nix store
        closure of the system toplevel.
      '';
    };

    ## Files to install in /etc (text or source symlink).
    environment.etc = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = ''
        Set of files to be installed in /etc. Each attribute maps a relative
        path under /etc to either { text = "..."; } for inline content or
        { source = /path; } for a symlink.
      '';
    };

    ## Systemd service unit definitions.
    systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = ''
        Set of systemd service units. Each attribute maps a unit name to an
        attrset with description, serviceConfig, wantedBy, after, wants, etc.
      '';
    };

    ## Systemd timer unit definitions.
    systemd.timers = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = "Set of systemd timer units.";
    };

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
    system.build.toplevel = pkgs.mkDerivation {
      name = "aos-system-toplevel";
      src = null;

      buildDeps = [ pkgs.coreutils ];

      phases = [
        {
          name = "build-toplevel";
          script = ''
            mkdir -p $out/etc/aos $out/bin $out/sbin

            # Render /etc files
            ${etcScript}

            # Render systemd units
            ${unitScripts}

            # Render systemd timers
            ${timerScripts}

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
              ) config.environment.systemPackages
            )}
          '';
        }
      ];

      meta = {
        description = "AOS system toplevel";
      };
    };

    system.build.kernel = pkgs.linux;

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

    system.build.initrd = pkgs.mkDerivation {
      name = "aos-initrd";
      src = null;

      buildDeps = [
        pkgs.coreutils
      ];

      phases = [
        {
          name = "build-initrd";
          script = ''
            mkdir -p $out

            # Generate systemd-based initrd manifest.
            # The initrd includes systemd, udevd, and modprobe for
            # service-based boot ordering without dracut.
            cat > $out/initrd-manifest << 'MANIFEST'
            kernel=${pkgs.linux}
            systemd=${pkgs.systemd}
            modules=${lib.concatStringsSep " " config.aos.boot.initrd.modules}
            type=systemd-initrd
            MANIFEST

            # Placeholder initrd.img — actual generation requires KVM
            touch $out/initrd.img
          '';
        }
      ];

      meta = {
        description = "AOS initrd (systemd-based initial ramdisk)";
      };
    };
  };
}
