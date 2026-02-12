# modules/base/build.nix — System build outputs module
#
# Declares the core options that the image builder and deploy bundle depend on:
#   - environment.systemPackages  — runtime packages accumulated by all modules
#   - environment.etc             — files to install in /etc
#   - systemd.services            — systemd unit definitions
#   - system.build.toplevel       — the top-level system derivation
#   - system.build.kernel         — the kernel derivation
#   - system.build.initrd         — the initrd derivation

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
      else
        "# skipping unit ${name} (incomplete definition)"
    ) config.systemd.services
  );

  # --- Build the system PATH from systemPackages ---
  makeBinPath =
    pkgsList: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") pkgsList);

in
{
  options = {
    environment.systemPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = ''
        The set of packages that appear in the system profile. These packages
        are made available in the system PATH and are included in the Nix store
        closure of the system toplevel.
      '';
    };

    environment.etc = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = ''
        Set of files to be installed in /etc. Each attribute maps a relative
        path under /etc to either { text = "..."; } for inline content or
        { source = /path; } for a symlink.
      '';
    };

    systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = ''
        Set of systemd service units. Each attribute maps a unit name to an
        attrset with description, serviceConfig, wantedBy, after, wants, etc.
      '';
    };

    systemd.timers = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = "Set of systemd timer units.";
    };

    system.build = {
      toplevel = lib.mkOption {
        type = lib.types.package;
        description = ''
          The top-level system derivation. Contains /etc, systemd units,
          and symlinks to all system packages. This is what the image builder
          and update system reference.
        '';
      };

      kernel = lib.mkOption {
        type = lib.types.package;
        description = "The kernel derivation providing bzImage.";
      };

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

    system.build.initrd = pkgs.mkDerivation {
      name = "aos-initrd";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.dracut
      ];

      phases = [
        {
          name = "build-initrd";
          script = ''
            mkdir -p $out

            # Generate initrd using dracut with AOS configuration
            # In a real build this would invoke dracut; for instantiation
            # we create a placeholder that records the intent.
            cat > $out/initrd-manifest << 'MANIFEST'
            kernel=${pkgs.linux}
            dracut=${pkgs.dracut}
            modules=${lib.concatStringsSep " " config.aos.boot.initrd.modules}
            MANIFEST

            # Placeholder initrd.img — actual generation requires KVM
            touch $out/initrd.img
          '';
        }
      ];

      meta = {
        description = "AOS initrd (initial ramdisk)";
      };
    };
  };
}
