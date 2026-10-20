##! Preserves host and storage policy defaults without constructing an image.
{
  pkgs,
  lib,
}: let
  evaluate = modules: specialArgs:
    lib.evalModules {
      inherit lib modules specialArgs;
      pkgs = {};
    };
  assertionsOption = {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [];
    };
  };
  homes = overrides:
    evaluate [
      ../../pkgs/system/_aos-host-policy/homes.nix
      assertionsOption
      {
        options.aos.users.users = lib.mkOption {
          type = lib.types.attrs;
          default = {};
        };
      }
      overrides
    ] {};
  defaultHomes = homes {};
  invalidHomes = homes {aos.homes.directory = "/home";};
  nssModules = [
    ../../modules/base/nsswitch.nix
    {
      options.environment.etc = lib.mkOption {
        type = lib.types.attrs;
        default = {};
      };
    }
  ];
  nss = evaluate nssModules {};
  systemdNss = evaluate (nssModules ++ [../../pkgs/system/_systemd-abilities/platform/nsswitch.nix]) {};
  extendedNss = evaluate (nssModules
    ++ [
      ../../pkgs/system/_systemd-abilities/platform/nsswitch.nix
      {
        aos.nsswitch.sources.supplemental-group = {
          database = "group";
          source = "ldap";
          order = 250;
          actions = [];
        };
      }
    ]) {};
  pam =
    evaluate [
      ../../pkgs/security/_linux-pam/module.nix
      {
        options.aos.abilities = lib.mkOption {type = lib.types.attrs;};
        aos.pam.services.sshd.startSession = true;
      }
    ] {
      package = "/nix/store/00000000000000000000000000000000-linux-pam";
    };
  zfs = overrides:
    evaluate [
      ../../pkgs/filesystem/_aos-zfs-provider/policy.nix
      assertionsOption
      {
        options.aos = {
          filesystems.zfs.enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
          };
          services = lib.mkOption {type = lib.types.attrs;};
          abilities = lib.mkOption {type = lib.types.attrs;};
          kernel = {
            sysctl = lib.mkOption {type = lib.types.attrs;};
            tunablePrerequisites = lib.mkOption {type = lib.types.listOf lib.types.anything;};
          };
        };
      }
      overrides
    ] {
      package = "/nix/store/00000000000000000000000000000000-zfs-provider";
      dependencies.zfs.version = "2.4.4";
    };
  defaultZfs = zfs {};
  invalidZfs = zfs {aos.filesystems.zfs.memory.arcPercent = 90;};
  pass = evaluated: builtins.all (entry: entry.assertion) evaluated.config.assertions;
  parameters = defaultZfs.config.aos.filesystems.zfs.moduleParameters;
in
  assert !defaultHomes.config.aos.homes.enable;
  assert defaultHomes.config.aos.homes.directory == "/var/home";
  assert defaultHomes.config.aos.homes.mode == "0700";
  assert pass defaultHomes && !pass invalidHomes;
  assert lib.hasInfix "hosts: files dns" nss.config.environment.etc."nsswitch.conf".text;
  assert !lib.hasInfix "mymachines" nss.config.environment.etc."nsswitch.conf".text;
  # NSS actions apply to the immediately preceding source. Files must merge
  # successful local groups before consulting the selected provider.
  assert builtins.elem "group: files [SUCCESS=merge] systemd" (lib.splitString "\n" systemdNss.config.environment.etc."nsswitch.conf".text);
  assert systemdNss.config.aos.nsswitch.sources.systemd-group.actions == [];
  assert builtins.elem "group: files [SUCCESS=merge] systemd ldap" (lib.splitString "\n" extendedNss.config.environment.etc."nsswitch.conf".text);
  assert lib.hasInfix "pam_keyinit.so force revoke" pam.config.aos.pam.files."pam.d/sshd".text;
  assert builtins.elem "spl.spl_kmem_cache_obj_per_slab=1" parameters;
  assert builtins.elem "zfs.zfs_arc_max=${toString (8 * 1073741824 * 70 / 100)}" parameters;
  assert builtins.elem "zfs.zfs_abd_scatter_max_order=0" parameters;
  assert defaultZfs.config.aos.kernel.sysctl."kernel.panic_on_oops" == "1";
  assert defaultZfs.config.aos.kernel.sysctl."vm.defrag_mode" == "1";
  assert pass defaultZfs && !pass invalidZfs;
    pkgs.mkDerivation {
      pname = "aos-baseline-policy-checks";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
