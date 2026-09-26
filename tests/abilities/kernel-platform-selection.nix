##! Strict selected-kernel projection checks.
{
  lib,
  pkgs,
}: let
  digest = character: "sha256:${lib.concatStrings (lib.replicate 64 character)}";
  packagePath = builtins.toString pkgs.linux;
  selectedKernel = {
    _type = "aos-selected-kernel";
    artifact = {
      _type = "aos-artifact-reference";
      content = digest "a";
      store_path = packagePath;
      nar_hash = digest "b";
      closure = digest "c";
    };
    configuration = {
      bootImage = "${packagePath}/boot/vmlinuz-${pkgs.linux.version}";
      moduleTree = "${packagePath}/lib/modules/${pkgs.linux.version}";
      release = pkgs.linux.version;
    };
    identity = {
      binding = "kernel:linux";
      implementation = "linux:kernel";
      package = {
        name = pkgs.linux.pname;
        version = pkgs.linux.version;
      };
      providerInstance = {
        environment = {
          authority = "test";
          key = "kernel-platform";
          stage = "build";
        };
        key = "linux-kernel";
      };
    };
    name = "linux";
    package = packagePath;
    targetPlatform = {
      inherit (pkgs.stdenv.hostPlatform) system;
      inherit (pkgs.stdenv.hostPlatform.constraints) abi cpu os;
    };
  };
  evaluate = value:
    (lib.evalModules {
      inherit lib pkgs;
      modules = [
        ../../modules/base/_kernel-selection.nix
        {
          options = {
            aos.boot.initrd.packageRoots = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
            environment.systemPackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
          };
          config = {
            aos.kernel.packageRoot = pkgs.linux;
            aos.kernel.selected = value;
          };
        }
      ];
    }).config.aos.kernel.selected;
  accepts = value:
    (builtins.tryEval (builtins.deepSeq (evaluate value) true)).success;
in
  assert accepts selectedKernel;
  assert !accepts (selectedKernel // {unexpected = true;});
  assert !accepts (selectedKernel // {targetPlatform = selectedKernel.targetPlatform // {unexpected = true;};});
  assert !accepts (selectedKernel // {identity = selectedKernel.identity // {unexpected = true;};});
  assert !accepts (selectedKernel // {
    identity = selectedKernel.identity // {
      package = selectedKernel.identity.package // {unexpected = true;};
    };
  });
  assert !accepts (selectedKernel // {configuration = selectedKernel.configuration // {unexpected = true;};});
    true
