# Evaluation and build contracts for Linux-hosted Darwin package composition.
{pkgs}: let
  lib = pkgs.lib;
  platforms = import ../../lib/platform.nix;
  buildPlatform = pkgs.stdenv.buildPlatform;
  x86Darwin = platforms.mkPlatform "x86_64-darwin";
  armDarwin = platforms.mkPlatform "aarch64-darwin";

  x86 = import ../.. {
    system = buildPlatform.system;
    crossSystem = x86Darwin.system;
  };
  arm = import ../.. {
    system = buildPlatform.system;
    crossSystem = armDarwin.system;
  };

  x86SplicesCmake =
    (x86.pkgs.spliceBuildDependency x86.pkgs.cmake).drvPath
    == x86.buildPackages.cmake.drvPath;
  armSplicesPython =
    (arm.pkgs.spliceBuildDependency arm.pkgs.python3).drvPath
    == arm.buildPackages.python3.drvPath;
  selectedBuildOutputsRemainSelected =
    (x86.pkgs.spliceBuildDependency x86.pkgs.glib.dev).drvPath
    == x86.buildPackages.glib.dev.drvPath
    && (x86.pkgs.spliceBuildDependency x86.pkgs.glib.dev).outputName == "dev"
    && (arm.pkgs.spliceBuildDependency arm.pkgs.glib.tools).drvPath
    == arm.buildPackages.glib.tools.drvPath
    && (arm.pkgs.spliceBuildDependency arm.pkgs.glib.tools).outputName == "tools";
  targetPackagesRemainDarwin =
    x86.pkgs.cmake.platforms.host.system
    == x86Darwin.system
    && arm.pkgs.python3.platforms.host.system == armDarwin.system;
  sdkPublicationIsTargeted =
    x86.pkgs.darwin-sdk.platforms.host.system
    == x86Darwin.system
    && arm.pkgs.darwin-sdk.platforms.host.system == armDarwin.system
    && x86.pkgs.darwin-sdk.drvPath != x86.stdenv.sdk.drvPath
    && arm.pkgs.darwin-sdk.drvPath != arm.stdenv.sdk.drvPath;
  runtimesComeFromCrossStdenv =
    x86.pkgs.darwin-runtimes.drvPath
    == x86.stdenv.darwinRuntimes.drvPath
    && arm.pkgs.darwin-runtimes.drvPath == arm.stdenv.darwinRuntimes.drvPath;
  baseToolsAreTargetPackages =
    x86.pkgs.bash.platforms.host.system
    == x86Darwin.system
    && x86.pkgs.coreutils.platforms.host.system == x86Darwin.system
    && arm.pkgs.gnumake.platforms.host.system == armDarwin.system
    && arm.pkgs.sed.platforms.host.system == armDarwin.system;
  baseToolBuildDepsStayNative =
    builtins.elem (toString x86.buildPackages.gnumake) x86.pkgs.bash.nativeBuildInputs
    && !(builtins.elem (toString x86.pkgs.gnumake) x86.pkgs.bash.nativeBuildInputs)
    && builtins.elem (toString arm.buildPackages.gnumake) arm.pkgs.bash.nativeBuildInputs
    && !(builtins.elem (toString arm.pkgs.gnumake) arm.pkgs.bash.nativeBuildInputs);
  publicToolchainsAreDarwin =
    x86.pkgs.cc.platforms.host.system
    == x86Darwin.system
    && x86.pkgs.gcc.platforms.host.system == x86Darwin.system
    && x86.pkgs.binutils.platforms.host.system == x86Darwin.system
    && arm.pkgs.cc.platforms.host.system == armDarwin.system
    && arm.pkgs.gcc.platforms.host.system == armDarwin.system
    && arm.pkgs.binutils.platforms.host.system == armDarwin.system;
  linuxOnlyAosRuntimeFragments = [
    "-aos-ebpf-"
    "-aos-landlock-"
    "-aos-selinux-"
    "-aos-verity-root-guard-"
    "-checkpolicy-"
    "-policycoreutils-"
    "-semodule-utils-"
    "-systemd-"
    "-util-linux-"
  ];
  aosRuntimeInputsArePortable = package:
    builtins.all (
      input:
        builtins.all (
          fragment: !(lib.hasInfix fragment (builtins.baseNameOf (toString input)))
        )
        linuxOnlyAosRuntimeFragments
    ) (package.buildInputs or []);
  darwinAosRuntimeIsPortable =
    aosRuntimeInputsArePortable x86.pkgs.aos
    && aosRuntimeInputsArePortable arm.pkgs.aos;

  targetRuntime = pkgs.lib.mkDerivation {
    pname = "darwin-target-runtime-probe";
    version = "0";
    hostPlatform = x86Darwin;
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib"
          printf '#define DARWIN_TARGET_PROBE 1\n' > "$out/include/probe.h"
          printf 'target-only\n' > "$out/bin/target-only"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };

  dependencyRoleProbe = pkgs.lib.mkDerivation {
    pname = "darwin-dependency-role-probe";
    version = "0";
    hostPlatform = x86Darwin;
    buildDeps = [pkgs.coreutils];
    runtimeDeps = [targetRuntime];
    phases = [
      {
        name = "check";
        script = ''
          case ":$PATH:" in
            *":${targetRuntime}/bin:"*)
              echo "Darwin runtime dependency leaked into Linux builder PATH" >&2
              exit 1
              ;;
          esac
          case ":$LD_LIBRARY_PATH:" in
            *":${targetRuntime}/lib:"*)
              echo "Darwin runtime dependency leaked into Linux loader path" >&2
              exit 1
              ;;
          esac
          case ":$C_INCLUDE_PATH:" in
            *":${targetRuntime}/include:"*) ;;
            *)
              echo "Darwin runtime headers missing from target include path" >&2
              exit 1
              ;;
          esac

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };
in
  assert x86SplicesCmake;
  assert armSplicesPython;
  assert selectedBuildOutputsRemainSelected;
  assert targetPackagesRemainDarwin;
  assert sdkPublicationIsTargeted;
  assert runtimesComeFromCrossStdenv;
  assert baseToolsAreTargetPackages;
  assert baseToolBuildDepsStayNative;
  assert publicToolchainsAreDarwin;
  assert darwinAosRuntimeIsPortable;
    pkgs.mkDerivation {
      pname = "cross-platform-foundation-check";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            test "$(cat ${targetRuntime}/nix-support/aos-target-platform)" = "x86_64-darwin"
            test "$(cat ${dependencyRoleProbe}/nix-support/aos-target-platform)" = "x86_64-darwin"
            test "$(cat ${x86.pkgs.darwin-sdk}/nix-support/aos-target-platform)" = "x86_64-darwin"
            test "$(cat ${arm.pkgs.darwin-sdk}/nix-support/aos-target-platform)" = "aarch64-darwin"

            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
