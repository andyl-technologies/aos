##! modules/profiles/development.nix — General software development environment
##!
##! Provides compilers, build systems, language tooling, diagnostics, common
##! development headers, interactive shells, and administrative utilities as
##! an opt-in system profile. Library discovery uses compiler and pkg-config
##! search paths; runtime linking continues to use each package's embedded
##! RPATH rather than a global `LD_LIBRARY_PATH`.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.profiles.development;

  tools = [
    pkgs.autoconf
    pkgs.autoconf-archive
    pkgs.autogen
    pkgs.automake
    pkgs.bash
    pkgs.bash-completion
    pkgs.bat
    pkgs.bottom
    pkgs.cloc
    pkgs.cmake
    pkgs.delve
    pkgs.direnv
    pkgs.dnsutils
    pkgs.docker
    pkgs.efibootmgr
    pkgs.fish
    pkgs.gcc
    pkgs.gdb
    pkgs.git
    pkgs.git-lfs
    pkgs.gnumake
    pkgs.go
    pkgs.gopls
    pkgs.htop
    pkgs.inetutils
    pkgs.iperf3
    pkgs.jq
    pkgs.kbd
    pkgs.libvirt
    pkgs.lm-sensors
    pkgs.meson
    pkgs.moreutils
    pkgs.ninja
    pkgs.nmap
    pkgs.nodejs
    pkgs.parallel
    pkgs.pciutils
    pkgs.pkg-config
    pkgs.pnpm
    pkgs.pv
    pkgs.python3
    pkgs.ripgrep
    pkgs.sccache
    pkgs.strace
    pkgs.tcpdump
    pkgs.tmux
    pkgs.uv
    pkgs.valgrind
    pkgs.vim
    pkgs.wget
    pkgs.zsh
  ];

  developmentLibraries = [
    pkgs.brotli
    pkgs.bzip2
    pkgs.cairo
    pkgs.curl
    pkgs.glib.dev
    pkgs.libffi
    pkgs.libgit2
    pkgs.libidn2
    pkgs.libpcap
    pkgs.libpng
    pkgs.libpsl
    pkgs.libunistring
    pkgs.libuv
    pkgs.libxml2
    pkgs.libxslt
    pkgs.libyaml
    pkgs.llvm
    pkgs.lz4
    pkgs.ncurses
    pkgs.nghttp2
    pkgs.nghttp3
    pkgs.ngtcp2
    pkgs.openssl
    pkgs.pcre2
    pkgs.protobuf
    pkgs.protobuf-c
    pkgs.readline
    pkgs.sqlite
    pkgs.xz
    pkgs.zlib
    pkgs.zstd
  ];

  allLibraries = developmentLibraries ++ cfg.extraLibraries;
  includePath = lib.concatStringsSep ":" (map (package: "${package}/include") allLibraries);
  libraryPath = lib.concatStringsSep ":" (map (package: "${package}/lib") allLibraries);
  pkgConfigPath = lib.concatStringsSep ":" (
    lib.concatMap
    (package: ["${package}/lib/pkgconfig" "${package}/share/pkgconfig"])
    allLibraries
  );
in {
  options.aos.profiles.development = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Install the general software development toolset.";
    };

    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = "Additional tools installed with the development profile.";
    };

    extraLibraries = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = "Additional libraries added to compiler and pkg-config search paths.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = tools ++ allLibraries ++ cfg.extraPackages;

    environment.etc."shells".text = ''
      ${pkgs.bash}/bin/bash
      ${pkgs.fish}/bin/fish
      ${pkgs.zsh}/bin/zsh
    '';

    environment.sessionVariables = {
      C_INCLUDE_PATH = lib.mkDefault includePath;
      LIBRARY_PATH = lib.mkDefault libraryPath;
      PKG_CONFIG_PATH = lib.mkDefault pkgConfigPath;
    };

    aos.security.sudo.enable = lib.mkDefault true;
    aos.security.utempter.enable = lib.mkDefault true;
    aos.security.wrappers = {
      ping = {
        source = "${pkgs.inetutils}/bin/ping";
        mode = "4755";
      };
      ping6 = {
        source = "${pkgs.inetutils}/bin/ping6";
        mode = "4755";
      };
    };

    system.checks.development = {
      description = "Development toolchain and library discovery checks";
      checks = [
        {
          name = "development-tools";
          description = "Representative compiler, build, language, and diagnostic tools run";
          script = ''
            vm.succeed("gcc --version")
            vm.succeed("clang --version")
            vm.succeed("gdb --version")
            vm.succeed("cmake --version")
            vm.succeed("meson --version")
            vm.succeed("ninja --version")
            vm.succeed("go version")
            vm.succeed("python3 --version")
            vm.succeed("pnpm --version")
            vm.succeed("uv --version")
          '';
        }
        {
          name = "development-libraries";
          description = "Compiler and pkg-config paths resolve common libraries";
          script = ''
            session_env = (
                "export C_INCLUDE_PATH='${includePath}' "
                "LIBRARY_PATH='${libraryPath}' "
                "PKG_CONFIG_PATH='${pkgConfigPath}'; "
            )
            vm.succeed(
                "grep -F 'PKG_CONFIG_PATH   DEFAULT=\"${pkgConfigPath}\"' "
                "/etc/pam/environment"
            )
            vm.succeed(
                session_env + "pkg-config --exists libcurl libxml-2.0 libpng zlib"
            )
            vm.succeed(
                session_env
                + "printf '#include <zlib.h>\\nint main(void) { return zlibVersion()[0] == 0; }\\n' "
                "| gcc -x c - -lz -o /tmp/aos-development-link "
                "&& /tmp/aos-development-link"
            )
            vm.fail(session_env + "test -n \"$LD_LIBRARY_PATH\"")
          '';
        }
        {
          name = "development-shells";
          description = "Interactive shells and privilege wrappers are registered";
          script = ''
            vm.succeed("grep -Fx ${pkgs.bash}/bin/bash /etc/shells")
            vm.succeed("grep -Fx ${pkgs.fish}/bin/fish /etc/shells")
            vm.succeed("grep -Fx ${pkgs.zsh}/bin/zsh /etc/shells")
            vm.succeed("test -u /run/wrappers/bin/sudo")
            vm.succeed("test -u /run/wrappers/bin/ping")
          '';
        }
      ];
    };
  };
}
