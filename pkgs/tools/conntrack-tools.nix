##! conntrack-tools — Connection tracking userspace tools for netfilter
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnetfilter_cthelper,
  libnetfilter_cttimeout,
  libnetfilter_queue,
  libtirpc,
}: let
  version = "1.4.9";
in
  mkDerivation {
    pname = "conntrack-tools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-${version}.tar.xz"
      ];
      hash = "sha256-wVr+SIqNQIydbWHpfb0Z88WRlC9iwT32RTqWHKQjHK4=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
      libnetfilter_conntrack
      libnetfilter_cthelper
      libnetfilter_cttimeout
      libnetfilter_queue
      libtirpc
    ];
    propagatedDeps = [];

    abilities = ./_conntrackd/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd conntrack-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "conntrack-tools — connection tracking userspace tools for netfilter";
      homepage = "https://www.netfilter.org/projects/conntrack-tools/";
      license = "GPL-2.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: let
      evaluate = conntrackdConfig:
        lib.evalModules {
          inherit lib;
          modules = [
            ../../modules/abilities/default.nix
            {
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
                contributable = true;
              };
              aos.abilities.environment = {
                authority = "deployment";
                key = "conntrackd-test";
                stage = "host";
              };
              conntrackd = conntrackdConfig;
            }
          ];
          packageModules = [
            {
              name = "conntrack-tools";
              module.imports = [./_conntrackd/module.nix];
            }
          ];
        };
      evaluated = evaluate {
        enable = true;
        mode = "sync";
        sync = {
          interface = "eth1";
          localAddress = "192.0.2.10";
          peerAddress = "192.0.2.11";
        };
      };
      invalidHashRange = evaluate {
        hashSize = 8192;
        hashLimit = 4096;
      };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      requests = evaluated.config.aos.abilities.requests;
      source = requests."conntrack-tools:daemon-configuration".parameters.source;
      lifecycle = requests."conntrack-tools:main-lifecycle".parameters;
      identity = requests."conntrack-tools:main-identity".parameters;
      literalText = builtins.concatStringsSep "" (builtins.map
        (fragment:
          if fragment.kind == "literal"
          then fragment.text
          else "")
        source.fragments);
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidHashRange
        && source.kind == "interpolated-text"
        && lib.hasInfix "Mode FTFW" literalText
        && lib.hasInfix "IPv4_address 192.0.2.10" literalText
        && lib.hasInfix "IPv4_Destination_Address 192.0.2.11" literalText
        && builtins.elem "conntrack-tools:main-lifecycle" (builtins.attrNames requests)
        && builtins.elem "conntrack-tools:main-reload" (builtins.attrNames requests)
        && builtins.elem "conntrack-tools:runtime-storage" (builtins.attrNames requests)
        && requests."conntrack-tools:log-storage".requirement
        == "conntrack-tools:persistent-storage-allocation"
        && lifecycle.configuration_change_action == "restart"
        && identity.file_creation_mask == "0027"
        && !(self ? configModule)
        && !(self ? expose);
    in {
      config =
        if contractHolds
        then
          pkgs.runCommand "conntrackd-ability-module" {} ''
            test -x ${self}/sbin/conntrackd
            touch "$out"
          ''
        else throw "the conntrackd ability module contract checks failed";
    };
  }
