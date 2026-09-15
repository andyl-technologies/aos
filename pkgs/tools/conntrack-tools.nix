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
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Conntrack returns success and reports its userspace version.";
        "files" = {};
        "input" = "The packaged connection-tracking client's release identity.";
        "operation" = "Request its version without opening a netfilter socket.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([str(next(path for path in __import__(\"pathlib\").Path(\"@out@\").rglob(\"conntrack\") if path.is_file())), \"--version\"]\n, capture_output=True, text=True)\nassert result.returncode == 0 and \"conntrack\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"conntrack-tools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "conntrack-tools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Conntrack rejects the unsupported option.";
        "files" = {};
        "input" = "A conntrack invocation containing an unknown option.";
        "operation" = "Parse the invalid option without modifying kernel state.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([str(next(path for path in __import__(\"pathlib\").Path(\"@out@\").rglob(\"conntrack\") if path.is_file())), \"--aos-invalid-option\"]\n, capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"conntrack-tools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "conntrack-tools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
      mkSystem,
    }: let
      qualifiedResultOf = request: output: {
        _type = "aos-request-output-reference";
        inherit request output;
      };
      evaluate = conntrackdConfig:
        mkSystem {
          systemName = "conntrack-tools-package-check";
          modules = [
            {
              environment.systemPackages = [self];
              conntrackd = conntrackdConfig;
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
      disabled = evaluate {};
      invalidHashRange = evaluate {
        hashSize = 8192;
        hashLimit = 4096;
      };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      ownedValues = lib.filterAttrs (name: _: lib.hasPrefix "conntrack-tools:" name);
      requests = evaluated.config.aos.abilities.requests;
      disabledAbilities = disabled.config.aos.abilities;
      disabledRequirements = builtins.attrNames disabledAbilities.requirementTemplates;
      source = requests."conntrack-tools:daemon-configuration".parameters.source;
      lifecycle = requests."conntrack-tools:main-lifecycle".parameters;
      identity = requests."conntrack-tools:main-identity".parameters;
      storageMounts = requests."conntrack-tools:main-storage".parameters.mounts;
      literalText = builtins.concatStringsSep "" (builtins.map
        (fragment:
          if fragment.kind == "literal"
          then fragment.text
          else "")
        source.fragments);
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidHashRange
        && ownedValues disabledAbilities.instances == {}
        && ownedValues disabledAbilities.requests == {}
        && builtins.elem "conntrack-tools:configuration-materialization" disabledRequirements
        && builtins.elem "conntrack-tools:service-lifecycle" disabledRequirements
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
        && builtins.map (mount: mount.source) storageMounts
        == [
          (qualifiedResultOf "conntrack-tools:runtime-storage" "planned-path")
          (qualifiedResultOf "conntrack-tools:log-storage" "planned-path")
        ]
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
