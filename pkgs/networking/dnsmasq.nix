##! dnsmasq — Lightweight DNS, DHCP, and TFTP server
{
  lib,
  mkDerivation,
  aos-runtime-checks,
  fetchurl,
  gnumake,
  gettext,
  pkg-config,
  libidn2,
  lua,
  nettle,
  gmp,
  dbus,
  systemd,
  libnetfilter_conntrack,
  libnfnetlink,
  nftables,
  service-management,
  aos-filesystem-provider,
}: let
  version = "2.93";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "dnsmasq";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Dnsmasq accepts the configuration without starting a daemon.";
        "files" = {
          "dnsmasq.conf" = "port=0\nno-dhcp-interface=*\nlog-facility=-\n";
        };
        "input" = "A self-contained dnsmasq configuration with DNS and DHCP disabled.";
        "operation" = "Parse and validate the configuration with dnsmasq's test mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/dnsmasq"
              "--test"
              "--conf-file=dnsmasq.conf"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Dnsmasq rejects the unknown directive with status 1.";
        "files" = {
          "invalid.conf" = "aos-not-a-dnsmasq-option=42\n";
        };
        "input" = "A dnsmasq configuration containing an unknown directive.";
        "operation" = "Parse the malformed configuration in test mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/dnsmasq"
              "--test"
              "--conf-file=invalid.conf"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://www.thekelleys.org.uk/dnsmasq/dnsmasq-${version}.tar.xz"];
      hash = "sha256-DADU5cl8gwbl+5MrNIs0JpycKaDn3w6OgpWLQHCSvBk=";
    };

    buildDeps = [gnumake gettext pkg-config];
    runtimeDeps = [
      libidn2
      lua
      nettle
      gmp
      dbus
      systemd
      libnetfilter_conntrack
      libnfnetlink
      nftables
    ];
    propagatedDeps = [];

    module = ./_dnsmasq;
    moduleDeps = [aos-runtime-checks service-management aos-filesystem-provider nftables];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dnsmasq-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" all-i18n \
            COPTS="-DHAVE_LIBIDN2 -DHAVE_LUASCRIPT -DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_CONNTRACK -DHAVE_NFTSET" \
            LOCALEDIR="$out/share/locale" \
            LUA=lua \
            PKG_CONFIG=pkg-config
        '';
      }
      {
        name = "install";
        script = ''
          make install-i18n \
            COPTS="-DHAVE_LIBIDN2 -DHAVE_LUASCRIPT -DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_CONNTRACK -DHAVE_NFTSET" \
            DESTDIR= \
            BINDIR="$out/bin" \
            MANDIR="$out/share/man" \
            LOCALEDIR="$out/share/locale" \
            LUA=lua \
            PKG_CONFIG=pkg-config

          install -Dm644 trust-anchors.conf "$out/share/dnsmasq/trust-anchors.conf"
          install -Dm644 dbus/dnsmasq.conf "$out/share/dbus-1/system.d/dnsmasq.conf"
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      nativeTests = import ./_dnsmasq/native-tests.nix {inherit lib self pkgs;};
      contractHolds = builtins.all (value: value) (builtins.attrValues nativeTests);
    in {
      tool = testing.mkToolCheck {
        pname = "tool-dnsmasq";
        tool = self;
        command = ''
          dnsmasq --version > /tmp/dnsmasq-version &&
          grep -F ' IDN2 ' /tmp/dnsmasq-version &&
          grep -F ' Lua ' /tmp/dnsmasq-version &&
          grep -F ' DNSSEC ' /tmp/dnsmasq-version &&
          grep -F ' nftset ' /tmp/dnsmasq-version
        '';
      };
      native-module-contract =
        if contractHolds
        then
          pkgs.runCommand "dnsmasq-native-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the dnsmasq native ability contract check failed";
    };

    meta = {
      description = "Lightweight DNS, DHCP, router advertisement, and TFTP server";
      homepage = "https://thekelleys.org.uk/dnsmasq/doc.html";
      license = "GPL-2.0-only";
      mainProgram = "dnsmasq";
    };
  }
