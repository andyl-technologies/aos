##! dnsmasq — Lightweight DNS, DHCP, and TFTP server
{
  lib,
  mkDerivation,
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
}: let
  version = "2.93";
in
  mkDerivation {
    pname = "dnsmasq";
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

    abilities = ./_dnsmasq/module.nix;

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
      evaluated = lib.evalModules {
        inherit lib;
        modules = [
          lib.abilities.module
          {
            options.assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
              contributable = true;
            };
            aos.abilities.environment = {
              authority = "deployment";
              key = "dnsmasq-test";
              stage = "host";
            };
            aos.services.dnsmasq = {
              enable = true;
              port = 5353;
              dhcpRanges = ["192.0.2.10,192.0.2.20,12h"];
            };
          }
        ];
        packageModules = [
          {
            name = "dnsmasq";
            module.imports = [./_dnsmasq/module.nix];
          }
        ];
      };
      requests = evaluated.config.aos.abilities.requests;
      configuration = requests."dnsmasq:server-configuration".parameters.source;
      dependencies = requests."dnsmasq:dnsmasq-dependencies".parameters;
      ingress = requests."dnsmasq:network-ingress".parameters;
      qualifiedResultOf = request: output: {
        _type = "aos-request-output-reference";
        inherit request output;
      };
      contractHolds =
        self.abilities ? interfaces
        && self.abilities ? implementations
        && self.abilities ? requirementTemplates
        && self.abilities ? guarantees
        && !(self.abilities ? contract)
        && builtins.hasAttr "network-ingress-policy" self.abilities.requirementTemplates
        && builtins.all (assertion: assertion.assertion) evaluated.config.assertions
        && configuration.kind == "interpolated-text"
        && !(lib.hasInfix "/run/" (builtins.toJSON configuration))
        && ingress.endpoints
        == [
          {
            transport = "tcp";
            port = 5353;
          }
          {
            transport = "udp";
            port = 5353;
          }
          {
            transport = "udp";
            port = 67;
          }
        ]
        && dependencies.prerequisites
        == [(qualifiedResultOf "dnsmasq:network-ingress" "readiness-resource")]
        && dependencies.after == []
        && dependencies.requires == [];
    in {
      tool = testing.mkToolCheck {
        pname = "tool-dnsmasq";
        tool = self;
        command = "dnsmasq --version | grep ' IDN ' | grep ' Lua ' | grep ' DNSSEC ' | grep ' nftset '";
      };
      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "dnsmasq-ability-module-contract" {} ''
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
