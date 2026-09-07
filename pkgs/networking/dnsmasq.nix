##! dnsmasq — Lightweight DNS, DHCP, and TFTP server
{
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
      libnetfilter_conntrack
      libnfnetlink
      nftables
    ];
    propagatedDeps = [];

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
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-dnsmasq";
        tool = self;
        command = "dnsmasq --version | grep ' IDN ' | grep ' Lua ' | grep ' DNSSEC ' | grep ' nftset '";
      };
    };

    meta = {
      description = "Lightweight DNS, DHCP, router advertisement, and TFTP server";
      homepage = "https://thekelleys.org.uk/dnsmasq/doc.html";
      license = "GPL-2.0-only";
      mainProgram = "dnsmasq";
    };
  }
