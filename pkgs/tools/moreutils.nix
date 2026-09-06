##! moreutils — Additional Unix command-line tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  libxml2,
  libxslt,
  docbook-xsl,
  docbook-xml,
  perl-ipc-run,
  perl-timedate,
  perl-time-duration,
}: let
  version = "0.70";
  modules = [perl-ipc-run perl-timedate perl-time-duration];
  modulePath = builtins.concatStringsSep " " (map (module: "${module}/lib/perl5") modules);
in
  mkDerivation {
    pname = "moreutils";
    inherit version;
    src = fetchurl {
      urls = ["https://deb.debian.org/debian/pool/main/m/moreutils/moreutils_${version}.orig.tar.xz"];
      hash = "sha256-qETF4zYKc9EsClYkdQ7MGWnWSv6i6EklMo8TdXbi61U=";
    };
    buildDeps = [gnumake perl libxml2 libxslt docbook-xsl docbook-xml];
    runtimeDeps = [perl] ++ modules;
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd moreutils-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" is_utf8/test.sh

          for document in *.docbook; do
            sed -i \
              's|http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd|${docbook-xml}/share/xml/docbook/schema/dtd/4.5/docbookx.dtd|' \
              "$document"
          done

          for script in chronic combine ts vidir vipe zrun; do
            sed -i \
              -e "1s|^#!.*|#!${perl}/bin/perl|" \
              -e "2i use lib qw(${modulePath});" \
              "$script"
          done
        '';
      }
      {
        name = "build";
        script = ''
          export XML_CATALOG_FILES="${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          make -j"$NIX_BUILD_CORES" \
            CC="$CC" \
            DOCBOOKXSL=${docbook-xsl}/share/xml/docbook/stylesheet/docbook-xsl
        '';
      }
      {
        name = "check";
        script = ''make check'';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            INSTALL_BIN="install -m 0755"
          printf 'input\n' | "$out/bin/sponge" /tmp/moreutils-sponge
          grep -qx input /tmp/moreutils-sponge
          printf 'test\n' | "$out/bin/ts" -s | grep -q test
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-moreutils";
        tool = self;
        command = "printf 'input\\n' | sponge /tmp/sponge-output && grep -qx input /tmp/sponge-output";
      };
    };
    meta = {
      description = "Provides useful Unix tools including sponge, chronic, vidir, and vipe";
      homepage = "https://joeyh.name/code/moreutils/";
      license = "GPL-2.0-or-later AND BSD-2-Clause";
    };
  }
