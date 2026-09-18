##! secilc — SELinux Common Intermediate Language compiler
{
  mkDerivation,
  fetchurl,
  gnumake,
  libsepol,
  libxml2,
  libxslt,
  docbook-xml,
  docbook-xsl,
}: let
  version = "3.10";
in
  mkDerivation {
    pname = "secilc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-tHDgCV1FBpqAzs+Av5xRImQrycFU9BqnbTBQ6DfVmiA=";
    };

    buildDeps = [
      gnumake
      libxml2
      libxslt
      docbook-xml
      docbook-xsl
    ];
    runtimeDeps = [libsepol];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/secilc
        '';
      }
      {
        name = "build";
        script = ''
          make secilc secil2conf secil2tree \
            PREFIX=$out \
            CPPFLAGS="-I${libsepol}/include" \
            LDFLAGS="-L${libsepol}/lib" \
            -j$NIX_BUILD_CORES

          # Upstream's `xmlto man` path validates with xmllint, then invokes
          # the DocBook manpage stylesheet through xsltproc with network access
          # disabled and XInclude enabled. Do the same conversion directly so
          # secilc does not require xmlto's unrelated formatter ecosystems.
          cat > aos-docbook-catalog.xml <<EOF
          <?xml version="1.0"?>
          <catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
            <public publicId="-//OASIS//DTD DocBook XML V4.2//EN" uri="file://${docbook-xml}/share/xml/docbook/schema/dtd/4.5/docbookx.dtd"/>
            <system systemId="http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd" uri="file://${docbook-xml}/share/xml/docbook/schema/dtd/4.5/docbookx.dtd"/>
            <nextCatalog catalog="file://${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"/>
            <nextCatalog catalog="file://${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"/>
          </catalog>
          EOF
          export XML_CATALOG_FILES="$PWD/aos-docbook-catalog.xml"

          for manual_source in secilc.8.xml secil2conf.8.xml secil2tree.8.xml; do
            manual_output="''${manual_source%.xml}"
            ${libxml2}/bin/xmllint \
              --noout \
              --nonet \
              --xinclude \
              --postvalid \
              --noent \
              "$manual_source"
            ${libxslt}/bin/xsltproc \
              --nonet \
              --xinclude \
              --output "$manual_output" \
              ${docbook-xsl}/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl \
              "$manual_source"
            test -s "$manual_output"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share/man/man8
          install -m 0755 secilc secil2conf secil2tree $out/bin/
          install -m 0644 secilc.8 secil2conf.8 secil2tree.8 $out/share/man/man8/

          test -x $out/bin/secilc
          test -x $out/bin/secil2conf
          test -x $out/bin/secil2tree
          test -f $out/share/man/man8/secilc.8
          test -f $out/share/man/man8/secil2conf.8
          test -f $out/share/man/man8/secil2tree.8
        '';
      }
    ];

    meta = {
      description = "SELinux Common Intermediate Language compiler";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "GPL-2.0-or-later";
    };
  }
