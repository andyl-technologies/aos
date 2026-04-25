##! inih — Simple .INI file parser library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "58";
in
  mkDerivation {
    pname = "inih";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/benhoyt/inih/archive/refs/tags/r${version}.tar.gz"
      ];
      hash = "sha256-55IWJg1d/+gJvahAvkirDux3N7K7nwLSJ1wbRjROp7c=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd inih-r${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CC -c -fPIC -o ini.o ini.c
          $CC -shared -o libinih.so.0 ini.o -Wl,-soname,libinih.so.0
          $AR rcs libinih.a ini.o
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/include $out/lib $out/lib/pkgconfig

          cp ini.h $out/include/

          cp libinih.so.0 $out/lib/
          ln -s libinih.so.0 $out/lib/libinih.so
          cp libinih.a $out/lib/

          cat > $out/lib/pkgconfig/inih.pc << PCEOF
          prefix=$out
          libdir=$out/lib
          includedir=$out/include

          Name: inih
          Description: simple .INI file parser
          Version: ${version}
          Libs: -L$out/lib -linih
          Cflags: -I$out/include
          PCEOF
        '';
      }
    ];

    meta = {
      description = "Simple .INI file parser library";
      homepage = "https://github.com/benhoyt/inih";
      license = "BSD-3-Clause";
    };
  }
