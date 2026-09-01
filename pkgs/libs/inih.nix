##! inih — Simple .INI file parser library
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "58";
  sharedLibrary =
    if stdenv.hostPlatform.isDarwin
    then "libinih.0.dylib"
    else "libinih.so.0";
  sharedLink =
    if stdenv.hostPlatform.isDarwin
    then "libinih.dylib"
    else "libinih.so";
  sharedFlags =
    if stdenv.hostPlatform.isDarwin
    then "-dynamiclib -Wl,-install_name,$out/lib/${sharedLibrary}"
    else "-shared -Wl,-soname,${sharedLibrary}";
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
          $CC ${sharedFlags} -o ${sharedLibrary} ini.o
          $AR rcs libinih.a ini.o
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/include $out/lib $out/lib/pkgconfig

          cp ini.h $out/include/

          cp ${sharedLibrary} $out/lib/
          ln -s ${sharedLibrary} $out/lib/${sharedLink}
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
