##! inih — Simple .INI file parser library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "inih-58";
    family = "inih";
    stream = "58";
    owner = "pkgs/libs/inih.nix";
    version = "58";
    upstreamId = "r58";
    repository = "benhoyt/inih";
    provider = "github-releases";
    tagPrefix = "r";
    major = 58;
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "benhoyt"
        "inih"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "r";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-55IWJg1d/+gJvahAvkirDux3N7K7nwLSJ1wbRjROp7c=";
    };
  };
  inherit (upstream) version;
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

    src = upstream.components.main.sources.source;
    update = upstream.update;

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
