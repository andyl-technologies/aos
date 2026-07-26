##! libyaml — YAML 1.1 parser and emitter library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.2.5";
in
  mkDerivation {
    pname = "libyaml";
    inherit version;

    src = fetchurl {
      urls = ["https://pyyaml.org/download/libyaml/yaml-${version}.tar.gz"];
      hash = "sha256-xkKum3X+4SCy2WxxJTi9LPKDIo0jN98s8piOPAJnjvQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd yaml-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
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
      description = "YAML 1.1 parser and emitter library";
      homepage = "https://pyyaml.org/wiki/LibYAML";
      license = "MIT";
    };
  }
