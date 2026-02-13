# meson — Build system designed for speed
{
  mkDerivation,
  fetchurl,
  python3,
}:

let
  version = "1.6.1";
in
mkDerivation {
  pname = "meson";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/mesonbuild/meson/releases/download/${version}/meson-${version}.tar.gz"
    ];
    hash = "sha256-HspJ62wm1Yu+5n/TM32O9VfAgE4wptFr/fJp25l0ZN4=";
  };

  buildDeps = [ python3 ];
  runtimeDeps = [ python3 ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd meson-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        # No configure step — meson is a pure Python package
        true
      '';
    }
    {
      name = "build";
      script = ''
        # No build step — meson is installed by copying Python modules
        true
      '';
    }
    {
      name = "install";
      script = ''
                mkdir -p $out/bin $out/lib/python3/site-packages

                # Install the mesonbuild Python package and entry point
                cp -r mesonbuild $out/lib/python3/site-packages/
                cp meson.py $out/lib/python3/site-packages/

                # Create wrapper script that invokes meson via python3
                cat > $out/bin/meson << EOF
        #!/bin/sh
        PYTHONPATH=$out/lib/python3/site-packages exec ${python3}/bin/python3 -m mesonbuild.mesonmain "\$@"
        EOF
                chmod +x $out/bin/meson
      '';
    }
  ];

  meta = {
    description = "Build system designed for speed";
    homepage = "https://mesonbuild.com/";
    license = "Apache-2.0";
  };
}
