##! packaging — Core Python package-version and metadata utilities
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "26.3";
in
  mkDerivation {
    pname = "packaging";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/p/packaging/packaging-${version}.tar.gz"
      ];
      hash = "sha256-lO3CVkJK84di6zEwbu0ovrnw78UKiDdJLJ1v1gBK7Xk=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd packaging-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python3.14/site-packages
          mkdir -p "$site"
          cp -r src/packaging "$site/"

          metadata="$site/packaging-${version}.dist-info"
          mkdir -p "$metadata"
          cat > "$metadata/METADATA" <<'EOF'
          Metadata-Version: 2.4
          Name: packaging
          Version: ${version}
          Requires-Python: >=3.9
          EOF
          touch "$metadata/INSTALLER"
          cp LICENSE LICENSE.APACHE LICENSE.BSD "$metadata/"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages \
            python3 -c 'import packaging; assert packaging.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "Core utilities for Python package versions and metadata";
      homepage = "https://packaging.pypa.io/";
      license = "Apache-2.0 OR BSD-2-Clause";
    };
  }
