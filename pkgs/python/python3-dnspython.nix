##! python3-dnspython — DNS toolkit for Python
{
  mkDerivation,
  fetchurl,
  buildPackages,
  python3,
}: let
  version = "2.8.0";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };

    pname = "python3-dnspython";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/rthalley/dnspython/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-iyHGS9eA1GGqlsXggtt4U3xnWBO1jvV1MFaQemAu8s4=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dnspython-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}"
          cp -R dns "$out/${sitePackages}/"

          PYTHONPATH="$out/${sitePackages}" ${buildPackages.python3}/bin/python3 -c \
            'import dns; assert dns.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "DNS toolkit for Python";
      homepage = "https://www.dnspython.org/";
      license = "ISC";
    };
  }
