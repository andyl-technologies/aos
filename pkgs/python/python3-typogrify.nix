##! typogrify Python module built from its source distribution.
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  python3-smartypants,
}:
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
    target = [];
    role = "public-package";
  };
  pname = "python3-typogrify";
  version = "2.1.0";
  src = fetchurl {
    urls = ["https://files.pythonhosted.org/packages/93/8c/b73fe0050bbf67c172b7c6d0c74c356939de0e891e669667f20381c099a8/typogrify-2.1.0.tar.gz"];
    hash = "f0aa004e98032a6e6be4c9da65e7eb7150e36ca3bf508adbcda82b4d003e61ee";
  };
  buildDeps = [buildPackages.python3];
  runtimeDeps = [python3 python3-smartypants];
  propagatedDeps = [python3 python3-smartypants];
  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd typogrify-2.1.0
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/lib/python3.14/site-packages" "$out/share/licenses/python3-typogrify"
        cp -R typogrify "$out/lib/python3.14/site-packages/"
        cp LICENSE.txt "$out/share/licenses/python3-typogrify/"

      '';
    }
  ];
  meta = {
    description = "typogrify Python module";
    homepage = "https://pypi.org/project/typogrify/";
    license = "BSD-3-Clause";
  };
}
