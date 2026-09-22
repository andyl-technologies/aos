##! jinja2 Python module built from its source distribution.
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  python3-markupsafe,
}:
mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
  pname = "python3-jinja2";
  version = "3.1.6";
  src = fetchurl {
    urls = ["https://files.pythonhosted.org/packages/df/bf/f7da0350254c0ed7c72f3e33cef02e048281fec7ecec5f032d4aac52226b/jinja2-3.1.6.tar.gz"];
    hash = "0137fb05990d35f1275a587e9aee6d56da821fc83491a0fb838183be43f66d6d";
  };
  buildDeps = [buildPackages.python3];
  runtimeDeps = [python3 python3-markupsafe];
  propagatedDeps = [python3 python3-markupsafe];
  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd jinja2-3.1.6
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/lib/python3.14/site-packages" "$out/share/licenses/python3-jinja2"
        cp -R src/jinja2 "$out/lib/python3.14/site-packages/"
        cp LICENSE.txt "$out/share/licenses/python3-jinja2/"

      '';
    }
  ];
  meta = {
    description = "jinja2 Python module";
    homepage = "https://pypi.org/project/jinja2/";
    license = "BSD-3-Clause";
  };
}
