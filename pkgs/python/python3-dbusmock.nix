##! python3-dbusmock — Mock D-Bus objects for service test suites
{
  mkDerivation,
  fetchurl,
  python3,
  python3-dbus,
  dbus,
}: let
  version = "0.38.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-dbusmock";
    inherit version;

    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/source/p/python-dbusmock/python_dbusmock-${version}.tar.gz"];
      hash = "sha256-Ihtl4cLkjen9Eb9+jBZa2vkWSPSaEfOQ0IakmDhvKYQ=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3 python3-dbus dbus];
    propagatedDeps = [python3 python3-dbus dbus];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd python_dbusmock-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site="$out/${sitePackages}"
          mkdir -p "$site"
          cp -R dbusmock python_dbusmock.egg-info "$site/"

          PYTHONPATH="$site:${python3-dbus}/${sitePackages}" \
            ${python3}/bin/python3 -c \
              'import dbusmock; assert dbusmock.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "Mock D-Bus objects for service test suites";
      homepage = "https://github.com/martinpitt/python-dbusmock";
      license = "LGPL-3.0-or-later";
    };
  }
