##! SETools — SELinux policy analysis tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  python3,
  setuptools,
  cython,
  libsepol,
  libselinux,
}: let
  version = "4.6.0";
in
  mkDerivation {
    pname = "setools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/setools/releases/download/${version}/setools-${version}.tar.bz2"
      ];
      hash = "sha256-lzGaq6+dQjeEHuYNzJsvKR5zp2HzF/0T4pPqI2fVgGw=";
    };

    buildDeps = [
      gnumake
      pkg-config
      python3
      setuptools
      cython
    ];
    runtimeDeps = [
      python3
      setuptools
      libsepol
      libselinux
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          if [ -d setools-${version} ]; then
            cd setools-${version}
          elif [ -d setools ]; then
            cd setools
          else
            cd "$(ls -d */ | head -1)"
          fi
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHONPATH=$(echo ${setuptools}/lib/python3.*/site-packages):$(echo ${cython}/lib/python3.*/site-packages)
          export SEPOL="${libsepol}/lib/libsepol.a"
          export CFLAGS="-I${libsepol}/include -I${libselinux}/include"
          export LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -Wl,-rpath,${libsepol}/lib -Wl,-rpath,${libselinux}/lib"
          ${python3}/bin/python3 setup.py build_ext -i
        '';
      }
      {
        name = "install";
        script = ''
          # Manual install — setup.py install fails on Python 3.12 because
          # its egg byte-compilation subprocess can't find distutils (removed
          # in 3.12). nixpkgs uses pyproject mode; we do a direct copy instead.
          SITE=$out/lib/python3/site-packages
          mkdir -p $SITE $out/bin $out/share/man/man1

          # Python packages (setools has the .so built in-place)
          cp -r setools $SITE/
          cp -r setoolsgui $SITE/

          # CLI scripts
          for script in apol sediff seinfo seinfoflow sesearch sedta sechecker; do
            if [ -f "$script" ]; then
              install -m 755 "$script" $out/bin/
              sed -i "1s|.*|#!${python3}/bin/python3|" $out/bin/$script
            fi
          done

          # Man pages
          for f in man/*.1; do
            install -m 644 "$f" $out/share/man/man1/ 2>/dev/null || true
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      tools = testing.mkVMTest {
        name = "cross-cutting-selinux-tools";
        rootfsDeps = [
          self
          pkgs.libselinux
          pkgs.libsepol
        ];
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.libselinux}/lib:${pkgs.libsepol}/lib:$LD_LIBRARY_PATH"
          # setools needs python
          export PYTHONPATH="${self}/lib/python3/site-packages:$PYTHONPATH"

          echo "==> Testing seinfo --version"
          seinfo --version
          echo "SELinux tools: PASS"
        '';
      };
    };

    meta = {
      description = "SETools — policy analysis tools for SELinux";
      homepage = "https://github.com/SELinuxProject/setools";
      license = "GPL-2.0-or-later";
    };
  }
