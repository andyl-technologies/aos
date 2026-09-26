##! SETools — SELinux policy analysis tools
{
  lib,
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
  version = "4.7.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "setools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the inclusive numeric range from 16 through 18.";
        "files" = {};
        "input" = "The extended-permission range 0x10-0x12.";
        "operation" = "Parse the range through SETools' public extended-permission utility API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import glob, sys\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nassert len(locations) == 1\nsys.path.insert(0, locations[0])\nimport setools\nassert setools.xperm_str_to_tuple_ranges(\"0x10-0x12\") == [(16, 18)]\nprint(\"setools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "setools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "SETools rejects the malformed policy image with its policy-loading exception.";
        "files" = {
          "invalid.policy" = "bad";
        };
        "input" = "A three-byte file presented as a compiled SELinux policy.";
        "operation" = "Open the malformed policy through SETools' public SELinuxPolicy API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport glob, sys\nsys.path.insert(0, glob.glob(\"@out@/lib/python*/site-packages\")[0])\nimport setools\ntry:\n    setools.SELinuxPolicy(\"invalid.policy\")\nexcept Exception:\n    pass\nelse:\n    raise RuntimeError(\"SETools accepted a malformed policy\")\n\nsys.stderr.write(\"setools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "setools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/setools/releases/download/${version}/setools-${version}.tar.bz2"
      ];
      hash = "sha256-m0FOrn8XqmylMkjRHXT60BWCohmFx4pIP6EkDnC9O2o=";
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
