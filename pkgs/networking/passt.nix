##! passt — Userspace networking for virtual machines and namespaces
{
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
}: let
  version = "2026_07_28.f8df3f1";
in
  mkDerivation {
    pname = "passt";
    inherit version;
    src = fetchurl {
      urls = ["https://passt.top/passt/snapshot/passt-${version}.tar.gz"];
      hash = "sha256-Kz7/s9zR9rG0baOiQZwDdQjSS8OfkFE7u7Zg6OtlIOU=";
    };
    buildDeps = [gnumake buildPackages.glibc.bin];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd passt-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" seccomp.sh doc/demo.sh
          sed -i \
            's|PAGE_SIZE=$(shell getconf PAGE_SIZE)|PAGE_SIZE=$(shell ${buildPackages.glibc.bin}/bin/getconf PAGE_SIZE)|' \
            Makefile
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" VERSION=${version}'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out" VERSION=${version}
          "$out/bin/passt" --version 2>&1 | grep -q '${version}'
          test -x "$out/bin/pasta"
          test -x "$out/bin/passt-repair"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-passt";
        tool = self;
        command = "passt --version 2>&1 | grep -q '${version}' && pasta --version 2>&1 | grep -q '${version}'";
      };
    };
    meta = {
      description = "Provides unprivileged socket transport for virtual machines and network namespaces";
      homepage = "https://passt.top/passt/about/";
      license = "GPL-2.0-or-later AND BSD-3-Clause";
      mainProgram = "passt";
    };
  }
