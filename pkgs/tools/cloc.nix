##! cloc — Source code line counter
{
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
  perl-algorithm-diff,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-moo,
  perl-parallel-forkmanager,
  perl-regexp-common,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.10";
  modules = [
    perl-algorithm-diff
    perl-class-method-modifiers
    perl-module-runtime
    perl-moo
    perl-parallel-forkmanager
    perl-regexp-common
    perl-role-tiny
    perl-sub-quote
  ];
  modulePath = builtins.concatStringsSep " " (map (module: "${module}/lib/perl5") modules);
  # The installed script targets Perl on the host platform; build checks run
  # with native Perl so a Linux builder can validate Darwin output.
  buildPerl = buildPackages.perl;
in
  mkDerivation {
    pname = "cloc";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/AlDanial/cloc/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-qPrDX0z0Jyh2VYC6Ea/CVorSBVCaIiBGY/UmFpVIQ20=";
    };
    buildDeps = [buildPerl];
    runtimeDeps = [perl] ++ modules;
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cloc-${version}/Unix
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/man/man1"
          sed -i \
            -e "1s|^#!.*|#!${perl}/bin/perl|" \
            -e "2i use lib qw(${modulePath});" \
            cloc
          install -m 0755 cloc "$out/bin/cloc"
          ${buildPerl}/bin/pod2man --section=1 --release='cloc ${version}' cloc.1.pod cloc.1
          install -m 0644 cloc.1 "$out/share/man/man1/cloc.1"

          ${buildPerl}/bin/perl "$out/bin/cloc" --version | grep -qx '${version}'
          printf 'fn main() {}\n' > example.rs
          ${buildPerl}/bin/perl "$out/bin/cloc" --quiet --csv example.rs | grep -q ',Rust,'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-cloc";
        tool = self;
        command = "cloc --version | grep -qx '${version}'";
      };
    };
    meta = {
      description = "Counts blank lines, comment lines, and physical source lines";
      homepage = "https://github.com/AlDanial/cloc";
      license = "GPL-2.0-or-later";
      mainProgram = "cloc";
    };
  }
