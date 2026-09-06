##! valgrind — Dynamic analysis and profiling tools
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  perl,
  gdb,
}: let
  version = "3.26.0";
in
  mkDerivation {
    pname = "valgrind";
    inherit version;

    src = fetchurl {
      urls = ["https://sourceware.org/pub/valgrind/valgrind-${version}.tar.bz2"];
      hash = "sha256-jVTHFwKRBvFkSq2vgCq5aS5T2T3QFcvRnnQZDrpha9c=";
    };

    buildDeps = [autoconf automake libtool gnumake perl];
    runtimeDeps = [perl gdb];
    propagatedDeps = [];
    hardeningDisable = ["stackprotector"];

    configureFlags = "--enable-only64bit --with-mpicc=no";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-valgrind";
        tool = self;
        command = "valgrind --version";
      };
    };

    meta = {
      description = "Dynamic analysis and profiling tool suite";
      homepage = "https://valgrind.org/";
      license = "GPL-2.0-or-later";
      mainProgram = "valgrind";
    };
  }
