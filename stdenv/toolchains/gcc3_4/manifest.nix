# stdenv/toolchains/gcc3_4/manifest.nix - GCC 3.4 tier POSIX tool manifest
{
  buildPlatform,
  hostPlatform,
  gcc,
  binutils,
  glibc,
}: let
  tripletBuildHostTarget = [
    "--build=${buildPlatform.config}"
    "--host=${hostPlatform.config}"
    "--target=${hostPlatform.config}"
  ];

  tripletNoNls = tripletBuildHostTarget ++ ["--disable-nls"];

  gnuMeta = description: homepage: license: {
    inherit description homepage license;
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };

  thisCompiler = {
    inherit gcc binutils glibc;
  };

  rawTool = attrs:
    {
      compiler = thisCompiler;
      gccVersion = "3.4.6";
      staticNssWrapper = true;
      cflags = "-O2 -I${glibc}/include";
      cppflags = "";
      ldflags = "-L${glibc}/lib -static";
      configureEnv = ''
        export PATH="${gcc}/bin:${binutils}/bin:$PATH"
        unset CXX CXXFLAGS
        unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
        unset PKG_CONFIG_PATH
      '';
    }
    // attrs;
in {
  tar = rawTool {
    pname = "tar";
    version = "1.14";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.14.tar.gz";
    hash = "1mz6wp9isz9qbc255x0xd6s5g4flpqyj2wdkdsffm0qhiq92yh1r";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility, version 1.14" "https://www.gnu.org/software/tar/" "GPL-2.0-or-later";
  };

  gzip = rawTool {
    pname = "gzip";
    version = "1.3.5";
    url = "https://alpha.gnu.org/gnu/gzip/gzip-1.3.5.tar.gz";
    hash = "1pkqayhb6rs3aj858wxyga4q3nha8x9y7bn5lbqad4985y5a0hm7";
    meta = gnuMeta "GNU gzip compression utility, version 1.3.5" "https://www.gnu.org/software/gzip/" "GPL-2.0-or-later";
  };

  bash = rawTool {
    pname = "bash";
    version = "3.0";
    url = "https://mirrors.kernel.org/gnu/bash/bash-3.0.tar.gz";
    hash = "1i4brapyyivim7mrrrd9iii4a5yilb2wzh9k6zgcwxh0ycpxrbw7";
    configureFlags =
      tripletNoNls
      ++ [
        "--without-bash-malloc"
      ];
    buildScript = ''
      make
    '';
    postInstall = ''
      test -f "$out/bin/bash" && test ! -f "$out/bin/sh" && ln -sf bash "$out/bin/sh"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 3.0" "https://www.gnu.org/software/bash/" "GPL-2.0-or-later";
  };

  coreutils = rawTool {
    pname = "coreutils";
    version = "5.2.1";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-5.2.1.tar.bz2";
    hash = "1m4gaqhwhpaba4n2qwsdy4spdrqx6aszrl4r8z7av4jdlyq3qckl";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 5.2.1" "https://www.gnu.org/software/coreutils/" "GPL-2.0-or-later";
  };

  gnumake = rawTool {
    pname = "gnumake";
    version = "3.80";
    url = "https://mirrors.kernel.org/gnu/make/make-3.80.tar.bz2";
    hash = "050qpdwd85y7f9lhkj0i19av2nybn248m26zkl2as47wp2y1daki";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 3.80" "https://www.gnu.org/software/make/" "GPL-2.0-or-later";
  };

  sed = rawTool {
    pname = "sed";
    version = "4.1.2";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.1.2.tar.gz";
    hash = "11rkzxnqjz226ifblx3y003y06kaqnw45ph6jxq2d3dpyliavq2h";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU stream editor, version 4.1.2" "https://www.gnu.org/software/sed/" "GPL-2.0-or-later";
  };

  grep = rawTool {
    pname = "grep";
    version = "2.5.1";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.5.1.tar.bz2";
    hash = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
    configureFlags =
      tripletNoNls
      ++ [
        "--disable-perl-regexp"
      ];
    meta = gnuMeta "GNU grep pattern matching utility, version 2.5.1" "https://www.gnu.org/software/grep/" "GPL-2.0-or-later";
  };

  gawk = rawTool {
    pname = "gawk";
    version = "3.1.3";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.3.tar.bz2";
    hash = "1yhi1nzpwl206jxfm3jxyk377bmyj9lkhiyiwphfmcrg1fyzzrlz";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/gawk" && test ! -f "$out/bin/awk" && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 3.1.3" "https://www.gnu.org/software/gawk/" "GPL-2.0-or-later";
  };

  findutils = rawTool {
    pname = "findutils";
    version = "4.1.20";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.1.20.tar.gz";
    hash = "1msh5bxc96jmry8gn1zm36ic87fjn8r7ffagzaq70vxavr00l5w8";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.1.20" "https://www.gnu.org/software/findutils/" "GPL-2.0-or-later";
  };

  diffutils = rawTool {
    pname = "diffutils";
    version = "2.8.1";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-2.8.1.tar.gz";
    hash = "198ja157yardrjq27pr5whbv73mn6hld0s9dfv1lkwdisd7y0k37";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 2.8.1" "https://www.gnu.org/software/diffutils/" "GPL-2.0-or-later";
  };

  patch = rawTool {
    pname = "patch";
    version = "2.5.4";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.4.tar.gz";
    hash = "0wrlwv5qz02ln3m90yxmwrnv7mgdp2yidarrih1ah9ig5lcdjhmg";
    meta = gnuMeta "GNU patch file patching utility, version 2.5.4" "https://www.gnu.org/software/patch/" "GPL-2.0-or-later";
  };
}
