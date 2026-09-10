##! Builds the static Perl needed to complete early libc utilities.
{
  buildTools,
  targetTools,
  buildPlatform,
  nssLibraries ? "-lnss_files -lnss_dns",
}: let
  version = "5.10.1";
  src = builtins.fetchTarball {
    url = "https://www.cpan.org/src/5.0/perl-${version}.tar.bz2";
    sha256 = "0wfch7jkcwmi5xmsrb7j18fn63hs7qvl958gzy6mfgxar6hj88dk";
  };
  shell = "${targetTools.bash}/bin/bash";
  path = builtins.concatStringsSep ":" (map (tool: "${tool}/bin") [
    targetTools.gcc
    targetTools.binutils
    targetTools.bash
    buildTools.coreutils
    buildTools.gnumake
    buildTools.sed
    buildTools.grep
    buildTools.gawk
    buildTools.findutils
    buildTools.tar
    buildTools.gzip
    buildTools.diffutils
    buildTools.patch
  ]);
in
  builtins.derivation {
    name = "perl-${version}";
    system = buildPlatform.system;
    builder = "${buildTools.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${path}"
        export CONFIG_SHELL="${shell}"
        export SHELL="$CONFIG_SHELL"

        cd "$TMPDIR"
        mkdir source
        (cd ${src} && tar cf - .) | (cd source && tar xf -)
        cd source
        chmod -R u+w .

        # Preserve pure-Perl compression modules in static builds and generate
        # Errno from the configured libc headers instead of host include paths.
        patch -p1 < ${./perl-5.10.1-bootstrap.patch}
        AOS_RUNTIME_SHELL="$CONFIG_SHELL" \
          "$CONFIG_SHELL" ${../../runtime-scripts.sh} .

        # Cwd clears PATH before invoking pwd under taint mode. Give its
        # trusted-command list an absolute target executable in the store.
        sed "s|'/bin/pwd'|'${targetTools.coreutils}/bin/pwd', '/bin/pwd'|" \
          lib/Cwd.pm > lib/Cwd.pm.tmp
        cat lib/Cwd.pm.tmp > lib/Cwd.pm
        rm lib/Cwd.pm.tmp

        # This bootstrap libc has no shared runtime. Link Perl's core
        # extensions into the interpreter instead of omitting their modules.
        "$CONFIG_SHELL" ./Configure -des \
          -Dprefix="$out" \
          -Dcc="${targetTools.gcc}/bin/gcc -static" \
          -Dar="${targetTools.binutils}/bin/ar" \
          -Dnm="${targetTools.binutils}/bin/nm" \
          -Dranlib="${targetTools.binutils}/bin/ranlib" \
          -Dsh="$CONFIG_SHELL" \
          -Dusrinc="${targetTools.glibc}/include" \
          -Dlocincpth="${targetTools.glibc}/include" \
          -Dloclibpth="${targetTools.glibc}/lib" \
          -Dglibpth="${targetTools.glibc}/lib" \
          -Dccflags="-O2 -isystem ${targetTools.glibc}/include" \
          -Dldflags="-static -L${targetTools.glibc}/lib" \
          -Dlibs="-lm -ldl -lcrypt -lpthread -Wl,--start-group -lc ${nssLibraries} -lresolv -Wl,--end-group" \
          -Uusedl -Uuseshrplib

        make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" miniperl
        # Keep extension generation serial while compiling the core in parallel.
        make SHELL="$CONFIG_SHELL"

        # Static extension installation omits POSIX's AutoLoader index. Generate
        # it before both the module and the documentation that imports it install.
        ./perl -Ilib -MAutoSplit -e \
          'autosplit("ext/POSIX/POSIX.pm", "lib/auto", 0, 1, 0)'
        test -f lib/auto/POSIX/autosplit.ix
        make SHELL="$CONFIG_SHELL" install

        AOS_RUNTIME_SHELL="$CONFIG_SHELL" \
          "$CONFIG_SHELL" ${../../runtime-scripts.sh} "$out"
        "$out/bin/perl" -MPOSIX -MErrno -e 'POSIX::getcwd() or die "getcwd failed"'
        "$out/bin/perl" -T -MCwd -e 'Cwd::cwd() or die "tainted cwd failed"'
        "$out/bin/perl" -MIO::Compress::Gzip=gzip -MIO::Uncompress::Gunzip=gunzip -e '
          my $source = "compression contract";
          my ($compressed, $restored);
          gzip(\$source => \$compressed) or die "gzip failed";
          gunzip(\$compressed => \$restored) or die "gunzip failed";
          $restored eq $source or die "compression round trip failed";
        '
      ''
    ];
  }
  // {
    inherit version;
    pname = "perl";
    passthru.evidenceSources = [src];
    meta = {
      description = "Static Perl interpreter for early libc and tracing tools";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
