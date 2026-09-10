##! Defines the complete static Perl package for early native toolchain tiers.
{
  glibc,
  coreutils,
  meta,
}: {
  pname = "perl";
  version = "5.10.1";
  url = "https://www.cpan.org/src/5.0/perl-5.10.1.tar.bz2";
  hash = "0wfch7jkcwmi5xmsrb7j18fn63hs7qvl958gzy6mfgxar6hj88dk";
  freezeAutotoolsTimestamps = false;

  configureScript = ''
    # Preserve all core modules while generating Errno from the target headers.
    patch -p1 < ${./perl-5.10.1-bootstrap.patch}

    # Cwd clears PATH under taint mode, so its trusted pwd must be absolute.
    sed "s|'/bin/pwd'|'${coreutils}/bin/pwd', '/bin/pwd'|" \
      lib/Cwd.pm > lib/Cwd.pm.tmp
    cat lib/Cwd.pm.tmp > lib/Cwd.pm
    rm lib/Cwd.pm.tmp

    # Config.pm retains the compiler command for installed extension builders.
    # Keep the static NSS frontend available after the build directory is gone.
    mkdir -p "$out/libexec"
    cp "$CC" "$out/libexec/cc"
    chmod +x "$out/libexec/cc"

    "$CONFIG_SHELL" ./Configure -des \
      -Dprefix="$out" \
      -Dcc="$out/libexec/cc -static" \
      -Dar="$AR" \
      -Dnm="$NM" \
      -Dranlib="$RANLIB" \
      -Dsh="$AOS_BASH" \
      -Dusrinc="${glibc}/include" \
      -Dlocincpth="${glibc}/include" \
      -Dloclibpth="${glibc}/lib" \
      -Dglibpth="${glibc}/lib" \
      -Dccflags="$CFLAGS" \
      -Dcppflags="$CPPFLAGS" \
      -Dldflags="$LDFLAGS -static" \
      -Dlibs="-lm -ldl -lcrypt -lpthread" \
      -Uusedl -Uuseshrplib
  '';

  buildScript = ''
    make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" miniperl
    make SHELL="$CONFIG_SHELL"

    # Static installation needs this index before documentation imports POSIX.
    ./perl -Ilib -MAutoSplit -e \
      'autosplit("ext/POSIX/POSIX.pm", "lib/auto", 0, 1, 0)'
    test -f lib/auto/POSIX/autosplit.ix
  '';

  installScript = ''
    make SHELL="$CONFIG_SHELL" install

    "$out/bin/perl" -MPOSIX -MErrno -e 'POSIX::getcwd() or die "getcwd failed"'
    "$out/bin/perl" -T -MCwd -e 'Cwd::cwd() or die "tainted cwd failed"'
    "$out/bin/perl" -MIO::Compress::Gzip=gzip -MIO::Uncompress::Gunzip=gunzip -e '
      my $source = "compression contract";
      my ($compressed, $restored);
      gzip(\$source => \$compressed) or die "gzip failed";
      gunzip(\$compressed => \$restored) or die "gunzip failed";
      $restored eq $source or die "compression round trip failed";
    '
  '';

  inherit meta;
}
