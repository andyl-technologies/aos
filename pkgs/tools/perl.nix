##! Perl — Practical Extraction and Reporting Language
{
  mkDerivation,
  fetchurl,
  gnumake,
  # Explicit toolchain inputs needed for the postInstall Config scrub.
  # `cc` is the wrapped cc (aos-cc-wrapper); `gcc` is the wrapped
  # gcc-14.3.0-wrapped; `gccUnwrapped` is the bare gcc-14.3.0-stage2
  # whose path Configure records into Config_heavy.pl via specs / PATH;
  # `glibc` is the multi-output glibc.
  cc,
  gcc,
  gccUnwrapped,
  glibc,
  stdenv,
  buildPackages,
}: let
  version = "5.40.1";
  isDarwin = stdenv.hostPlatform.isDarwin;
  targetCpu = stdenv.hostPlatform.constraints.cpu;
  archDirectory =
    if isDarwin
    then "${targetCpu}-darwin"
    else "x86_64-linux";
  longDoubleSize =
    if stdenv.hostPlatform.isAarch64
    then "8"
    else "16";
  # Native Perl records the public GCC package set, while Darwin Perl is
  # compiled by the bootstrap cross wrapper in stdenv. Referencing public
  # pkgs.gcc/cc from a cross output check would add the final Canadian-cross
  # compiler to every Perl consumer without checking the compiler actually
  # used for this derivation.
  recordedCc =
    if isDarwin
    then stdenv.cc
    else cc;
  recordedGcc =
    if isDarwin
    then stdenv.cc
    else gcc;
  recordedGccUnwrapped =
    if isDarwin
    then stdenv.cc
    else gccUnwrapped;
  perlCrossVersion = "1.6.4";
  perlCrossSrc = fetchurl {
    urls = [
      "https://github.com/arsv/perl-cross/archive/refs/tags/${perlCrossVersion}.tar.gz"
    ];
    hash = "sha256-sXZSK86x/DUz64XkQ15asG90c2M5eRIqj1sYorT8hlo=";
  };
in
  mkDerivation {
    pname = "perl";
    inherit version;

    # Two outputs: $out is the scrubbed, ship-ready interpreter; $dev
    # preserves the unmodified Config.pm / Config_heavy.pl so a future
    # developer can audit the build-time toolchain or rebuild an
    # XS-capable variant.
    outputs = ["out" "dev"];

    src = fetchurl {
      urls = [
        "https://www.cpan.org/src/5.0/perl-${version}.tar.xz"
      ];
      hash = "sha256-36IMLu8rSvEzUlYQu7Zd0Td37PmYycWxzPDTCOcy7j8=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if isDarwin
        then [buildPackages.llvm]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    # Per-output reference check: $out must not reference the unwrapped
    # compiler or the cc-wrapper. If a substitution in postInstall misses
    # a path, Nix fails the build with the offending reference. $dev is
    # exempt — it intentionally keeps the unscrubbed Config files.
    outputChecks = {
      out = {
        disallowedReferences = [recordedGcc recordedGccUnwrapped recordedCc];
      };
    };

    phases = [
      {
        name = "unpack";
        script =
          if isDarwin
          then ''
            tar xf $src
            cd perl-${version}

              # perl-cross replaces target execution probes with compile/link
              # tests and a Linux miniperl used only for source generation.
              chmod -R u+w .
              tar xf ${perlCrossSrc} --strip-components=1

              # Every helper must execute with the hermetic AOS build shell.
              for script in \
                configure miniperl_top 0pack.sh modclean Makefile.config.SH \
                cnf/configure cnf/*.sh
              do
                [ -f "$script" ] || continue
                sed -i "1s|^#!/bin/sh$|#!$CONFIG_SHELL|" "$script"
              done

              # Time::HiRes treats a target link probe as a runnable native
              # executable and concludes that clockid_t is absent. Darwin's
              # public time.h always defines the type, so cache that target
              # fact before the extension adds a conflicting typedef.
              sed -i \
                '/^sub has_clockid_t{/a\    return 1;' \
                dist/Time-HiRes/Makefile.PL
          ''
          else ''
            tar xf $src
            cd perl-${version}
          '';
      }
      {
        name = "configure";
        script =
          if isDarwin
          then ''
            # perl-cross configures a Linux build-miniperl before the Darwin
            # target. Its probe uses the conventional GNU readelf name; AOS
            # LLVM provides the compatible implementation as llvm-readelf.
            mkdir -p "$TMPDIR/perl-native-tools"
            ln -s ${buildPackages.llvm}/bin/llvm-readelf \
              "$TMPDIR/perl-native-tools/readelf"
            export PATH="$TMPDIR/perl-native-tools:$PATH"

            # perl-cross still names an ELF-only inspection tool even when
            # every ABI size is supplied.  A no-op keeps that unused lookup
            # hermetic; Mach-O byte order is pinned below as well.
            export READELF=true

            ./configure \
              --build=${stdenv.buildPlatform.config} \
              --target=${stdenv.hostPlatform.config} \
              --with-cc="$CC" \
              --with-ranlib="$RANLIB" \
              --with-objdump="$OBJDUMP" \
              --host-cc="$CC_FOR_BUILD" \
              --sysroot="$SDKROOT" \
              --prefix="$out" \
              --man1dir="$out/share/man/man1" \
              --man3dir="$out/share/man/man3" \
              --libs=pthread,dl,m,util,c \
              -Dar="$AR" \
              -Dnm="$NM" \
              -Dosname=darwin \
              -Dosvers=20.0.0 \
              -Darchname=darwin-thread-multi-2level \
              -Dprivlib="$out/lib/perl5/${version}" \
              -Darchlib="$out/lib/perl5/${version}/${archDirectory}" \
              -Dvendorprefix="$out" \
              -Dvendorlib="$out/lib/perl5/${version}" \
              -Dvendorarch="$out/lib/perl5/${version}/${archDirectory}" \
              -Dusethreads \
              -Duseshrplib \
              -Dlibperl=libperl.dylib \
              -Dso=dylib \
              -Ddlext=bundle \
              -Dusedl=define \
              -Ddlsrc=dl_dlopen.xs \
              -Dcccdlflags=' ' \
              -Dccdlflags=' ' \
              -Dlddlflags='-bundle -undefined dynamic_lookup' \
              -Dldlibpthname=DYLD_LIBRARY_PATH \
              -Dusenm=false \
              -Dusevfork=true \
              -Dusemymalloc=n \
              -Dd_nanosleep=define \
              -Dd_thread_local=undef \
              -Dd_syscall=undef \
              -Di_dbm=undef \
              -Dcharsize=1 \
              -Dshortsize=2 \
              -Dintsize=4 \
              -Dlongsize=8 \
              -Ddoublesize=8 \
              -Dptrsize=8 \
              -Dlongdblsize=${longDoubleSize} \
              -Dlonglongsize=8 \
              -Dsizesize=8 \
              -Dfpossize=8 \
              -Dlseeksize=8 \
              -Duidsize=4 \
              -Dgidsize=4 \
              -Dtimesize=8 \
              -Dbyteorder=12345678
          ''
          else ''
            ./Configure \
              -des \
              -Dprefix=$out \
              -Dvendorprefix=$out \
              -Dprivlib=$out/lib/perl5/${version} \
              -Darchlib=$out/lib/perl5/${version}/${archDirectory} \
              -Dvendorlib=$out/lib/perl5/${version} \
              -Dvendorarch=$out/lib/perl5/${version}/${archDirectory} \
              -Dman1dir=$out/share/man/man1 \
              -Dman3dir=$out/share/man/man3 \
              -Dusethreads \
              -Duseshrplib \
              -Dlibs='-lpthread -ldl -lm -lutil -lc'
          '';
      }
      {
        name = "build";
        script =
          if isDarwin
          then ''
            # Modules are Mach-O bundles, while libperl itself is a dylib.
            # perl-cross uses one linker variable for both, so separate the
            # shared-library rule exactly as upstream Makefile.SH does.
            sed -i '/^perl\$x: LDFLAGS += -Wl,-E$/d' Makefile
            sed -i \
              's|$(CC) $(LDDLFLAGS) -o $@ $(filter %$o,$^) $(LIBS)|$(CC) $(SHRPLDFLAGS) -o $@ $(filter %$o,$^) $(LIBS)|' \
              Makefile

            # perl-cross's generated module graph races source generation
            # against XS compilation under parallel make.
            make -j1 \
              SHRPLDFLAGS='-dynamiclib -Wl,-compatibility_version,${version} -Wl,-current_version,${version} -Wl,-install_name,@rpath/libperl.dylib'
          ''
          else ''
            make -j$NIX_BUILD_CORES
          '';
      }
      {
        name = "install";
        script =
          ''
            make install

            # ── Preserve unmodified Config files in $dev before scrubbing ──
            # $dev is a forensic copy mirroring $out's layout, not a usable
            # perl interpreter. Lets future devs audit the build-time
            # toolchain or rebuild an XS-capable variant from this baseline.
            mkdir -p "$dev"
            for cfg in "$out"/lib/perl5/*/*/Config.pm "$out"/lib/perl5/*/*/Config_heavy.pl; do
              [ -f "$cfg" ] || continue
              rel="''${cfg#$out/}"
              mkdir -p "$dev/$(dirname "$rel")"
              cp "$cfg" "$dev/$rel"
            done

            # ── Scrub $out: rewrite build-time toolchain refs ──────────────
            # Mirrors nixpkgs perl/interpreter.nix:312-332. After this step
            # $Config{cc}, $Config{libpth}, etc. resolve to /no-such-path
            # (or empty). The AOS perl-consumer audit shows no package
            # reads $Config{cc}, so this breaks nothing — and it cuts the
            # ~900 MB toolchain cascade that perl drags into every closure.

            # libpth is a parsed Perl list; substituting hash digits inside
            # the string would leave a syntactically-valid but bogus path.
            # Replace the whole line instead (mirrors interpreter.nix:317-318).
            sed "/ *libpth =>/c\\    libpth => ' '," \
              -i "$out"/lib/perl5/*/*/Config.pm

            # Config_heavy.pl entries are inert strings — plain path
            # substitution is safe. The pattern set covers perl's directly-
            # recorded cc/gcc and the glibc outputs Configure picks up via
            # CFLAGS/LIBRARY_PATH; without scrubbing glibc.dev/glibc.static
            # the closure leak would just shift from gcc to those.
            for pattern in \
              "${recordedCc}" \
              "${recordedGcc}" \
              "${recordedGccUnwrapped}" \
              "${glibc}" \
              "${glibc.dev}" \
              "${glibc.static}" \
            ; do
              if [ -n "$pattern" ]; then
                sed -i "s|$pattern|/no-such-path|g" \
                  "$out"/lib/perl5/*/*/Config_heavy.pl
              fi
            done

            # .packlist records build-time install paths — drop it.
            rm -f "$out"/lib/perl5/*/*/.packlist
          ''
          + (
            if isDarwin
            then ''
              # Perl installs generated module data and documentation outside
              # the generic executable/config scrub set. Remove build-time
              # store references from every shipped regular file while
              # retaining the interpreter's own paths and target runtimes.
              find "$out" -type f -print0 \
                | xargs -0 -r nuke-refs \
                    -e "$out" \
                    -e "${stdenv.darwinRuntimes}"
            ''
            else ""
          );
      }
    ];

    meta = {
      description = "Perl — practical extraction and reporting language";
      homepage = "https://www.perl.org";
      license = "Artistic-1.0-Perl";
    };
  }
