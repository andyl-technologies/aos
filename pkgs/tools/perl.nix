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
}: let
  version = "5.40.1";
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

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    # Per-output reference check: $out must not reference the unwrapped
    # compiler or the cc-wrapper. If a substitution in postInstall misses
    # a path, Nix fails the build with the offending reference. $dev is
    # exempt — it intentionally keeps the unscrubbed Config files.
    outputChecks = {
      out = {
        disallowedReferences = [gcc gccUnwrapped cc];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd perl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./Configure \
            -des \
            -Dprefix=$out \
            -Dvendorprefix=$out \
            -Dprivlib=$out/lib/perl5/${version} \
            -Darchlib=$out/lib/perl5/${version}/x86_64-linux \
            -Dvendorlib=$out/lib/perl5/${version} \
            -Dvendorarch=$out/lib/perl5/${version}/x86_64-linux \
            -Dman1dir=$out/share/man/man1 \
            -Dman3dir=$out/share/man/man3 \
            -Dusethreads \
            -Duseshrplib \
            -Dlibs='-lpthread -ldl -lm -lutil -lc'
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
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
            "${cc}" \
            "${gcc}" \
            "${gccUnwrapped}" \
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
        '';
      }
    ];

    meta = {
      description = "Perl — practical extraction and reporting language";
      homepage = "https://www.perl.org";
      license = "Artistic-1.0-Perl";
    };
  }
