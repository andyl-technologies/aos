##! Linux-native cctools ld64 with source-built DTrace and TAPI support.
{
  mkDerivation,
  fetchurl,
  gnumake,
  llvm,
  gcc,
  glibc,
  appleLibTapi,
  darwinDtraceCompiler,
  libbsd,
  util-linux,
}: let
  revision = "d9456c221e1f462e17c0b3297748bc089d5a861e";
in
  mkDerivation {
    pname = "darwin-cctools-linker";
    version = "949.0.1-ld64-512.4";

    src = fetchurl {
      urls = [
        "https://github.com/tpoechtrager/cctools-port/archive/${revision}.tar.gz"
      ];
      hash = "sha256-lvC4VjddJMVyNszhOjHFvy+kiEPhHsnCNR4zLuRCe/Q=";
    };

    buildDeps = [gnumake llvm appleLibTapi darwinDtraceCompiler libbsd util-linux];
    runtimeDeps = [appleLibTapi util-linux];
    hardeningDisable = ["all"];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cctools-port-${revision}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./cctools-native-dtrace.patch}
          grep -q -- '-isystem /usr/local/include -isystem /usr/pkg/include' cctools/configure
          grep -q -- '-L/usr/local/lib -L/usr/pkg/lib' cctools/configure
          sed -i \
            -e 's| -isystem /usr/local/include -isystem /usr/pkg/include||g' \
            -e 's| -L/usr/local/lib -L/usr/pkg/lib||g' \
            -e 's| -Wl,-rpath,/usr/local/lib,--enable-new-dtags||g' \
            cctools/configure cctools/configure.ac
        '';
      }
      {
        name = "configure";
        script = ''
          cd cctools
          export CC="${llvm}/bin/clang --gcc-toolchain=${gcc} -B${glibc}/lib -idirafter ${glibc.dev}/include"
          export CXX="${llvm}/bin/clang++ --gcc-toolchain=${gcc} -B${glibc}/lib -idirafter ${glibc.dev}/include"
          export CPPFLAGS="$CPPFLAGS -I${appleLibTapi}/include"
          export LDFLAGS="$LDFLAGS -L${glibc}/lib -Wl,-dynamic-linker,${glibc}/lib/ld-linux-x86-64.so.2 -Wl,-rpath,${glibc}/lib -L${appleLibTapi}/lib -L${darwinDtraceCompiler}/lib -Wl,-rpath,${appleLibTapi}/lib -Wl,-rpath,${darwinDtraceCompiler}/lib"
          ./configure \
            --prefix="$out" \
            --target=aarch64-apple-darwin \
            --with-libtapi=${appleLibTapi} \
            --disable-xar-support
        '';
      }
      {
        name = "build";
        script = ''
          # cargo-nextest needs the Darwin linker only.  Building the complete
          # cctools suite also compiles host-side otool disassemblers whose
          # legacy SDK compatibility surface is unrelated to ld64.
          make -C libstuff -j"$NIX_BUILD_CORES"
          make -C ld64 -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          make -C ld64 install
        '';
      }
    ];

    meta = {
      description = "Linux-native cctools ld64 with arm64 DTrace DOF support";
      license = "APSL-2.0";
    };
  }
