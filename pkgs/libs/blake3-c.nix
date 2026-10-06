##! Pinned portable C BLAKE3 implementation for native RAM authentication.
{
  mkDerivation,
  fetchurl,
  stdenv,
}: let
  version = "1.8.5";
in
  mkDerivation {
    pname = "blake3-c";
    inherit version;
    src = fetchurl {
      urls = ["https://static.crates.io/crates/blake3/blake3-${version}.crate"];
      hash = "sha256-Cqg8NOYoQ9kk+QXg9chm6x3WVF/E1xnoA9m6YDA3H84=";
    };
    buildDeps = [];
    runtimeDeps = [];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd blake3-${version}
          '';
        }
        {
          name = "build";
          script = ''
            # Pin the portable implementation independently of host CPU dispatch.
            # The native oracle must also run on cross-built guest targets.
            for source in blake3 blake3_dispatch blake3_portable; do
              "$CC" -O2 -fPIC -std=c11 -Wall -Wextra -Werror \
                -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 \
                -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0 \
                -I c -c "c/$source.c" -o "$source.o"
            done
            "$AR" crs libblake3.a blake3.o blake3_dispatch.o blake3_portable.o
            "$CC" -O2 -std=c11 -I c c/example.c libblake3.a -o blake3-example
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              test "$(printf '%s' "" | ./blake3-example)" = \
                af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
              test "$(printf abc | ./blake3-example)" = \
                6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            mkdir -p "$out/lib/pkgconfig" "$out/include" "$out/share/licenses/blake3-c"
            cp libblake3.a "$out/lib/"
            cp c/blake3.h "$out/include/"
            cp LICENSE_CC0 LICENSE_A2 LICENSE_A2LLVM "$out/share/licenses/blake3-c/"
            cat > "$out/lib/pkgconfig/blake3.pc" <<EOF
            prefix=$out
            libdir=\''${prefix}/lib
            includedir=\''${prefix}/include

            Name: blake3
            Description: Portable native BLAKE3 C implementation
            Version: ${version}
            Libs: -L\''${libdir} -lblake3
            Cflags: -I\''${includedir}
            EOF
          '';
        }
      ];
    meta = {
      description = "Pinned portable C BLAKE3 implementation";
      homepage = "https://github.com/BLAKE3-team/BLAKE3";
      license = "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception";
    };
  }
