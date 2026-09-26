##! AV1 decoding library and command-line decoder.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xxhash,
}: let
  version = "1.5.4";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "dav1d";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A known-good, single-frame AV1 IVF bitstream.";
        operation = "Decode it to YUV 4:2:0 pixels.";
        expected = "The decoded pixels match the frame encoded losslessly by Libaom.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import base64
                from pathlib import Path

                encoded = (
                    "L`z9V001BWK~^v^5C9MW82|tP0RR910RR9100000Y5)KL00000000005&#MY7!3d"
                    "00Dv-H5C8y2!ojqsC6#>);QnbCW$<Q#9rV6lQUQ-M^JB{MC%$9YlzfBgHD|ONXhf"
                    "5ULkk_UFRNmTC)V3)Ngl|249Mbx7rGrsFhJ(cMe^ZE-~c0ou;dI*1b=<TJs<"
                )
                Path("frame.ivf").write_bytes(base64.b85decode(encoded))
              ''
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@out@/bin/dav1d"
              "--quiet"
              "--input"
              "frame.ivf"
              "--output"
              "decoded.yuv"
              "--muxer"
              "yuv"
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                luma = bytes((x * 9 + y * 7) % 256 for y in range(16) for x in range(16))
                chroma = bytes([90]) * 64 + bytes([160]) * 64
                assert Path("decoded.yuv").read_bytes() == luma + chroma
                print("dav1d AV1 frame decoding passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "dav1d AV1 frame decoding passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not contain an AV1 bitstream.";
        operation = "Attempt to decode them.";
        expected = "The decoder rejects the invalid input.";
        files."bad.ivf" = "not AV1\n";
        artifacts = [];
        steps = [
          {
            argv = [
              "@out@/bin/dav1d"
              "--quiet"
              "--input"
              "bad.ivf"
              "--output"
              "bad.yuv"
              "--muxer"
              "yuv"
            ];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://download.videolan.org/pub/videolan/dav1d/${version}/dav1d-${version}.tar.xz"];
      hash = "1id52hairrw4axf8725jld3ncfy1r8jsp4ck8m28vf4yqsvicrk8";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.nasm buildPackages.pkg-config];
    runtimeDeps = [xxhash];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd dav1d-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dxxhash_muxer=enabled
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build -j"$NIX_BUILD_CORES"
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
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build install
            mkdir -p "$out/share/licenses/dav1d"
            cp COPYING "$out/share/licenses/dav1d/"
          '';
        }
      ];
    meta = {
      description = "AV1 decoding library and command-line decoder";
      homepage = "https://www.videolan.org/projects/dav1d.html";
      license = "BSD-2-Clause";
    };
  }
