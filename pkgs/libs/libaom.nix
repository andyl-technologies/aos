##! libaom — AV1 encoding and decoding for AVIF images and video.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "3.15.0";
  targetCpu =
    if stdenv.hostPlatform.isAarch64
    then "arm64"
    else "x86_64";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libaom";
    inherit version;
    src = fetchurl {
      urls = ["https://storage.googleapis.com/aom-releases/libaom-${version}.tar.gz"];
      hash = "15mgh5824aa6c9dwmrqzm3qm0qmha87054dnn5dwi2q7rj7c627a";
    };

    buildDeps =
      [buildPackages.cmake buildPackages.gnumake buildPackages.nasm buildPackages.perl buildPackages.python3 buildPackages.doxygen]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [buildPackages.llvm]
        else []
      );
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libaom-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DBUILD_SHARED_LIBS=ON \
              -DENABLE_NASM=ON \
              -DAOM_TARGET_CPU=${targetCpu} \
              ${
              if stdenv.isCross && stdenv.hostPlatform.isDarwin
              then "-DCMAKE_INSTALL_NAME_TOOL=${buildPackages.llvm}/bin/llvm-install-name-tool"
              else ""
            }
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
            cmake --build build --target docs --parallel "$NIX_BUILD_CORES"
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
              # Exercise both public command-line programs with deterministic
              # lossless input, without downloading media during the build.
              ${buildPackages.python3}/bin/python3 - <<'PY'
              from pathlib import Path

              frames = []
              for frame_index in range(2):
                  luma = bytes((x * 7 + y * 11 + frame_index * 31) % 256
                               for y in range(32) for x in range(32))
                  chroma_u = bytes([80 + frame_index * 10]) * 256
                  chroma_v = bytes([160 - frame_index * 10]) * 256
                  frames.append(luma + chroma_u + chroma_v)

              Path("sample.yuv").write_bytes(b"".join(frames))
              Path("sample.y4m").write_bytes(
                  b"YUV4MPEG2 W32 H32 F25:1 Ip A1:1 C420jpeg\n"
                  + b"".join(b"FRAME\n" + frame for frame in frames)
              )
              PY
              build/aomenc --codec=av1 --lossless=1 --cpu-used=8 --limit=2 \
                --ivf --output=sample.ivf sample.y4m
              build/aomdec --codec=av1 --rawvideo --i420 --output=roundtrip.yuv sample.ivf
              cmp sample.yuv roundtrip.yuv
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/libaom"
            cp LICENSE PATENTS "$out/share/licenses/libaom/"
          '';
        }
      ];

    meta = {
      description = "AV1 codec library with encoder, decoder, examples, and documentation";
      homepage = "https://aomedia.googlesource.com/aom/";
      license = "BSD-2-Clause";
    };
  }
