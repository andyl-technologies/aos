##! Open Darwin SDK surface used by the Linux-hosted cross toolchain.
##!
##! Zig maintains a redistributable aggregation of Apple open-source libc,
##! XNU, libdispatch, and related public headers together with a textual TAPI
##! description of libSystem.  This derivation installs only those source/data
##! inputs; it does not contain or extract an Xcode SDK.
{
  mkDerivation,
  fetchurl,
}: let
  version = "0.16.0";
in
  mkDerivation {
    pname = "darwin-sdk";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ziglang.org/download/${version}/zig-${version}.tar.xz"
      ];
      hash = "sha256-QxhpWe3IfVx6G+e30qJe//0izlgHx6+ZBn+G+ZZBv98=";
    };

    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd "zig-${version}"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p \
            "$out/usr/include/c++/v1" \
            "$out/usr/include/libunwind" \
            "$out/usr/lib" \
            "$out/share/licenses/darwin-sdk"

          cp -R lib/libc/include/any-darwin-any/. "$out/usr/include/"
          cp -R lib/libcxx/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libcxxabi/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libunwind/include/. "$out/usr/include/libunwind/"
          cp lib/libc/darwin/libSystem.tbd "$out/usr/lib/libSystem.tbd"
          cp lib/libc/darwin/SDKSettings.json "$out/SDKSettings.json"
          cp LICENSE "$out/share/licenses/darwin-sdk/Zig-LICENSE"
          cp lib/libcxx/LICENSE.TXT "$out/share/licenses/darwin-sdk/libcxx-LICENSE"
          cp lib/libcxxabi/LICENSE.TXT "$out/share/licenses/darwin-sdk/libcxxabi-LICENSE"
          cp lib/libunwind/LICENSE.TXT "$out/share/licenses/darwin-sdk/libunwind-LICENSE"

          # Darwin's libc, libdl, libm, pthread, resolv, and libutil symbols
          # are all re-exported by libSystem.  Make the traditional linker
          # names resolve to the same textual stub without shipping binaries.
          for library in c dl m pthread resolv util; do
            ln -s libSystem.tbd "$out/usr/lib/lib$library.tbd"
          done
        '';
      }
    ];

    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    meta = {
      description = "Redistributable Darwin headers and libSystem link stubs";
      homepage = "https://ziglang.org/";
      license = "APSL-2.0 AND BSD-3-Clause AND MIT";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  }
