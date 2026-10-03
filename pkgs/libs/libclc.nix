##! OpenCL built-in libraries, including Mesa SPIR-V targets
{
  mkDerivation,
  buildPackages,
}: let
  llvm = buildPackages.llvm;
  translator = buildPackages.spirv-llvm-translator;
in
  mkDerivation {
    pname = "libclc";
    inherit (llvm) version src;

    buildDeps = [
      buildPackages.cmake
      buildPackages.ninja
      buildPackages.python3
      buildPackages.cc
      llvm
      translator
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd llvm-project-${llvm.version}.src
        '';
      }
      {
        name = "configure";
        script = ''
          # Device libraries contain IR rather than host machine code. Keep
          # all upstream targets, including both Mesa SPIR-V environments.
          # The prepare-builtins generator executes on the build platform.
          unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH LIBRARY_PATH
          unset NIX_CFLAGS_COMPILE NIX_LDFLAGS CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
          cmake -S libclc -B build -G Ninja \
            -DCMAKE_C_COMPILER=${buildPackages.cc}/bin/cc \
            -DCMAKE_CXX_COMPILER=${buildPackages.cc}/bin/c++ \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DLLVM_DIR=${llvm}/lib/cmake/llvm \
            -DLLVM_SPIRV=${translator}/bin/llvm-spirv
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
          mkdir -p "$out/lib/pkgconfig" "$out/share/licenses/libclc"
          ln -s ../../share/pkgconfig/libclc.pc "$out/lib/pkgconfig/libclc.pc"
          cp libclc/LICENSE.TXT "$out/share/licenses/libclc/"
        '';
      }
    ];

    meta = {
      description = "OpenCL built-in libraries for AMD, NVIDIA and Mesa SPIR-V targets";
      homepage = "https://libclc.llvm.org/";
      license = "Apache-2.0 WITH LLVM-exception";
    };
  }
