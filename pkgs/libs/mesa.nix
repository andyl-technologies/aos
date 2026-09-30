##! Mesa OpenGL, EGL, GBM, Vulkan and OpenCL graphics drivers
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  libdrm,
  libglvnd,
  libx11,
  libxext,
  libxxf86vm,
  libxshmfence,
  libxcb,
  xorgproto,
  wayland,
  wayland-protocols,
  vulkan-headers,
  vulkan-loader,
  libva,
  zlib,
  zstd,
  expat,
  elfutils,
  libunwind,
  systemd,
  gcc-libs,
  rust,
  llvm-graphics,
  spirv-llvm-translator-graphics,
  spirv-tools,
  libclc,
}: let
  version = "26.1.4";
  rustSources = import ./_mesa-rust-sources.nix {inherit fetchurl;};
  sitePackages = "lib/python3.14/site-packages";
  pythonPath =
    "${buildPackages.meson}/lib/python3/site-packages:"
    + builtins.concatStringsSep ":" (map (package: "${package}/${sitePackages}") [
      buildPackages.python3-mako
      buildPackages.python3-markupsafe
      buildPackages.packaging
      buildPackages.python3-pyyaml
    ]);
in
  mkDerivation {
    pname = "mesa";
    inherit version;
    src = fetchurl {
      urls = ["https://archive.mesa3d.org/mesa-${version}.tar.xz"];
      hash = "sha256-BycFyqmt9HQPFIkZSxPieK2VkWaGO1Jx/kI6hjU8mrY=";
    };

    buildDeps =
      [
        buildPackages.meson
        buildPackages.ninja
        buildPackages.pkg-config
        buildPackages.python3
        buildPackages.python3-mako
        buildPackages.python3-markupsafe
        buildPackages.packaging
        buildPackages.python3-pyyaml
        buildPackages.flex
        buildPackages.bison
        buildPackages.rust
        buildPackages.bindgen
        buildPackages.cbindgen
        buildPackages.glslang
        buildPackages.wayland
        buildPackages.llvm-graphics
      ]
      ++ lib.optionals stdenv.isCross [buildPackages.cmake rust.passthru.buildTool];
    runtimeDeps = [
      libdrm
      libglvnd
      libx11
      libxext
      libxxf86vm
      libxshmfence
      libxcb
      xorgproto
      wayland
      wayland-protocols
      vulkan-headers
      vulkan-loader
      libva
      zlib
      zstd
      expat
      elfutils
      libunwind
      systemd
      gcc-libs
      llvm-graphics
      spirv-llvm-translator-graphics
      spirv-tools
      libclc
    ];
    propagatedDeps = [libdrm libglvnd wayland vulkan-headers libva];
    passthru.evidenceSources = map (component: component.src) rustSources;
    PYTHONPATH = pythonPath;

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd mesa-${version}
            # Populate every pinned Rust subproject and its upstream Meson
            # overlay before configuration; the sandbox performs no downloads.
            ${builtins.concatStringsSep "\n" (map (component: ''
                tar xf ${component.src} -C subprojects
                cp -R subprojects/packagefiles/${component.patchDirectory}/. \
                  subprojects/${component.directory}/
              '')
              rustSources)}

            # LLVM and GNU libunwind both install libunwind.h. This translation
            # unit links GNU libunwind, whose symbols use a distinct prefix.
            test "$(grep -c '^#include <libunwind.h>$' src/util/u_debug_stack.h)" -eq 1
            sed -i 's|^#include <libunwind.h>$|#include "${libunwind}/include/libunwind.h"|' \
              src/util/u_debug_stack.h

            ${lib.optionalString stdenv.isCross ''
              # Mesa otherwise invokes a build-host llvm-config for target
              # headers and libraries. Its CMake resolver reads the target
              # LLVM package metadata with the cross compiler instead.
              test "$(grep -c "method : host_machine.system() == 'windows' ? 'auto' : 'config-tool'," meson.build)" -eq 1
              sed -i "s|method : host_machine.system() == 'windows' ? 'auto' : 'config-tool',|method : host_machine.system() == 'windows' ? 'auto' : 'cmake',|" meson.build

              # The Linux cross Rust package keeps a native compiler with the
              # target standard library. Meson must use that compiler and the
              # target C linker for Rusticl, not the native Rust default.
              cat > mesa-cross-rust.ini <<'MESON_RUST'
              [binaries]
              rust = ['${rust.passthru.buildTool}/bin/rustc', '--target', '${stdenv.hostPlatform.config}', '-C', 'linker=${stdenv.cc}/bin/cc']
              MESON_RUST
            ''}
          '';
        }
        {
          name = "configure";
          script = ''
            ${lib.optionalString (!stdenv.isCross) ''
              export LLVM_CONFIG=${buildPackages.llvm-graphics}/bin/llvm-config
            ''}
            export NIX_LDFLAGS="$NIX_LDFLAGS -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib"
            # Keep the complete upstream platform and driver selections.
            # Explicitly enable the public dispatch, video and OpenCL APIs.
            # Mesa's C++ RTTI setting must match LLVM's library ABI.
            ${buildPackages.python3}/bin/python3 -m mesonbuild.mesonmain \
              setup build $mesonFlags ${lib.optionalString stdenv.isCross "--cross-file=mesa-cross-rust.ini -Dcmake_prefix_path=${llvm-graphics}"} --prefix="$out" --libdir=lib \
              --buildtype=release --wrap-mode=nodownload \
              -Dcpp_rtti=false \
              -Dglvnd=enabled -Degl=enabled -Dgbm=enabled \
              -Dgallium-va=enabled -Dgallium-rusticl=true -Dbuild-tests=true
          '';
        }
        {
          name = "build";
          script = ''
            ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            ${buildPackages.python3}/bin/python3 -m mesonbuild.mesonmain \
              test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            ninja -C build install
            mkdir -p "$out/share/licenses/mesa"
            cp -R docs/license* "$out/share/licenses/mesa/"
          '';
        }
      ];

    meta = {
      description = "OpenGL, EGL, GBM, Vulkan and OpenCL graphics drivers";
      homepage = "https://www.mesa3d.org/";
      license = "MIT AND BSD-2-Clause AND BSD-3-Clause AND Apache-2.0";
    };
  }
