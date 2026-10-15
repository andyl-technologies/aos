# Builds data artifacts for one explicit Linux syscall ABI; it never runs PID1.
{
  mkDerivation,
  llvm-gem5,
  python3,
  diffutils,
  architecture,
  targetTriple,
  kernelHeaders,
  kernelHeaderSource,
  kernelHeaderRecipe,
  recipe,
  pname,
}: let
  sourceIdentity = builtins.toJSON {
    schema = "aos.gem5.linux-device-fixture-source.v1";
    inherit architecture targetTriple;
    compiler = "${llvm-gem5}";
    python = "${python3}";
    kernel_headers = "${kernelHeaders}";
    kernel_header_source = "${kernelHeaderSource}";
    pid1_sha256 = builtins.hashFile "sha256" ./linux-device-init.c;
    packer_sha256 = builtins.hashFile "sha256" ./make-device-initramfs.py;
    checker_sha256 = builtins.hashFile "sha256" ./linux-init-artifact-check.py;
    controls_sha256 = builtins.hashFile "sha256" ./linux-init-artifact-tests.py;
    socket_abi_sha256 = builtins.hashFile "sha256" ./freestanding-uapi/sys/socket.h;
    recipe_sha256 = builtins.hashFile "sha256" recipe;
    common_recipe_sha256 = builtins.hashFile "sha256" ./linux-device-fixture.nix;
    kernel_header_recipe_sha256 = builtins.hashFile "sha256" kernelHeaderRecipe;
  };
in
  mkDerivation {
    inherit pname sourceIdentity;
    passAsFile = ["sourceIdentity"];
    version = "1";
    outputs = ["out" "source"];
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [kernelHeaders llvm-gem5 python3 diffutils];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          # This freestanding PID1 supplies its own entry, syscall ABI and headers.
          # Ordinary Clang defaults inject a host libc interpreter even with -static.
          ${llvm-gem5}/bin/clang --no-default-config --target=${targetTriple} -fuse-ld=lld \
            -nostdinc -nostdlib -static -fno-pie -Wl,-no-pie -ffreestanding -fno-builtin \
            -fno-stack-protector -O2 -Wall -Wextra -Werror \
            -I${./freestanding-uapi} -I${kernelHeaders}/include \
            -Wl,--build-id=none -Wl,-e,_start ${./linux-device-init.c} -o init
          ${python3}/bin/python3 -I -B ${./make-device-initramfs.py} init initrd.img
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/licenses/${pname}" "$source/build" \
            "$source/freestanding-uapi/sys" "$source/licenses"
          cp init initrd.img "$out/"
          cp ${./linux-device-init.c} "$source/linux-device-init.c"
          cp ${./make-device-initramfs.py} "$source/make-device-initramfs.py"
          cp ${./linux-init-artifact-check.py} "$source/linux-init-artifact-check.py"
          cp ${./linux-init-artifact-tests.py} "$source/linux-init-artifact-tests.py"
          cp ${./freestanding-uapi/sys/socket.h} "$source/freestanding-uapi/sys/socket.h"
          cp ${recipe} "$source/build/recipe.nix"
          cp ${./linux-device-fixture.nix} "$source/build/common-recipe.nix"
          cp ${kernelHeaderRecipe} "$source/build/kernel-header-recipe.nix"
          cp "$sourceIdentityPath" "$source/source-manifest.json"
          cp -R ${kernelHeaders}/include "$source/kernel-headers"
          cp ${../../../LICENSES/MIT.txt} "$source/licenses/MIT.txt"
          cp ${../../../LICENSES/Apache-2.0.txt} "$source/licenses/Apache-2.0.txt"
          cp ${../../../LICENSES/MIT.txt} "$out/share/licenses/${pname}/LICENSE"
          ln -s ${kernelHeaderSource} "$source/kernel-header-source"
          ln -s "$source" "$out/share/corresponding-source"
          ${python3}/bin/python3 -I -B ${./linux-init-artifact-check.py} \
            ${architecture} "$out" > "$source/binary-bindings.json"
        '';
      }
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -I -B ${./linux-init-artifact-check.py} \
            ${architecture} "$out" > fixture-bindings.json
          ${diffutils}/bin/cmp "$source/binary-bindings.json" fixture-bindings.json
        '';
      }
    ];
    meta = {
      description = "Source-built ${architecture} Linux PID1/initramfs with opt-in network, block and 9p probes; native boot and device parity require independent qualification";
      license = "MIT";
    };
  }
