##! Bounded real ELF and Linux initramfs loader geometry; no native admission
{
  mkDerivation,
  binutils,
  python3,
}: let
  helper = ./_gem5/x86-linux-loader.py;
  check = ./_gem5/x86-linux-loader-check.py;
  fixture = ./_gem5/x86-linux-loader-fixture.S;
in
  mkDerivation {
    pname = "gem5-x86-linux-loader-check";
    version = "1";
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
    buildDeps = [binutils python3];
    runtimeDeps = [];
    phases = [
      {
        name = "check";
        script = ''
          ${binutils}/bin/as --64 ${fixture} -o loader-fixture.o
          ${binutils}/bin/ld -m elf_x86_64 --build-id=none -Ttext=0x400000 \
            -e _start loader-fixture.o -o loader-fixture.elf
          ${python3}/bin/python3 -I -B ${check} ${helper} \
            loader-fixture.elf loader-check > loader-check.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/checks" "$out/share/gem5/x86-loader-source" \
            "$out/share/licenses/gem5-x86-linux-loader-check"
          cp loader-check.json "$out/share/checks/x86-linux-loader.json"
          cp ${helper} "$out/share/gem5/x86-loader-source/loader.py"
          cp ${check} "$out/share/gem5/x86-loader-source/check.py"
          cp ${fixture} "$out/share/gem5/x86-loader-source/fixture.S"
          cp ${./gem5-x86-linux-loader-check.nix} "$out/share/gem5/x86-loader-source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-x86-linux-loader-check/LICENSE"
        '';
      }
    ];
    meta = {
      description = "Checks fixed x86 ELF/initramfs regions and exact Linux boot-protocol writes without creating native execution or capture authority";
      license = "MIT";
    };
  }
