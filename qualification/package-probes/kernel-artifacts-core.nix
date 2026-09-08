##! Exercises kernel, UAPI, GPU module, and firmware artifact formats.
{testing}: let
  mkPythonProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
    primaryFiles ? {},
    badFiles ? {},
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = primaryFiles;
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} artifact passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = [
            {
              argv = ["@python@" "-c" badScript];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected malformed artifact\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  elfParser = ''
    import pathlib, struct

    def parse_elf(path):
        path = pathlib.Path(path)
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(64)
            if len(header) != 64 or header[:4] != bytes([0x7f]) + b"ELF":
                raise ValueError("missing ELF64 header")
            if header[4:7] != bytes([2, 1, 1]):
                raise ValueError("unsupported ELF encoding")

            elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
            section_offset = struct.unpack_from("<Q", header, 40)[0]
            header_size, section_size, section_count, names_index = struct.unpack_from("<H4xHHH", header, 52)
            if version != 1 or header_size != 64 or section_size != 64:
                raise ValueError("invalid ELF header dimensions")
            if section_count < 2 or names_index == 0 or names_index >= section_count:
                raise ValueError("invalid ELF section indexes")
            if section_offset > size or section_count > (size - section_offset) // section_size:
                raise ValueError("ELF section table extends beyond the artifact")

            stream.seek(section_offset)
            raw_headers = stream.read(section_count * section_size)
            headers = [
                struct.unpack_from("<IIQQQQIIQQ", raw_headers, index * section_size)
                for index in range(section_count)
            ]
            names_header = headers[names_index]
            names_offset, names_size = names_header[4], names_header[5]
            if names_offset > size or names_size > size - names_offset:
                raise ValueError("ELF section-name table extends beyond the artifact")
            stream.seek(names_offset)
            names = stream.read(names_size)

            sections = {}
            for section in headers:
                name_offset = section[0]
                if name_offset >= len(names):
                    raise ValueError("ELF section name is out of range")
                name_end = names.find(b"\0", name_offset)
                if name_end < 0:
                    raise ValueError("ELF section name is unterminated")
                name = names[name_offset:name_end].decode("ascii")
                data_offset, data_size = section[4], section[5]
                if section[1] != 8 and (data_offset > size or data_size > size - data_offset):
                    raise ValueError("ELF section extends beyond the artifact")
                if name in sections:
                    raise ValueError("ELF repeats a section name")
                sections[name] = (data_offset, data_size, section[1])

        return elf_type, machine, sections

    def read_section(path, section):
        offset, size, _section_type = section
        with pathlib.Path(path).open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            raise ValueError("ELF section is truncated")
        return data
  '';

  kernelParser = ''
    import pathlib, re, struct

    def parse_boot_image(path, machine):
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(0x240)
        if machine == 62:
            if len(header) < 0x20a or header[0x1fe:0x200] != bytes.fromhex("55aa"):
                raise ValueError("invalid x86 boot sector")
            if header[0x202:0x206] != b"HdrS" or struct.unpack_from("<H", header, 0x206)[0] < 0x020b:
                raise ValueError("invalid x86 boot protocol")
            setup_sectors = header[0x1f1] or 4
            if size <= (setup_sectors + 1) * 512:
                raise ValueError("x86 kernel payload is truncated")
        elif machine == 183:
            if len(header) < 64 or struct.unpack_from("<I", header, 0x38)[0] != 0x644d5241:
                raise ValueError("invalid arm64 Image header")
            image_size = struct.unpack_from("<Q", header, 0x10)[0]
            if image_size and size < image_size:
                raise ValueError("arm64 kernel payload is truncated")
        else:
            raise ValueError("unsupported kernel architecture")

    def parse_config(text):
        settings = {}
        assignment = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")
        disabled = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")
        for line in text.splitlines():
            match = assignment.fullmatch(line) or disabled.fullmatch(line)
            if match is None:
                continue
            name = match.group(1)
            if name in settings:
                raise ValueError("kernel config repeats " + name)
            settings[name] = match.group(2) if line[0] != "#" else "n"
        if not settings:
            raise ValueError("kernel config contains no settings")
        return settings

    def validate_symbol_map(path):
        wanted = {"_text", "linux_banner"}
        previous = -1
        with path.open() as lines:
            for line in lines:
                fields = line.rstrip("\n").split(" ", 2)
                if len(fields) != 3 or len(fields[1]) != 1:
                    raise ValueError("malformed System.map record")
                address = int(fields[0], 16)
                if address < previous:
                    raise ValueError("System.map is not address ordered")
                previous = address
                wanted.discard(fields[2])
        if wanted:
            raise ValueError("System.map lacks required kernel symbols")
  '';

  kernelArtifactScript = package: extraValidation: ''
    ${elfParser}
    ${kernelParser}

    root = pathlib.Path("@out@")
    images = list((root / "boot").glob("vmlinuz-*"))
    if len(images) != 1:
        raise ValueError("kernel output does not contain one boot image")
    release = images[0].name.removeprefix("vmlinuz-")
    config_path = root / "boot" / ("config-" + release)
    map_path = root / "boot" / ("System.map-" + release)
    vmlinux_path = pathlib.Path("@output:vmlinux@/boot") / ("vmlinux-" + release)

    elf_type, machine, sections = parse_elf(vmlinux_path)
    if elf_type != 2 or machine not in (62, 183) or ".text" not in sections:
        raise ValueError("vmlinux is not an executable kernel ELF")
    parse_boot_image(images[0], machine)
    validate_symbol_map(map_path)
    settings = parse_config(config_path.read_text())
    ${extraValidation}
    print("${package} artifact passed")
  '';

  malformedBootScript = package: ''
    ${kernelParser}

    source = next(pathlib.Path("@out@/boot").glob("vmlinuz-*"))
    malformed = pathlib.Path("malformed-vmlinuz")
    header = bytearray(source.open("rb").read(0x240))
    if header[0x202:0x206] == b"HdrS":
        header[0x202:0x206] = b"bad!"
        machine = 62
    else:
        header[0x38:0x3c] = bytes(4)
        machine = 183
    malformed.write_bytes(header)
    try:
        parse_boot_image(malformed, machine)
    except ValueError:
        import sys
        sys.stderr.write("${package} rejected malformed artifact\n")
        raise SystemExit(7)
    raise RuntimeError("malformed boot image was accepted")
  '';
in {
  linux = mkPythonProbe {
    package = "linux";
    primaryInput = "The packaged boot image, kernel config, symbol map, module tree, and separate vmlinux output.";
    primaryOperation = "Parse the boot and ELF headers, validate the symbol map, and inspect loadable kernel modules.";
    primaryExpected = "The outputs form one architecture-consistent bootable kernel release with valid ELF modules.";
    primaryScript = kernelArtifactScript "linux" ''
      if settings.get("CONFIG_MODULES") != "y":
          raise ValueError("runtime kernel does not enable modules")
      module_root = root / "lib/modules" / release
      modules = list(module_root.rglob("*.ko"))
      if not modules:
          raise ValueError("runtime kernel has no loadable modules")
      for module in modules:
          module_type, module_machine, _module_sections = parse_elf(module)
          if module_type != 1 or module_machine != machine:
              raise ValueError("kernel module has an incompatible ELF identity")
    '';
    badInput = "A copy of the packaged boot image with its architecture header corrupted.";
    badOperation = "Parse the malformed copy with the architecture-specific boot-image validator.";
    badExpected = "The validator rejects the image before treating its payload as bootable.";
    badScript = malformedBootScript "linux";
  };

  linux-crucible = mkPythonProbe {
    package = "linux-crucible";
    primaryInput = "The Crucible fixture kernel image, vmlinux, symbol map, and resolved built-in-only configuration.";
    primaryOperation = "Parse the image formats and enforce the fixture's virtio, 9p, ext4, and no-module contracts.";
    primaryExpected = "The fixture is a bootable kernel whose required guest devices are built in and whose module tree is empty.";
    primaryScript = kernelArtifactScript "linux-crucible" ''
      required_builtin = [
          "CONFIG_VIRTIO", "CONFIG_VIRTIO_PCI", "CONFIG_VIRTIO_BLK",
          "CONFIG_VIRTIO_NET", "CONFIG_NET_9P", "CONFIG_NET_9P_VIRTIO",
          "CONFIG_9P_FS", "CONFIG_EXT4_FS",
      ]
      if any(settings.get(name) != "y" for name in required_builtin):
          raise ValueError("Crucible kernel lacks a required built-in feature")
      if settings.get("CONFIG_MODULES", "n") != "n" or settings.get("CONFIG_KMOD", "n") != "n":
          raise ValueError("Crucible kernel unexpectedly supports loadable modules")
      if list((root / "lib/modules").rglob("*.ko")):
          raise ValueError("Crucible output unexpectedly contains a module")
    '';
    badInput = "The resolved fixture config plus a contradictory CONFIG_MODULES assignment.";
    badOperation = "Parse the contradictory Kconfig document with the same strict config parser.";
    badExpected = "The parser rejects the duplicate setting instead of accepting an ambiguous fixture contract.";
    badScript = ''
      ${kernelParser}

      config = next(pathlib.Path("@out@/boot").glob("config-*")).read_text()
      try:
          parse_config(config + "\nCONFIG_MODULES=y\n")
      except ValueError:
          import sys
          sys.stderr.write("linux-crucible rejected malformed artifact\n")
          raise SystemExit(7)
      raise RuntimeError("contradictory kernel config was accepted")
    '';
  };

  linux-headers = testing.mkQualificationPackageProbe {
    name = "linux-headers";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "linux-headers";
      primary = {
        input = "A seccomp BPF consumer with compile-time checks for the published Linux UAPI layout and constants.";
        operation = "Compile the consumer using only the packaged sanitized kernel headers.";
        expected = "The headers provide a self-consistent seccomp, audit, and socket-filter userspace ABI.";
        files."consumer.c" = ''
          #include <linux/filter.h>
          #include <linux/seccomp.h>

          _Static_assert(SECCOMP_MODE_FILTER == 2, "seccomp filter ABI changed");
          _Static_assert(SECCOMP_RET_ALLOW == 0x7fff0000U, "seccomp allow action changed");
          _Static_assert(sizeof(struct seccomp_data) == 64, "seccomp_data ABI size changed");

          static struct sock_filter filter[] = {
              BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
              BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_RET_ALLOW, 0, 1),
              BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
          };

          int main(void) {
              return filter[0].code == (BPF_LD | BPF_W | BPF_ABS) ? 0 : 1;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "-nostdinc" "-isystem" "@out@/include" "-Wall" "-Werror" "-c" "consumer.c" "-o" "consumer.o"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" ''
              data = open("consumer.o", "rb").read(20)
              assert data[:4] == bytes([0x7f]) + b"ELF" and data[16:18] == bytes([1, 0])
              print("linux-headers artifact passed")
            ''];
            exit_code = 0;
            stdout.exact = "linux-headers artifact passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A consumer asserting a one-byte seccomp_data layout that contradicts the published UAPI.";
        operation = "Compile the malformed ABI expectation against the packaged sanitized headers.";
        expected = "The C compiler rejects the incompatible structure-size assertion.";
        files."consumer.c" = ''
          #include <linux/seccomp.h>
          _Static_assert(sizeof(struct seccomp_data) == 1, "malformed seccomp ABI expectation");
        '';
        steps = [
          {
            argv = ["@cc@" "-nostdinc" "-isystem" "@out@/include" "-Wall" "-Werror" "-c" "consumer.c" "-o" "consumer.o"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  nvidia-gsp-firmware = mkPythonProbe {
    package = "nvidia-gsp-firmware";
    primaryInput = "The GA10x and TU10x signed GSP firmware containers.";
    primaryOperation = "Parse each RISC-V ELF container and validate its firmware image, version, build ID, and signature sections.";
    primaryExpected = "Both GPU-family artifacts are complete ELF firmware containers for the packaged driver version with distinct build IDs.";
    primaryScript = ''
      ${elfParser}

      firmware_roots = list(pathlib.Path("@out@/lib/firmware/nvidia").iterdir())
      if len(firmware_roots) != 1 or not firmware_roots[0].is_dir():
          raise ValueError("firmware output does not contain one version")
      version = firmware_roots[0].name
      names = ["gsp_ga10x.bin", "gsp_tu10x.bin"]
      build_ids = []
      for name in names:
          path = firmware_roots[0] / name
          elf_type, machine, sections = parse_elf(path)
          if elf_type != 1 or machine != 243:
              raise ValueError("GSP container is not relocatable RISC-V ELF")
          required = {".fwimage", ".fwversion", ".note.gnu.build-id", ".symtab", ".strtab"}
          if not required.issubset(sections):
              raise ValueError("GSP container lacks a required section")
          if sections[".fwimage"][1] < 1024 * 1024:
              raise ValueError("GSP firmware image is implausibly short")
          if read_section(path, sections[".fwversion"]) != version.encode() + b"\0":
              raise ValueError("GSP firmware version does not match its package directory")

          signatures = [section for section in sections if section.startswith(".fwsignature_")]
          if not signatures or any(sections[section][1] != 4096 for section in signatures):
              raise ValueError("GSP container lacks a complete signature record")
          note = read_section(path, sections[".note.gnu.build-id"])
          if len(note) != 36 or struct.unpack_from("<III", note)[0:3] != (4, 20, 3) or note[12:16] != b"GNU\0":
              raise ValueError("GSP container has an invalid GNU build ID")
          build_ids.append(note[16:36])
      if len(set(build_ids)) != 2:
          raise ValueError("GPU-family firmware containers share a build ID")
      print("nvidia-gsp-firmware artifact passed")
    '';
    badInput = "A truncated copy of one packaged GSP ELF container.";
    badOperation = "Parse the copy with the same bounded ELF section-table parser.";
    badExpected = "The parser rejects the container because its declared section table lies beyond the truncated input.";
    badScript = ''
      ${elfParser}

      source = next(pathlib.Path("@out@/lib/firmware/nvidia").rglob("gsp_ga10x.bin"))
      malformed = pathlib.Path("truncated-gsp.bin")
      malformed.write_bytes(source.open("rb").read(64))
      try:
          parse_elf(malformed)
      except ValueError:
          import sys
          sys.stderr.write("nvidia-gsp-firmware rejected malformed artifact\n")
          raise SystemExit(7)
      raise RuntimeError("truncated GSP container was accepted")
    '';
  };

  nvidia-open = mkPythonProbe {
    package = "nvidia-open";
    primaryInput = "The NVIDIA DRM, modeset, peer-memory, UVM, and core kernel modules built for the staged kernel.";
    primaryOperation = "Parse every module as relocatable ELF and validate its module metadata against the installed kernel release.";
    primaryExpected = "All five expected x86-64 modules carry license and matching vermagic metadata.";
    primaryScript = ''
      ${elfParser}

      module_roots = list(pathlib.Path("@out@/lib/modules").iterdir())
      if len(module_roots) != 1 or not module_roots[0].is_dir():
          raise ValueError("module output does not contain one kernel release")
      release = module_roots[0].name
      modules = {path.name: path for path in module_roots[0].rglob("*.ko")}
      expected = {"nvidia.ko", "nvidia-drm.ko", "nvidia-modeset.ko", "nvidia-peermem.ko", "nvidia-uvm.ko"}
      if set(modules) != expected:
          raise ValueError("NVIDIA output has an unexpected module set")
      for path in modules.values():
          elf_type, machine, sections = parse_elf(path)
          if elf_type != 1 or machine != 62 or ".modinfo" not in sections:
              raise ValueError("NVIDIA module has an invalid ELF identity")
          records = set(read_section(path, sections[".modinfo"]).rstrip(b"\0").split(b"\0"))
          vermagic = [record for record in records if record.startswith(b"vermagic=")]
          licenses = [record for record in records if record.startswith(b"license=")]
          if len(vermagic) != 1 or vermagic[0].split(b"=", 1)[1].split(b" ", 1)[0].decode() != release:
              raise ValueError("NVIDIA module vermagic does not match its release directory")
          if len(licenses) != 1 or not licenses[0].split(b"=", 1)[1]:
              raise ValueError("NVIDIA module lacks license metadata")
      print("nvidia-open artifact passed")
    '';
    badInput = "A truncated copy of one packaged NVIDIA kernel module.";
    badOperation = "Parse the copy with the same bounded ELF section-table parser.";
    badExpected = "The parser rejects the module before accepting any modinfo metadata.";
    badScript = ''
      ${elfParser}

      source = next(pathlib.Path("@out@/lib/modules").rglob("nvidia.ko"))
      malformed = pathlib.Path("truncated-nvidia.ko")
      malformed.write_bytes(source.open("rb").read(63))
      try:
          parse_elf(malformed)
      except ValueError:
          import sys
          sys.stderr.write("nvidia-open rejected malformed artifact\n")
          raise SystemExit(7)
      raise RuntimeError("truncated NVIDIA module was accepted")
    '';
  };
}
