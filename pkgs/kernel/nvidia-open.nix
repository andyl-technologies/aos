##! NVIDIA open GPU kernel modules
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  perl,
  kmod,
  elfutils,
  dwarves,
  linux,
  kernel ? linux,
}: let
  version = "610.43.02";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "All five expected x86-64 modules carry license and matching vermagic metadata.";
      "files" = {};
      "input" = "The NVIDIA DRM, modeset, peer-memory, UVM, and core kernel modules built for the staged kernel.";
      "operation" = "Parse every module as relocatable ELF and validate its module metadata against the installed kernel release.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\n\nmodule_roots = list(pathlib.Path(\"@out@/lib/modules\").iterdir())\nif len(module_roots) != 1 or not module_roots[0].is_dir():\n    raise ValueError(\"module output does not contain one kernel release\")\nrelease = module_roots[0].name\nmodules = {path.name: path for path in module_roots[0].rglob(\"*.ko\")}\nexpected = {\"nvidia.ko\", \"nvidia-drm.ko\", \"nvidia-modeset.ko\", \"nvidia-peermem.ko\", \"nvidia-uvm.ko\"}\nif set(modules) != expected:\n    raise ValueError(\"NVIDIA output has an unexpected module set\")\nfor path in modules.values():\n    elf_type, machine, sections = parse_elf(path)\n    if elf_type != 1 or machine != 62 or \".modinfo\" not in sections:\n        raise ValueError(\"NVIDIA module has an invalid ELF identity\")\n    records = set(read_section(path, sections[\".modinfo\"]).rstrip(b\"\\0\").split(b\"\\0\"))\n    vermagic = [record for record in records if record.startswith(b\"vermagic=\")]\n    licenses = [record for record in records if record.startswith(b\"license=\")]\n    if len(vermagic) != 1 or vermagic[0].split(b\"=\", 1)[1].split(b\" \", 1)[0].decode() != release:\n        raise ValueError(\"NVIDIA module vermagic does not match its release directory\")\n    if len(licenses) != 1 or not licenses[0].split(b\"=\", 1)[1]:\n        raise ValueError(\"NVIDIA module lacks license metadata\")\nprint(\"nvidia-open artifact passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "nvidia-open artifact passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The parser rejects the module before accepting any modinfo metadata.";
      "files" = {};
      "input" = "A truncated copy of one packaged NVIDIA kernel module.";
      "operation" = "Parse the copy with the same bounded ELF section-table parser.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\n\nsource = next(pathlib.Path(\"@out@/lib/modules\").rglob(\"nvidia.ko\"))\nmalformed = pathlib.Path(\"truncated-nvidia.ko\")\nmalformed.write_bytes(source.open(\"rb\").read(63))\ntry:\n    parse_elf(malformed)\nexcept ValueError:\n    import sys\n    sys.stderr.write(\"nvidia-open rejected malformed artifact\\n\")\n    raise SystemExit(7)\nraise RuntimeError(\"truncated NVIDIA module was accepted\")\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "nvidia-open rejected malformed artifact\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

    pname = "nvidia-open-kernel-modules";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-Yvu+KVJ+ML4yyzizDfrS6U2xyof3elgJDlY8dmmFfmA=";
    };

    buildDeps = [gnumake bash perl kmod elfutils dwarves];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [kernel.dev];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd open-gpu-kernel-modules-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export KCFLAGS="''${KCFLAGS:-} -ffile-prefix-map=${kernel.dev}=/build/kernel-sdk"
          make -j"$NIX_BUILD_CORES" modules \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=x86_64 ARCH=x86_64 \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
        '';
      }
      {
        name = "install";
        script = ''
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j"$NIX_BUILD_CORES" modules_install \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=x86_64 ARCH=x86_64 \
            INSTALL_MOD_PATH="$out" \
            INSTALL_MOD_STRIP=1 \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
          find "$out/lib/modules" -type l -delete
        '';
      }
    ];

    meta = {
      description = "Open NVIDIA GPU kernel modules built for the exact AOS kernel";
      homepage = "https://github.com/NVIDIA/open-gpu-kernel-modules";
      license = "MIT OR GPL-2.0-only";
    };

    passthru = {inherit kernel;};
  }
