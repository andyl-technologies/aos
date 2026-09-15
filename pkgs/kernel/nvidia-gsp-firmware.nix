##! NVIDIA GSP firmware matched to the open kernel modules
{
  lib,
  mkDerivation,
  fetchurl,
  bash,
  zstd,
}: let
  version = "610.43.02";
in
  mkDerivation {
    pname = "nvidia-gsp-firmware";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Both GPU-family artifacts are complete ELF firmware containers for the packaged driver version with distinct build IDs.";
        "files" = {};
        "input" = "The GA10x and TU10x signed GSP firmware containers.";
        "operation" = "Parse each RISC-V ELF container and validate its firmware image, version, build ID, and signature sections.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\n\nfirmware_roots = list(pathlib.Path(\"@out@/lib/firmware/nvidia\").iterdir())\nif len(firmware_roots) != 1 or not firmware_roots[0].is_dir():\n    raise ValueError(\"firmware output does not contain one version\")\nversion = firmware_roots[0].name\nnames = [\"gsp_ga10x.bin\", \"gsp_tu10x.bin\"]\nbuild_ids = []\nfor name in names:\n    path = firmware_roots[0] / name\n    elf_type, machine, sections = parse_elf(path)\n    if elf_type != 1 or machine != 243:\n        raise ValueError(\"GSP container is not relocatable RISC-V ELF\")\n    required = {\".fwimage\", \".fwversion\", \".note.gnu.build-id\", \".symtab\", \".strtab\"}\n    if not required.issubset(sections):\n        raise ValueError(\"GSP container lacks a required section\")\n    if sections[\".fwimage\"][1] < 1024 * 1024:\n        raise ValueError(\"GSP firmware image is implausibly short\")\n    if read_section(path, sections[\".fwversion\"]) != version.encode() + b\"\\0\":\n        raise ValueError(\"GSP firmware version does not match its package directory\")\n\n    signatures = [section for section in sections if section.startswith(\".fwsignature_\")]\n    if not signatures or any(sections[section][1] != 4096 for section in signatures):\n        raise ValueError(\"GSP container lacks a complete signature record\")\n    note = read_section(path, sections[\".note.gnu.build-id\"])\n    if len(note) != 36 or struct.unpack_from(\"<III\", note)[0:3] != (4, 20, 3) or note[12:16] != b\"GNU\\0\":\n        raise ValueError(\"GSP container has an invalid GNU build ID\")\n    build_ids.append(note[16:36])\nif len(set(build_ids)) != 2:\n    raise ValueError(\"GPU-family firmware containers share a build ID\")\nprint(\"nvidia-gsp-firmware artifact passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "nvidia-gsp-firmware artifact passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The parser rejects the container because its declared section table lies beyond the truncated input.";
        "files" = {};
        "input" = "A truncated copy of one packaged GSP ELF container.";
        "operation" = "Parse the copy with the same bounded ELF section-table parser.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\n\nsource = next(pathlib.Path(\"@out@/lib/firmware/nvidia\").rglob(\"gsp_ga10x.bin\"))\nmalformed = pathlib.Path(\"truncated-gsp.bin\")\nmalformed.write_bytes(source.open(\"rb\").read(64))\ntry:\n    parse_elf(malformed)\nexcept ValueError:\n    import sys\n    sys.stderr.write(\"nvidia-gsp-firmware rejected malformed artifact\\n\")\n    raise SystemExit(7)\nraise RuntimeError(\"truncated GSP container was accepted\")\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "nvidia-gsp-firmware rejected malformed artifact\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://us.download.nvidia.com/XFree86/Linux-x86_64/${version}/NVIDIA-Linux-x86_64-${version}.run"
      ];
      hash = "sha256-MDSgVLtM33dS/43CclZMsQVROAS/9TU4lFkBsWyndGM=";
    };

    buildDeps = [bash zstd];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tail -n +1022 "$src" | zstd -d | tar -x -f - -- \
            firmware/gsp_ga10x.bin \
            firmware/gsp_tu10x.bin
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/firmware/nvidia/${version}"
          cp firmware/gsp_ga10x.bin firmware/gsp_tu10x.bin \
            "$out/lib/firmware/nvidia/${version}/"
        '';
      }
    ];

    meta = {
      description = "NVIDIA GSP firmware matched to open kernel modules ${version}";
      homepage = "https://www.nvidia.com/";
      license = "NVIDIA-Software-License";
    };
  }
