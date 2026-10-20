{
  lib,
  stdenv,
  linuxFixtureWith,
}: let
  fixturePlatform =
    {
      "x86_64-linux" = {
        console = "ttyS0";
        serialConfig = ''
          CONFIG_SERIAL_8250=y
          CONFIG_SERIAL_8250_CONSOLE=y
        '';
      };
      "aarch64-linux" = {
        console = "ttyAMA0";
        serialConfig = ''
          CONFIG_SERIAL_AMBA_PL011=y
          CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
        '';
      };
    }
    .${
      stdenv.hostPlatform.system
    }
    or (throw "linux-crucible: unsupported system '${stdenv.hostPlatform.system}'");
  extraConfig = ''
    # Crucible test fixture kernel. This is deliberately a STOCK kernel: it
    # carries only functional additions needed to run the shipped test guests
    # (serial console, virtio transports, 9p, ext4) and a couple of deployment
    # simplifications (built-in-only). It contains NO determinism
    # shaping of any kind. Crucible's determinism is entirely host-side (QEMU
    # icount plus a seeded entropy source); no guest kernel config or cmdline
    # may be load-bearing for reproducibility. User guests keep supplying their
    # own, entirely unmodified, kernels.
    ${fixturePlatform.serialConfig}
    CONFIG_VIRTIO=y
    CONFIG_VIRTIO_PCI=y
    CONFIG_VIRTIO_PCI_LEGACY=y
    CONFIG_VIRTIO_BLK=y
    CONFIG_VIRTIO_NET=y
    CONFIG_VIRTIO_CONSOLE=y
    CONFIG_IOMMU_SUPPORT=y
    CONFIG_VIRTIO_IOMMU=y
    CONFIG_ACPI=y
    CONFIG_ACPI_VIOT=y
    CONFIG_UEVENT_HELPER=y
    CONFIG_UEVENT_HELPER_PATH=""
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_EXT4_FS=y

    # CONFIG_MODULES is not set
    # CONFIG_KMOD is not set
  '';

  fixtureKernelParams = [
    "console=${fixturePlatform.console}"
    "reboot=k"
    "panic=1"
    "root=/dev/vda"
    "ro"
    "net.ifnames=0"
  ];
  kernel = (linuxFixtureWith extraConfig).overrideAttrs (prev: {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "linux-crucible";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The fixture is a bootable kernel whose required guest devices are built in and whose module tree is empty.";
        "files" = {};
        "input" = "The Crucible fixture kernel image, vmlinux, symbol map, and resolved built-in-only configuration.";
        "operation" = "Parse the image formats and enforce the fixture's virtio, 9p, ext4, and no-module contracts.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\nimport pathlib, re, struct\n\ndef parse_boot_image(path, machine):\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(0x240)\n    if machine == 62:\n        if len(header) < 0x20a or header[0x1fe:0x200] != bytes.fromhex(\"55aa\"):\n            raise ValueError(\"invalid x86 boot sector\")\n        if header[0x202:0x206] != b\"HdrS\" or struct.unpack_from(\"<H\", header, 0x206)[0] < 0x020b:\n            raise ValueError(\"invalid x86 boot protocol\")\n        setup_sectors = header[0x1f1] or 4\n        if size <= (setup_sectors + 1) * 512:\n            raise ValueError(\"x86 kernel payload is truncated\")\n    elif machine == 183:\n        if len(header) < 64 or struct.unpack_from(\"<I\", header, 0x38)[0] != 0x644d5241:\n            raise ValueError(\"invalid arm64 Image header\")\n        image_size = struct.unpack_from(\"<Q\", header, 0x10)[0]\n        if image_size and size < image_size:\n            raise ValueError(\"arm64 kernel payload is truncated\")\n    else:\n        raise ValueError(\"unsupported kernel architecture\")\n\ndef parse_config(text):\n    settings = {}\n    assignment = re.compile(r\"^(CONFIG_[A-Z0-9_]+)=(.*)$\")\n    disabled = re.compile(r\"^# (CONFIG_[A-Z0-9_]+) is not set$\")\n    for line in text.splitlines():\n        match = assignment.fullmatch(line) or disabled.fullmatch(line)\n        if match is None:\n            continue\n        name = match.group(1)\n        if name in settings:\n            raise ValueError(\"kernel config repeats \" + name)\n        settings[name] = match.group(2) if line[0] != \"#\" else \"n\"\n    if not settings:\n        raise ValueError(\"kernel config contains no settings\")\n    return settings\n\ndef validate_symbol_map(path):\n    wanted = {\"_text\", \"linux_banner\"}\n    previous = -1\n    with path.open() as lines:\n        for line in lines:\n            fields = line.rstrip(\"\\n\").split(\" \", 2)\n            if len(fields) != 3 or len(fields[1]) != 1:\n                raise ValueError(\"malformed System.map record\")\n            address = int(fields[0], 16)\n            if address < previous:\n                raise ValueError(\"System.map is not address ordered\")\n            previous = address\n            wanted.discard(fields[2])\n    if wanted:\n        raise ValueError(\"System.map lacks required kernel symbols\")\n\n\nroot = pathlib.Path(\"@out@\")\nimages = list((root / \"boot\").glob(\"vmlinuz-*\"))\nif len(images) != 1:\n    raise ValueError(\"kernel output does not contain one boot image\")\nrelease = images[0].name.removeprefix(\"vmlinuz-\")\nconfig_path = root / \"boot\" / (\"config-\" + release)\nmap_path = root / \"boot\" / (\"System.map-\" + release)\nvmlinux_path = pathlib.Path(\"@output:vmlinux@/boot\") / (\"vmlinux-\" + release)\n\nelf_type, machine, sections = parse_elf(vmlinux_path)\nif elf_type != 2 or machine not in (62, 183) or \".text\" not in sections:\n    raise ValueError(\"vmlinux is not an executable kernel ELF\")\nparse_boot_image(images[0], machine)\nvalidate_symbol_map(map_path)\nsettings = parse_config(config_path.read_text())\nrequired_builtin = [\n    \"CONFIG_VIRTIO\", \"CONFIG_VIRTIO_PCI\", \"CONFIG_VIRTIO_BLK\",\n    \"CONFIG_VIRTIO_NET\", \"CONFIG_NET_9P\", \"CONFIG_NET_9P_VIRTIO\",\n    \"CONFIG_9P_FS\", \"CONFIG_EXT4_FS\",\n]\nif any(settings.get(name) != \"y\" for name in required_builtin):\n    raise ValueError(\"Crucible kernel lacks a required built-in feature\")\nif settings.get(\"CONFIG_MODULES\", \"n\") != \"n\" or settings.get(\"CONFIG_KMOD\", \"n\") != \"n\":\n    raise ValueError(\"Crucible kernel unexpectedly supports loadable modules\")\nif list((root / \"lib/modules\").rglob(\"*.ko\")):\n    raise ValueError(\"Crucible output unexpectedly contains a module\")\n\nprint(\"linux-crucible artifact passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "linux-crucible artifact passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The parser rejects the duplicate setting instead of accepting an ambiguous fixture contract.";
        "files" = {};
        "input" = "The resolved fixture config plus a contradictory CONFIG_MODULES assignment.";
        "operation" = "Parse the contradictory Kconfig document with the same strict config parser.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, re, struct\n\ndef parse_boot_image(path, machine):\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(0x240)\n    if machine == 62:\n        if len(header) < 0x20a or header[0x1fe:0x200] != bytes.fromhex(\"55aa\"):\n            raise ValueError(\"invalid x86 boot sector\")\n        if header[0x202:0x206] != b\"HdrS\" or struct.unpack_from(\"<H\", header, 0x206)[0] < 0x020b:\n            raise ValueError(\"invalid x86 boot protocol\")\n        setup_sectors = header[0x1f1] or 4\n        if size <= (setup_sectors + 1) * 512:\n            raise ValueError(\"x86 kernel payload is truncated\")\n    elif machine == 183:\n        if len(header) < 64 or struct.unpack_from(\"<I\", header, 0x38)[0] != 0x644d5241:\n            raise ValueError(\"invalid arm64 Image header\")\n        image_size = struct.unpack_from(\"<Q\", header, 0x10)[0]\n        if image_size and size < image_size:\n            raise ValueError(\"arm64 kernel payload is truncated\")\n    else:\n        raise ValueError(\"unsupported kernel architecture\")\n\ndef parse_config(text):\n    settings = {}\n    assignment = re.compile(r\"^(CONFIG_[A-Z0-9_]+)=(.*)$\")\n    disabled = re.compile(r\"^# (CONFIG_[A-Z0-9_]+) is not set$\")\n    for line in text.splitlines():\n        match = assignment.fullmatch(line) or disabled.fullmatch(line)\n        if match is None:\n            continue\n        name = match.group(1)\n        if name in settings:\n            raise ValueError(\"kernel config repeats \" + name)\n        settings[name] = match.group(2) if line[0] != \"#\" else \"n\"\n    if not settings:\n        raise ValueError(\"kernel config contains no settings\")\n    return settings\n\ndef validate_symbol_map(path):\n    wanted = {\"_text\", \"linux_banner\"}\n    previous = -1\n    with path.open() as lines:\n        for line in lines:\n            fields = line.rstrip(\"\\n\").split(\" \", 2)\n            if len(fields) != 3 or len(fields[1]) != 1:\n                raise ValueError(\"malformed System.map record\")\n            address = int(fields[0], 16)\n            if address < previous:\n                raise ValueError(\"System.map is not address ordered\")\n            previous = address\n            wanted.discard(fields[2])\n    if wanted:\n        raise ValueError(\"System.map lacks required kernel symbols\")\n\n\nconfig = next(pathlib.Path(\"@out@/boot\").glob(\"config-*\")).read_text()\ntry:\n    parse_config(config + \"\\nCONFIG_MODULES=y\\n\")\nexcept ValueError:\n    import sys\n    sys.stderr.write(\"linux-crucible rejected malformed artifact\\n\")\n    raise SystemExit(7)\nraise RuntimeError(\"contradictory kernel config was accepted\")\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "linux-crucible rejected malformed artifact\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    passthru =
      (prev.passthru or {})
      // {
        crucibleExtraConfig = extraConfig;
        crucibleFixtureConsole = fixturePlatform.console;
        crucibleFixtureKernelParams = fixtureKernelParams;
        crucibleFixtureKernelCmdline = lib.concatStringsSep " " fixtureKernelParams;
        crucibleDeterminismMechanism = "host-side-qemu-icount-seeded-entropy";
        crucibleFixtureOnly = true;
      };
    meta =
      (prev.meta or {})
      // {
        description = "Linux kernel fixture for Crucible determinism gates";
      };
  });
in
  kernel
  // {
    passthru =
      (kernel.passthru or {})
      // {
        aos =
          (kernel.passthru.aos or {})
          // {
            maintenance = kernel.passthru.aos.maintenance // {members = ["linux-crucible"];};
          };
      };
  }
