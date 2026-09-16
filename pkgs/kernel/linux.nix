##! Linux Kernel
{
  lib,
  mkDerivation,
  linuxSource,
  stdenv,
  buildPackages,
  gnumake,
  perl,
  bash,
  gawk,
  openssl,
  kmod,
  bison,
  flex,
  rsync,
  elfutils,
  bc,
  dwarves,
  patchelf,
  python3,
  zstd,
  # Optional: extra kernel config fragment text to merge after the base
  # config fragments. Like NixOS structuredExtraConfig but as raw kconfig text.
  extraConfig ? "",
  # Fixture kernels may intentionally omit the general system runtime contract.
  enforceRequiredConfig ? true,
}: let
  archMap = {
    "x86_64-linux" = {
      karch = "x86_64";
      target = "bzImage";
      imgPath = "arch/x86/boot/bzImage";
    };
    "aarch64-linux" = {
      karch = "arm64";
      target = "Image";
      imgPath = "arch/arm64/boot/Image";
    };
  };
  kernelArch =
    archMap.${stdenv.system}
    or (throw "linux: unsupported system '${stdenv.system}'");
  hostIncludePath = "${buildPackages.elfutils}/include:${buildPackages.openssl}/include:${buildPackages.zlib}/include";
  hostLibraryPath = "${buildPackages.elfutils}/lib:${buildPackages.openssl}/lib:${buildPackages.zlib}/lib";
  hostPkgConfigPath = "${buildPackages.elfutils}/lib/pkgconfig:${buildPackages.openssl}/lib/pkgconfig:${buildPackages.zlib}/lib/pkgconfig";
  kernelMakeFlags = ''
    ARCH=${kernelArch.karch} \
    CC="$CC" \
    LD="$LD" \
    AR="$AR" \
    NM="$NM" \
    OBJCOPY="${stdenv.binutils}/bin/objcopy" \
    OBJDUMP="${stdenv.binutils}/bin/objdump" \
    READELF="${stdenv.binutils}/bin/readelf" \
    STRIP="$STRIP" \
    HOSTCC="env C_INCLUDE_PATH=${hostIncludePath} LIBRARY_PATH=${hostLibraryPath} ${buildPackages.cc}/bin/cc" \
    HOSTCXX="env C_INCLUDE_PATH=${hostIncludePath} LIBRARY_PATH=${hostLibraryPath} ${buildPackages.cc}/bin/c++" \
    HOSTLD="${buildPackages.binutils}/bin/ld" \
    HOSTAR="${buildPackages.binutils}/bin/ar" \
    HOSTPKG_CONFIG="env PKG_CONFIG_PATH=${hostPkgConfigPath} ${buildPackages.pkg-config}/bin/pkg-config" \
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "linux";
    abilities = ./_linux-abilities;
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The outputs form one architecture-consistent bootable kernel release with valid ELF modules.";
        "files" = {};
        "input" = "The packaged boot image, kernel config, symbol map, module tree, and separate vmlinux output.";
        "operation" = "Parse the boot and ELF headers, validate the symbol map, and inspect loadable kernel modules.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, struct\n\ndef parse_elf(path):\n    path = pathlib.Path(path)\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(64)\n        if len(header) != 64 or header[:4] != bytes([0x7f]) + b\"ELF\":\n            raise ValueError(\"missing ELF64 header\")\n        if header[4:7] != bytes([2, 1, 1]):\n            raise ValueError(\"unsupported ELF encoding\")\n\n        elf_type, machine, version = struct.unpack_from(\"<HHI\", header, 16)\n        section_offset = struct.unpack_from(\"<Q\", header, 40)[0]\n        header_size, section_size, section_count, names_index = struct.unpack_from(\"<H4xHHH\", header, 52)\n        if version != 1 or header_size != 64 or section_size != 64:\n            raise ValueError(\"invalid ELF header dimensions\")\n        if section_count < 2 or names_index == 0 or names_index >= section_count:\n            raise ValueError(\"invalid ELF section indexes\")\n        if section_offset > size or section_count > (size - section_offset) // section_size:\n            raise ValueError(\"ELF section table extends beyond the artifact\")\n\n        stream.seek(section_offset)\n        raw_headers = stream.read(section_count * section_size)\n        headers = [\n            struct.unpack_from(\"<IIQQQQIIQQ\", raw_headers, index * section_size)\n            for index in range(section_count)\n        ]\n        names_header = headers[names_index]\n        names_offset, names_size = names_header[4], names_header[5]\n        if names_offset > size or names_size > size - names_offset:\n            raise ValueError(\"ELF section-name table extends beyond the artifact\")\n        stream.seek(names_offset)\n        names = stream.read(names_size)\n\n        sections = {}\n        for section in headers:\n            name_offset = section[0]\n            if name_offset >= len(names):\n                raise ValueError(\"ELF section name is out of range\")\n            name_end = names.find(b\"\\0\", name_offset)\n            if name_end < 0:\n                raise ValueError(\"ELF section name is unterminated\")\n            name = names[name_offset:name_end].decode(\"ascii\")\n            data_offset, data_size = section[4], section[5]\n            if section[1] != 8 and (data_offset > size or data_size > size - data_offset):\n                raise ValueError(\"ELF section extends beyond the artifact\")\n            if name in sections:\n                raise ValueError(\"ELF repeats a section name\")\n            sections[name] = (data_offset, data_size, section[1])\n\n    return elf_type, machine, sections\n\ndef read_section(path, section):\n    offset, size, _section_type = section\n    with pathlib.Path(path).open(\"rb\") as stream:\n        stream.seek(offset)\n        data = stream.read(size)\n    if len(data) != size:\n        raise ValueError(\"ELF section is truncated\")\n    return data\n\nimport pathlib, re, struct\n\ndef parse_boot_image(path, machine):\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(0x240)\n    if machine == 62:\n        if len(header) < 0x20a or header[0x1fe:0x200] != bytes.fromhex(\"55aa\"):\n            raise ValueError(\"invalid x86 boot sector\")\n        if header[0x202:0x206] != b\"HdrS\" or struct.unpack_from(\"<H\", header, 0x206)[0] < 0x020b:\n            raise ValueError(\"invalid x86 boot protocol\")\n        setup_sectors = header[0x1f1] or 4\n        if size <= (setup_sectors + 1) * 512:\n            raise ValueError(\"x86 kernel payload is truncated\")\n    elif machine == 183:\n        if len(header) < 64 or struct.unpack_from(\"<I\", header, 0x38)[0] != 0x644d5241:\n            raise ValueError(\"invalid arm64 Image header\")\n        image_size = struct.unpack_from(\"<Q\", header, 0x10)[0]\n        if image_size and size < image_size:\n            raise ValueError(\"arm64 kernel payload is truncated\")\n    else:\n        raise ValueError(\"unsupported kernel architecture\")\n\ndef parse_config(text):\n    settings = {}\n    assignment = re.compile(r\"^(CONFIG_[A-Z0-9_]+)=(.*)$\")\n    disabled = re.compile(r\"^# (CONFIG_[A-Z0-9_]+) is not set$\")\n    for line in text.splitlines():\n        match = assignment.fullmatch(line) or disabled.fullmatch(line)\n        if match is None:\n            continue\n        name = match.group(1)\n        if name in settings:\n            raise ValueError(\"kernel config repeats \" + name)\n        settings[name] = match.group(2) if line[0] != \"#\" else \"n\"\n    if not settings:\n        raise ValueError(\"kernel config contains no settings\")\n    return settings\n\ndef validate_symbol_map(path):\n    wanted = {\"_text\", \"linux_banner\"}\n    previous = -1\n    with path.open() as lines:\n        for line in lines:\n            fields = line.rstrip(\"\\n\").split(\" \", 2)\n            if len(fields) != 3 or len(fields[1]) != 1:\n                raise ValueError(\"malformed System.map record\")\n            address = int(fields[0], 16)\n            if address < previous:\n                raise ValueError(\"System.map is not address ordered\")\n            previous = address\n            wanted.discard(fields[2])\n    if wanted:\n        raise ValueError(\"System.map lacks required kernel symbols\")\n\n\nroot = pathlib.Path(\"@out@\")\nimages = list((root / \"boot\").glob(\"vmlinuz-*\"))\nif len(images) != 1:\n    raise ValueError(\"kernel output does not contain one boot image\")\nrelease = images[0].name.removeprefix(\"vmlinuz-\")\nconfig_path = root / \"boot\" / (\"config-\" + release)\nmap_path = root / \"boot\" / (\"System.map-\" + release)\nvmlinux_path = pathlib.Path(\"@output:vmlinux@/boot\") / (\"vmlinux-\" + release)\n\nelf_type, machine, sections = parse_elf(vmlinux_path)\nif elf_type != 2 or machine not in (62, 183) or \".text\" not in sections:\n    raise ValueError(\"vmlinux is not an executable kernel ELF\")\nparse_boot_image(images[0], machine)\nvalidate_symbol_map(map_path)\nsettings = parse_config(config_path.read_text())\nif settings.get(\"CONFIG_MODULES\") != \"y\":\n    raise ValueError(\"runtime kernel does not enable modules\")\nmodule_root = root / \"lib/modules\" / release\nmodules = list(module_root.rglob(\"*.ko\"))\nif not modules:\n    raise ValueError(\"runtime kernel has no loadable modules\")\nfor module in modules:\n    module_type, module_machine, _module_sections = parse_elf(module)\n    if module_type != 1 or module_machine != machine:\n        raise ValueError(\"kernel module has an incompatible ELF identity\")\n\nprint(\"linux artifact passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "linux artifact passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The validator rejects the image before treating its payload as bootable.";
        "files" = {};
        "input" = "A copy of the packaged boot image with its architecture header corrupted.";
        "operation" = "Parse the malformed copy with the architecture-specific boot-image validator.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, re, struct\n\ndef parse_boot_image(path, machine):\n    size = path.stat().st_size\n    with path.open(\"rb\") as stream:\n        header = stream.read(0x240)\n    if machine == 62:\n        if len(header) < 0x20a or header[0x1fe:0x200] != bytes.fromhex(\"55aa\"):\n            raise ValueError(\"invalid x86 boot sector\")\n        if header[0x202:0x206] != b\"HdrS\" or struct.unpack_from(\"<H\", header, 0x206)[0] < 0x020b:\n            raise ValueError(\"invalid x86 boot protocol\")\n        setup_sectors = header[0x1f1] or 4\n        if size <= (setup_sectors + 1) * 512:\n            raise ValueError(\"x86 kernel payload is truncated\")\n    elif machine == 183:\n        if len(header) < 64 or struct.unpack_from(\"<I\", header, 0x38)[0] != 0x644d5241:\n            raise ValueError(\"invalid arm64 Image header\")\n        image_size = struct.unpack_from(\"<Q\", header, 0x10)[0]\n        if image_size and size < image_size:\n            raise ValueError(\"arm64 kernel payload is truncated\")\n    else:\n        raise ValueError(\"unsupported kernel architecture\")\n\ndef parse_config(text):\n    settings = {}\n    assignment = re.compile(r\"^(CONFIG_[A-Z0-9_]+)=(.*)$\")\n    disabled = re.compile(r\"^# (CONFIG_[A-Z0-9_]+) is not set$\")\n    for line in text.splitlines():\n        match = assignment.fullmatch(line) or disabled.fullmatch(line)\n        if match is None:\n            continue\n        name = match.group(1)\n        if name in settings:\n            raise ValueError(\"kernel config repeats \" + name)\n        settings[name] = match.group(2) if line[0] != \"#\" else \"n\"\n    if not settings:\n        raise ValueError(\"kernel config contains no settings\")\n    return settings\n\ndef validate_symbol_map(path):\n    wanted = {\"_text\", \"linux_banner\"}\n    previous = -1\n    with path.open() as lines:\n        for line in lines:\n            fields = line.rstrip(\"\\n\").split(\" \", 2)\n            if len(fields) != 3 or len(fields[1]) != 1:\n                raise ValueError(\"malformed System.map record\")\n            address = int(fields[0], 16)\n            if address < previous:\n                raise ValueError(\"System.map is not address ordered\")\n            previous = address\n            wanted.discard(fields[2])\n    if wanted:\n        raise ValueError(\"System.map lacks required kernel symbols\")\n\n\nsource = next(pathlib.Path(\"@out@/boot\").glob(\"vmlinuz-*\"))\nmalformed = pathlib.Path(\"malformed-vmlinuz\")\nheader = bytearray(source.open(\"rb\").read(0x240))\nif header[0x202:0x206] == b\"HdrS\":\n    header[0x202:0x206] = b\"bad!\"\n    machine = 62\nelse:\n    header[0x38:0x3c] = bytes(4)\n    machine = 183\nmalformed.write_bytes(header)\ntry:\n    parse_boot_image(malformed, machine)\nexcept ValueError:\n    import sys\n    sys.stderr.write(\"linux rejected malformed artifact\\n\")\n    raise SystemExit(7)\nraise RuntimeError(\"malformed boot image was accepted\")\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "linux rejected malformed artifact\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit (linuxSource) version src;
    update = linuxSource.updateFor "linux";

    # `out` is the slim runtime kernel (compressed vmlinuz + modules). The
    # separate `vmlinux` output carries the uncompressed ELF that test VMMs
    # need (Firecracker cannot boot a compressed bzImage) — it is built here
    # anyway, so exposing it costs no extra build, and keeping it in its own
    # output means it never enters the production system closure (only a
    # test's closure, via lib/testing/vm.nix). See the install phase.
    outputs = ["out" "dev" "vmlinux"];

    buildDeps = [
      gnumake
      perl
      bash
      gawk
      openssl
      bison
      flex
      rsync
      elfutils
      bc
      dwarves
      patchelf
      python3
      zstd
    ];
    runtimeDeps = [kmod];
    propagatedDeps = [];

    # Kbuild owns the kernel's compiler and linker policy. The userspace
    # wrapper flags (PIE, Fortify, format, control-flow) are wrong for
    # kernel code, so opt out of the whole policy here.
    hardeningDisable = ["all"];

    # Path to kernel config fragments — these are merged before building.
    configDir = ./config;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-${linuxSource.version}
          for f in $(find . -type f -name '*.py'); do
            case "$(head -n 1 "$f")" in
              '#!'*python*) sed -i "1s|.*|#!${buildPackages.python3}/bin/python3|" "$f" ;;
            esac
          done
        '';
      }
      {
        name = "configure";
        script = ''
          # Start with a default config for the target architecture
          make ${kernelMakeFlags} defconfig

          # Merge our config fragments on top
          for frag in $configDir/*.config; do
            scripts/kconfig/merge_config.sh -m .config "$frag"
          done

          # Architecture-specific fragments (e.g. x86 IBT, arm64 PAC) live in
          # a per-arch subdirectory keyed by the kernel's ARCH name.
          for frag in "$configDir/${kernelArch.karch}"/*.config; do
            [ -e "$frag" ] || continue
            scripts/kconfig/merge_config.sh -m .config "$frag"
          done

          # Merge extra config from the system profile. Written via a
          # heredoc (not builtins.toFile, which rejects fragments that
          # reference a derivation — e.g. CONFIG_MODULE_SIG_KEY pointing at
          # a key in the store). The sed normalises leading whitespace,
          # since kconfig/merge_config silently ignore `CONFIG_x=...` lines
          # that aren't at column 0.
          ${
            if extraConfig != ""
            then ''
              cat > .extra-config << 'EXTRAEOF'
              ${extraConfig}
              EXTRAEOF
              sed -i 's/^[[:space:]]*//' .extra-config
              scripts/kconfig/merge_config.sh -m .config .extra-config
            ''
            else ""
          }

          # Finalize — fill in defaults for any new symbols
          make ${kernelMakeFlags} olddefconfig

          ${
            if enforceRequiredConfig
            then ''
              # These fragments describe runtime contracts rather than preferences.
              # Kconfig may silently discard an unavailable value, so fail the build
              # when a required symbol does not survive dependency resolution.
              for frag in "$configDir"/required-*.config "$configDir/${kernelArch.karch}"/required-*.config; do
                [ -e "$frag" ] || continue
                sed -n '/^CONFIG_[A-Z0-9_]*=[ym]$/p' "$frag" | while read -r requirement; do
                  if ! grep -qx "$requirement" .config; then
                    echo "required kernel setting was not resolved: $requirement" >&2
                    exit 1
                  fi
                done
              done
            ''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          # sorttable (host tool) uses pthreads; glibc's pthread_exit needs
          # libgcc_s.so.1 for stack unwinding at runtime. Other generated host
          # tools load libelf, OpenSSL, and zlib while producing the image.
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibraryPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j$NIX_BUILD_CORES ${kernelMakeFlags} ${kernelArch.target}
          if gawk '/^CONFIG_MODULES=y$/ { found = 1 } END { exit found ? 0 : 1 }' .config; then
            make -j$NIX_BUILD_CORES ${kernelMakeFlags} modules
          fi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/boot $out/lib/modules

          # Install kernel image (the self-decompressing, BTF-bearing image
          # the system actually boots).
          cp ${kernelArch.imgPath} $out/boot/vmlinuz-${linuxSource.version}
          cp System.map $out/boot/System.map-${linuxSource.version}
          cp .config $out/boot/config-${linuxSource.version}

          # NOTE: the unstripped `vmlinux` ELF (~480 MiB of DWARF, produced
          # because CONFIG_DEBUG_INFO_BTF requires CONFIG_DEBUG_INFO) is
          # deliberately NOT shipped in `out`. The running kernel exposes BTF
          # for eBPF CO-RE via /sys/kernel/btf/vmlinux from its in-memory .BTF
          # section; vmlinux is only needed at build time (pahole reads it to
          # embed BTF). Keeping it out of the runtime closure saves ~480 MiB.
          #
          # It IS placed in the separate `vmlinux` output for test VMMs:
          # Firecracker boots an uncompressed ELF, not the self-decompressing
          # bzImage. This output is referenced only by lib/testing/vm.nix, so
          # the production system closure (which references `out`) is unaffected.
          mkdir -p $vmlinux/boot
          cp vmlinux $vmlinux/boot/vmlinux-${linuxSource.version}

          # External modules must build against the exact configured kernel,
          # including generated headers, symbol versions, BTF tools, and any
          # deployment-specific signing policy. Keep that interface in a
          # separate output so ordinary systems do not retain the large build
          # tree merely to boot the runtime kernel.
          kernel_build=$dev/lib/modules/${linuxSource.version}/build
          mkdir -p "$kernel_build"
          cp -a . "$kernel_build/"
          rm -f "$kernel_build/${kernelArch.imgPath}"

          # Generated command metadata, object debugging records, and vmlinux
          # diagnostics can name the scheduler's cross compiler. Replace only
          # its fixed-size store hash so binary offsets and every permitted
          # runtime path stay intact.
          cross_compiler=${stdenv.cc.cc}
          cross_compiler_hash=''${cross_compiler#/nix/store/}
          cross_compiler_hash=''${cross_compiler_hash%%-*}
          scrubbed_hash=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
          reference_files="$TMPDIR/cross-compiler-reference-files"
          reference_scan_status=0
          find "$kernel_build" "$vmlinux" -type f \
            -exec grep -a -l -F "$cross_compiler" {} + \
            > "$reference_files" || reference_scan_status=$?
          if [ "$reference_scan_status" -gt 1 ]; then
            echo "failed to scan the kernel build tree for cross-compiler references" >&2
            exit "$reference_scan_status"
          fi
          while read -r generated_file; do
            sed -i "s|$cross_compiler_hash|$scrubbed_hash|g" "$generated_file"
          done < "$reference_files"

          # Kbuild's host helpers are part of the external-module interface.
          # Give helpers that use libelf an immutable runtime search path so
          # downstream module builds do not depend on ambient host libraries.
          find "$kernel_build/tools" "$kernel_build/scripts" -type f -perm -0100 | while read -r helper; do
            if patchelf --print-needed "$helper" 2>/dev/null | grep -qx libelf.so.1; then
              patchelf --set-rpath ${buildPackages.elfutils}/lib "$helper"
            fi
          done

          # Install modules only when the final config supports loadable
          # modules. Strip their DWARF; BTF stays in the kernel image.
          if gawk '/^CONFIG_MODULES=y$/ { found = 1 } END { exit found ? 0 : 1 }' .config; then
            make modules_install \
              ${kernelMakeFlags}INSTALL_MOD_PATH=$out \
              INSTALL_MOD_STRIP=1 \
              DEPMOD=${buildPackages.kmod}/sbin/depmod
          fi

          # External-module builders consume the explicit `dev` output. Keep
          # the runtime module tree independent so boot closures do not retain
          # the configured source tree or deployment signing inputs.
        '';
      }
    ];

    meta = {
      description = "Linux kernel — the operating system kernel";
      homepage = "https://www.kernel.org";
      license = "GPL-2.0-only";
    };
  }
