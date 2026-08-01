{
  pkgs,
  lib,
}: let
  root = ../..;
  rustFilesUnder = relativeRoot: let
    absoluteRoot = root + "/${relativeRoot}";
    entries = builtins.readDir absoluteRoot;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        relative = "${relativeRoot}/${name}";
      in
        if kind == "regular" && lib.hasSuffix ".rs" name
        then [relative]
        else if kind == "directory"
        then rustFilesUnder relative
        else []
    )
    (builtins.attrNames entries);
  launchRust =
    builtins.concatStringsSep "\n"
    (map (relative: builtins.readFile (root + "/${relative}"))
      (["crates/crucible-qemu/src/launch.rs"] ++ rustFilesUnder "crates/crucible-qemu/src/launch"));
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  kernelVirtualizationConfig = builtins.readFile ../../pkgs/kernel/config/virtualization.config;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  sourceRequirements = [
    {
      label = "scenario seed default";
      needle = "const DEFAULT_SCENARIO_SEED: u64 = 0x0010_c001;";
    }
    {
      label = "firmware seed item name";
      needle = "const GUEST_ENTROPY_FW_CFG_NAME: &str = \"opt/crucible/seed\";";
    }
    {
      label = "deterministic rng object id";
      needle = "const GUEST_ENTROPY_RNG_ID: &str = \"crucible-rng0\";";
    }
    {
      label = "raw seed file name";
      needle = "const GUEST_ENTROPY_SEED_FILE_NAME: &str = \"crucible-guest-entropy-seed.bin\";";
    }
    {
      label = "32 byte guest entropy seed";
      needle = "const GUEST_ENTROPY_SEED_BYTES: usize = 32;";
    }
    {
      label = "scenario seed stored on candidate";
      needle = "pub scenario_seed: u64,";
    }
    {
      label = "scenario seed builder";
      needle = "pub fn with_scenario_seed(mut self, scenario_seed: u64) -> Self";
    }
    {
      label = "scenario seed setter also updates run seed";
      needle = "self.run_seed = scenario_seed;";
    }
    {
      label = "run seed setter also updates scenario seed";
      needle = "self.scenario_seed = run_seed;";
    }
    {
      label = "split seed rejection";
      needle = "RunSeedDiffersFromScenarioSeed";
    }
    {
      label = "guest entropy seed derivation type";
      needle = "pub struct GuestEntropySeed";
    }
    {
      label = "guest entropy seed file artifact";
      needle = "pub struct GuestEntropySeedFile";
    }
    {
      label = "seed file materialization helper";
      needle = "pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> std::io::Result<PathBuf>";
    }
    {
      label = "guest entropy derives from scenario seed";
      needle = "pub fn from_scenario_seed(scenario_seed: u64) -> Self";
    }
    {
      label = "stable splitmix derivation";
      needle = "fn splitmix64(mut value: u64) -> u64";
    }
    {
      label = "guest entropy seed stored on profile";
      needle = "guest_entropy_seed: GuestEntropySeed,";
    }
    {
      label = "guest entropy computed during validation";
      needle = "GuestEntropySeed::from_scenario_seed(self.scenario_seed)";
    }
    {
      label = "firmware seed launch flag";
      needle = "\"-fw_cfg\".to_owned(),";
    }
    {
      label = "firmware seed launch payload";
      needle = "seed_file.file_name()";
    }
    {
      label = "deterministic rng-builtin object";
      needle = "format!(\"rng-builtin,id={GUEST_ENTROPY_RNG_ID}\")";
    }
    {
      label = "deterministic virtio-rng device";
      needle = "format!(\"virtio-rng-pci,rng={GUEST_ENTROPY_RNG_ID}\")";
    }
    {
      label = "hardware entropy disabled in CPU";
      needle = "reject_enabled_entropy_feature(&lower, \"rdrand\")?";
    }
    {
      label = "rdseed disabled in CPU";
      needle = "reject_enabled_entropy_feature(&lower, \"rdseed\")?";
    }
    {
      label = "stock guest cmdline default (entropy sealed host-side, not via cmdline trust flags)";
      needle = "const DEFAULT_KERNEL_CMDLINE: &str = \"console=ttyS0 reboot=k panic=1 quiet\";";
    }
    {
      label = "scenario seed in hash material";
      needle = "format!(\"scenario_seed={}\", self.scenario_seed),";
    }
    {
      label = "guest entropy fw_cfg name in hash material";
      needle = "format!(\"guest_entropy_fw_cfg_name={GUEST_ENTROPY_FW_CFG_NAME}\"),";
    }
    {
      label = "guest entropy seed file in hash material";
      needle = "format!(\"guest_entropy_seed_file_name={GUEST_ENTROPY_SEED_FILE_NAME}\"),";
    }
    {
      label = "guest entropy seed source in hash material";
      needle = "\"guest_entropy_seed_source=scenario-seed\".to_owned(),";
    }
    {
      label = "guest entropy seed in hash material";
      needle = "guest_entropy_seed_hex={}";
    }
    {
      label = "deterministic rng scope in hash material";
      needle = "\"qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin\".to_owned(),";
    }
    {
      label = "host entropy sources disabled in hash material";
      needle = "\"guest_entropy_host_sources=disabled\".to_owned(),";
    }
  ];

  testRequirements = [
    {
      label = "fw_cfg argument assertion";
      needle = "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin";
    }
    {
      label = "rng-builtin argument assertion";
      needle = "[\"-object\", \"rng-builtin,id=crucible-rng0\"]";
    }
    {
      label = "virtio-rng argument assertion";
      needle = "[\"-device\", \"virtio-rng-pci,rng=crucible-rng0\"]";
    }
    {
      label = "guest entropy sealed host-side, not via guest cmdline trust flags";
      needle = "fn launch_profile_accepts_any_guest_kernel_cmdline()";
    }
    {
      label = "any guest cmdline validates with host-side seals intact";
      needle = "any guest cmdline must pass pre-spawn validation with host-side seals intact";
    }
    {
      label = "split seed rejected";
      needle = "LaunchProfileError::RunSeedDiffersFromScenarioSeed";
    }
    {
      label = "fw_cfg seed file binding test";
      needle = "launch_profile_binds_fw_cfg_file_to_guest_entropy_seed";
    }
    {
      label = "scenario seed hash assertion";
      needle = "scenario_seed=1097729";
    }
    {
      label = "guest entropy source hash assertion";
      needle = "guest_entropy_seed_source=scenario-seed";
    }
    {
      label = "guest entropy seed hex assertion";
      needle = "guest_entropy_seed_hex=";
    }
    {
      label = "guest entropy rng object assertion";
      needle = "guest_entropy_rng_object=rng-builtin,id=crucible-rng0";
    }
    {
      label = "guest entropy host source assertion";
      needle = "guest_entropy_host_sources=disabled";
    }
    {
      label = "scenario seed drift assertion";
      needle = "with_scenario_seed(0x1234)";
    }
    {
      label = "guest entropy seed derivation regression";
      needle = "guest_entropy_seed_is_scenario_seed_derived";
    }
    {
      label = "run seed unified with guest entropy assertion";
      needle = "the QEMU internal seed is unified with the guest CSPRNG scenario seed";
    }
  ];

  failures =
    failuresFor "crates/crucible-qemu/src/launch*.rs" launchRust sourceRequirements
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest testRequirements
    ++ failuresFor "pkgs/kernel/config/virtualization.config" kernelVirtualizationConfig [
      {
        label = "hardware RNG core";
        needle = "CONFIG_HW_RANDOM=y";
      }
      {
        label = "virtio hardware RNG";
        needle = "CONFIG_HW_RANDOM_VIRTIO=y";
      }
    ];

  probe = pkgs.mkDerivation {
    pname = "crucible-phase1-guest-entropy-probe";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-probe";
        script = ''
          mkdir -p "$out/bin"

          cat > guest-entropy-probe.c <<'PROBE_C'
          #include <errno.h>
          #include <fcntl.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <stdlib.h>
          #include <string.h>
          #include <sys/mount.h>
          #include <sys/reboot.h>
          #include <sys/stat.h>
          #include <unistd.h>

          enum {
            SEED_BYTES = 32,
            SAMPLE_BYTES = 32,
          };

          static uint64_t splitmix64(uint64_t value) {
            value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
            value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
            return value ^ (value >> 31);
          }

          static void derive_seed(uint64_t scenario_seed, unsigned char out[SEED_BYTES]) {
            uint64_t state = scenario_seed ^ 0x4352554349424c45ULL;

            for (size_t index = 0; index < SEED_BYTES / sizeof(uint64_t); index++) {
              uint64_t word;

              state += 0x9e3779b97f4a7c15ULL + index;
              word = splitmix64(state);
              memcpy(out + index * sizeof(word), &word, sizeof(word));
            }
          }

          static int mount_one(const char *source, const char *target, const char *type) {
            if (mkdir(target, 0755) != 0 && errno != EEXIST) {
              perror(target);
              return -1;
            }
            if (mount(source, target, type, 0, "") != 0 && errno != EBUSY) {
              perror(target);
              return -1;
            }
            return 0;
          }

          static int read_file_flags(const char *path, unsigned char *buf, size_t len,
                                     int flags) {
            int fd = open(path, O_RDONLY | flags);
            size_t offset = 0;

            if (fd < 0) {
              perror(path);
              return -1;
            }
            while (offset < len) {
              ssize_t n = read(fd, buf + offset, len - offset);
              if (n < 0) {
                perror(path);
                close(fd);
                return -1;
              }
              if (n == 0) {
                fprintf(stderr, "%s ended after %zu bytes\n", path, offset);
                close(fd);
                return -1;
              }
              offset += (size_t)n;
            }
            close(fd);
            return 0;
          }

          static int read_file(const char *path, unsigned char *buf, size_t len) {
            return read_file_flags(path, buf, len, 0);
          }

          static int read_file_nonblock(const char *path, unsigned char *buf, size_t len) {
            return read_file_flags(path, buf, len, O_NONBLOCK);
          }

          static int read_text(const char *path, char *buf, size_t len) {
            int fd = open(path, O_RDONLY);
            ssize_t n;

            if (fd < 0) {
              perror(path);
              return -1;
            }
            n = read(fd, buf, len - 1);
            if (n < 0) {
              perror(path);
              close(fd);
              return -1;
            }
            buf[n] = '\0';
            close(fd);
            return 0;
          }

          static int parse_cmdline_seed(uint64_t *seed) {
            char cmdline[4096];
            char *start;
            char *end;

            if (read_text("/proc/cmdline", cmdline, sizeof(cmdline)) != 0) {
              return -1;
            }
            start = strstr(cmdline, "crucible_seed=");
            if (start == NULL) {
              fputs("missing crucible_seed= on kernel cmdline\n", stderr);
              return -1;
            }
            start += strlen("crucible_seed=");
            errno = 0;
            *seed = strtoull(start, &end, 0);
            if (errno != 0 || end == start || (*end != '\0' && *end != ' ' && *end != '\n')) {
              fputs("invalid crucible_seed= on kernel cmdline\n", stderr);
              return -1;
            }
            /* D-31: the guest cmdline is stock. Determinism is sealed host-side
               (seeded fw_cfg entropy + rng-builtin, fixed -cpu without
               RDRAND/RDSEED, -icount), so the guest does not need to pin
               random.trust_* off. We only require the seed to be present. */
            return 0;
          }

          static int cpuinfo_excludes_host_entropy(void) {
            char cpuinfo[16384];

            if (read_text("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo)) != 0) {
              return -1;
            }
            if (strstr(cpuinfo, " rdrand") != NULL || strstr(cpuinfo, " rdseed") != NULL) {
              fputs("guest CPU exposes rdrand/rdseed\n", stderr);
              return -1;
            }
            puts("CPU_ENTROPY_FEATURES=rdrand-disabled,rdseed-disabled");
            return 0;
          }

          static void print_hex(const char *key, const unsigned char *buf, size_t len) {
            static const char digits[] = "0123456789abcdef";

            fputs(key, stdout);
            putchar('=');
            for (size_t i = 0; i < len; i++) {
              putchar(digits[buf[i] >> 4]);
              putchar(digits[buf[i] & 0x0f]);
            }
            putchar('\n');
          }

          int main(void) {
            static const char fw_cfg_seed[] =
                "/sys/firmware/qemu_fw_cfg/by_name/opt/crucible/seed/raw";
            unsigned char expected[SEED_BYTES];
            unsigned char actual[SEED_BYTES];
            unsigned char hwrng[SAMPLE_BYTES];
            unsigned char urandom[SAMPLE_BYTES];
            uint64_t seed;

            if (mount_one("proc", "/proc", "proc") != 0 ||
                mount_one("sysfs", "/sys", "sysfs") != 0 ||
                mount_one("devtmpfs", "/dev", "devtmpfs") != 0) {
              return 1;
            }
            if (parse_cmdline_seed(&seed) != 0 || cpuinfo_excludes_host_entropy() != 0) {
              return 1;
            }

            derive_seed(seed, expected);
            if (read_file(fw_cfg_seed, actual, sizeof(actual)) != 0) {
              return 1;
            }
            print_hex("EXPECTED_SEED_HEX", expected, sizeof(expected));
            print_hex("FW_CFG_SEED_HEX", actual, sizeof(actual));
            if (memcmp(expected, actual, sizeof(expected)) != 0) {
              fputs("fw_cfg seed does not match derived scenario seed\n", stderr);
              return 1;
            }
            puts("FW_CFG_SEED_MATCH=true");

            if (read_file_nonblock("/dev/hwrng", hwrng, sizeof(hwrng)) != 0) {
              return 1;
            }
            print_hex("HWRNG_HEX", hwrng, sizeof(hwrng));

            if (read_file("/dev/urandom", urandom, sizeof(urandom)) != 0) {
              return 1;
            }
            print_hex("URANDOM_HEX", urandom, sizeof(urandom));
            return 0;
          }
          PROBE_C

          cc -std=c11 -O2 -Wall -Wextra -Werror \
            guest-entropy-probe.c \
            -o "$out/bin/guest-entropy-probe"

          cat > crucible-httpget-workload.c <<'WORKLOAD_C'
          #include <errno.h>
          #include <fcntl.h>
          #include <stdio.h>
          #include <stdlib.h>
          #include <string.h>
          #include <unistd.h>

          enum { WORKLOAD_SAMPLE_BYTES = 32 };

          static int cmdline_value_is_exactly_once(
              const char *cmdline,
              const char *key,
              const char *expected) {
            size_t key_len = strlen(key);
            size_t expected_len = strlen(expected);
            int matches = 0;
            int bad_value = 0;
            const char *cursor = cmdline;

            while (*cursor != '\0') {
              while (*cursor == ' ' || *cursor == '\n' || *cursor == '\t') {
                cursor++;
              }

              const char *start = cursor;
              while (*cursor != '\0' && *cursor != ' ' && *cursor != '\n' && *cursor != '\t') {
                cursor++;
              }
              size_t len = (size_t)(cursor - start);

              if (len == key_len && memcmp(start, key, key_len) == 0) {
                matches++;
                bad_value = 1;
              } else if (
                  len > key_len &&
                  memcmp(start, key, key_len) == 0 &&
                  start[key_len] == '=') {
                const char *value = start + key_len + 1;
                size_t value_len = len - key_len - 1;

                matches++;
                if (value_len != expected_len || memcmp(value, expected, expected_len) != 0) {
                  bad_value = 1;
                }
              }
            }

            return matches == 1 && bad_value == 0 ? 0 : -1;
          }

          static int read_text(const char *path, char *buf, size_t len) {
            int fd = open(path, O_RDONLY);
            ssize_t n;

            if (fd < 0) {
              perror(path);
              return -1;
            }
            n = read(fd, buf, len - 1);
            if (n < 0) {
              perror(path);
              close(fd);
              return -1;
            }
            buf[n] = '\0';
            close(fd);
            return 0;
          }

          static int read_file(const char *path, unsigned char *buf, size_t len) {
            int fd = open(path, O_RDONLY);
            size_t offset = 0;

            if (fd < 0) {
              perror(path);
              return -1;
            }
            while (offset < len) {
              ssize_t n = read(fd, buf + offset, len - offset);
              if (n < 0) {
                perror(path);
                close(fd);
                return -1;
              }
              if (n == 0) {
                fprintf(stderr, "%s ended after %zu bytes\n", path, offset);
                close(fd);
                return -1;
              }
              offset += (size_t)n;
            }
            close(fd);
            return 0;
          }

          static void print_hex(const char *key, const unsigned char *buf, size_t len) {
            static const char digits[] = "0123456789abcdef";

            fputs(key, stdout);
            putchar('=');
            for (size_t i = 0; i < len; i++) {
              putchar(digits[buf[i] >> 4]);
              putchar(digits[buf[i] & 0x0f]);
            }
            putchar('\n');
          }

          int main(void) {
            unsigned char transcript[WORKLOAD_SAMPLE_BYTES];
            char cmdline[4096];

            if (read_text("/proc/cmdline", cmdline, sizeof(cmdline)) != 0) {
              return 1;
            }
            if (cmdline_value_is_exactly_once(cmdline, "crucible.workload", "httpget") != 0) {
              fputs("kernel cmdline does not select crucible.workload=httpget exactly once\n", stderr);
              return 1;
            }
            if (read_file("/dev/urandom", transcript, sizeof(transcript)) != 0) {
              return 1;
            }

            puts("WORKLOAD_BINARY=crucible-httpget-workload");
            puts("WORKLOAD=crucible.workload=httpget");
            print_hex("WORKLOAD_RNG_HEX", transcript, sizeof(transcript));
            puts("WORKLOAD_RESULT:PASS");
            return 0;
          }
          WORKLOAD_C

          cc -std=c11 -O2 -Wall -Wextra -Werror \
            crucible-httpget-workload.c \
            -o "$out/bin/crucible-httpget-workload"
        '';
      }
    ];
  };

  poweroffHelper = pkgs.mkDerivation {
    pname = "crucible-phase1-guest-entropy-poweroff";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-poweroff-helper";
        script = ''
          mkdir -p "$out/bin"

          cat > poweroff.c <<'POWEROFF_C'
          #include <stdio.h>
          #include <sys/reboot.h>
          #include <unistd.h>

          #ifndef RB_POWER_OFF
          #define RB_POWER_OFF 0x4321fedc
          #endif

          int main(void) {
            sync();
            if (reboot(RB_POWER_OFF) != 0) {
              perror("poweroff");
              return 1;
            }
            return 0;
          }
          POWEROFF_C

          cc poweroff.c -o "$out/bin/guest-entropy-poweroff"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      probe
      poweroffHelper
    ];
    depPaths = builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in [
          "${base}/bin"
          "${base}/sbin"
        ]
      )
      initramfsDeps
    );
    graphPairs =
      lib.concatLists
      (lib.imap (i: dep: [
          "closure-${builtins.toString i}"
          dep
        ])
        initramfsDeps);
  in
    pkgs.mkDerivation {
      pname = "crucible-phase1-guest-entropy-initramfs";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.cpio
        pkgs.pigz
      ];

      exportReferencesGraph = graphPairs;

      phases = [
        {
          name = "build-initramfs";
          script = ''
            set -eu

            grep -h '^/nix/store/' closure-* | sort -u > closure-paths

            mkdir -p root/bin root/sbin root/nix/store root/tmp root/proc root/sys root/dev root/run
            while IFS= read -r p; do
              cp -a "$p" root"$p"
            done < closure-paths

            ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
            ln -sfn ${pkgs.bash}/bin/bash root/bin/bash
            ln -sfn ${poweroffHelper}/bin/guest-entropy-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_GUEST_ENTROPY_READY"
            if guest-entropy-probe && crucible-httpget-workload; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
            poweroff
            INIT
            chmod +x root/init

            mkdir -p "$out"
            (
              cd root
              find . -print0 \
                | LC_ALL=C sort -z \
                | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
                | pigz -9 -n -p "''${NIX_BUILD_CORES:-1}" > "$out/initrd.img"
            )
          '';
        }
      ];
    };
in
  if failures != []
  then throw "crucible phase1 guest entropy launch check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-guest-entropy-launch";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.gawk
        pkgs.grep
        pkgs.qemu-crucible
      ];

      INITRAMFS = "${initramfs}/initrd.img";
      KERNEL = builtins.toString pkgs.linux;
      QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";

      phases = [
        {
          name = "run-guest-entropy-launch-probe";
          script = ''
            set -eu

            unset LD_LIBRARY_PATH || true

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            cat > write-seed.c <<'WRITE_SEED_C'
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            enum { SEED_BYTES = 32 };

            static uint64_t splitmix64(uint64_t value) {
              value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
              value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
              return value ^ (value >> 31);
            }

            static void derive_seed(uint64_t scenario_seed, unsigned char out[SEED_BYTES]) {
              uint64_t state = scenario_seed ^ 0x4352554349424c45ULL;

              for (size_t index = 0; index < SEED_BYTES / sizeof(uint64_t); index++) {
                uint64_t word;

                state += 0x9e3779b97f4a7c15ULL + index;
                word = splitmix64(state);
                memcpy(out + index * sizeof(word), &word, sizeof(word));
              }
            }

            int main(int argc, char **argv) {
              unsigned char seed[SEED_BYTES];
              uint64_t scenario_seed;
              FILE *out;

              if (argc != 3) {
                fprintf(stderr, "usage: %s <scenario-seed> <seed-file>\n", argv[0]);
                return 1;
              }

              scenario_seed = strtoull(argv[1], NULL, 0);
              derive_seed(scenario_seed, seed);

              out = fopen(argv[2], "wb");
              if (out == NULL) {
                perror(argv[2]);
                return 1;
              }
              if (fwrite(seed, 1, sizeof(seed), out) != sizeof(seed)) {
                perror(argv[2]);
                fclose(out);
                return 1;
              }
              fclose(out);

              for (size_t i = 0; i < sizeof(seed); i++) {
                printf("%02x", seed[i]);
              }
              putchar('\n');
              return 0;
            }
            WRITE_SEED_C

            cc -std=c11 -O2 -Wall -Wextra -Werror write-seed.c -o write-seed

            vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
            if [ -z "$vmlinuz" ]; then
              fail "no vmlinuz under $KERNEL/boot"
            fi

            jitter_pids=""
            start_jitter() {
              i=0
              while [ "$i" -lt 3 ]; do
                yes > /dev/null &
                jitter_pids="$jitter_pids $!"
                i=$((i + 1))
              done
            }

            stop_jitter() {
              for pid in $jitter_pids; do
                kill "$pid" 2>/dev/null || true
              done
              for pid in $jitter_pids; do
                wait "$pid" 2>/dev/null || true
              done
              jitter_pids=""
            }

            trap stop_jitter EXIT

            run_one() {
              label="$1"
              scenario_seed="$2"
              run_dir="$TMPDIR/run-$label"
              mkdir -p "$run_dir"

              ./write-seed "$scenario_seed" "$run_dir/crucible-guest-entropy-seed.bin" \
                > "$run_dir/expected-seed.hex"

              (
                cd "$run_dir"
                timeout 300 "$QEMU" \
                  -nodefaults \
                  -no-user-config \
                  -display none \
                  -monitor none \
                  -machine q35 \
                  -accel sim,thread=single \
                  -icount shift=0,sleep=off,align=off \
                  -cpu qemu64,-rdrand,-rdseed \
                  -m 256 \
                  -smp 1 \
                  -rtc base=2026-01-01T00:00:00,clock=vm \
                  -seed "$scenario_seed" \
                  -fw_cfg name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin \
                  -object rng-builtin,id=crucible-rng0 \
                  -device virtio-rng-pci,rng=crucible-rng0 \
                  -kernel "$vmlinuz" \
                  -initrd "$INITRAMFS" \
                  -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0 crucible_seed=$scenario_seed crucible.workload=httpget" \
                  -chardev file,id=serial0,path=serial.log \
                  -serial chardev:serial0 \
                  -no-reboot
              ) || {
                if [ -f "$run_dir/serial.log" ]; then
                  cat "$run_dir/serial.log" >&2
                fi
                fail "guest $label QEMU run failed"
              }

              grep -q 'TEST_RESULT:PASS' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label did not report TEST_RESULT:PASS"
                }
              if grep -q 'TEST_RESULT:FAIL' "$run_dir/serial.log"; then
                cat "$run_dir/serial.log" >&2
                fail "guest $label reported TEST_RESULT:FAIL"
              fi
              grep -q 'FW_CFG_SEED_MATCH=true' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label did not verify fw_cfg seed"
                }
              grep -q 'WORKLOAD=crucible.workload=httpget' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label did not confirm workload selection"
                }
              grep -q 'WORKLOAD_BINARY=crucible-httpget-workload' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label did not run the selected workload binary"
                }
              grep -q 'WORKLOAD_RESULT:PASS' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label workload did not report WORKLOAD_RESULT:PASS"
                }
              grep -q 'CPU_ENTROPY_FEATURES=rdrand-disabled,rdseed-disabled' "$run_dir/serial.log" \
                || {
                  cat "$run_dir/serial.log" >&2
                  fail "guest $label exposed host CPU entropy features"
                }
            }

            get_kv() {
              label="$1"
              key="$2"
              gawk -F= -v key="$key" '$1 == key { value = $2; sub(/\r$/, "", value) } END { print value }' \
                "$TMPDIR/run-$label/serial.log"
            }

            run_one same-a 1097729
            start_jitter
            run_one same-b 1097729
            stop_jitter
            run_one different 1097730

            fw_a=$(get_kv same-a FW_CFG_SEED_HEX)
            fw_b=$(get_kv same-b FW_CFG_SEED_HEX)
            fw_c=$(get_kv different FW_CFG_SEED_HEX)
            expected_a=$(cat "$TMPDIR/run-same-a/expected-seed.hex")
            hwrng_a=$(get_kv same-a HWRNG_HEX)
            hwrng_b=$(get_kv same-b HWRNG_HEX)
            hwrng_c=$(get_kv different HWRNG_HEX)
            urandom_a=$(get_kv same-a URANDOM_HEX)
            urandom_b=$(get_kv same-b URANDOM_HEX)
            urandom_c=$(get_kv different URANDOM_HEX)
            workload_rng_a=$(get_kv same-a WORKLOAD_RNG_HEX)
            workload_rng_b=$(get_kv same-b WORKLOAD_RNG_HEX)
            workload_rng_c=$(get_kv different WORKLOAD_RNG_HEX)

            [ "$fw_a" = "$expected_a" ] || fail "fw_cfg seed was not the raw derived seed"
            [ "$fw_a" = "$fw_b" ] || fail "same seed changed fw_cfg seed"
            [ "$fw_a" != "$fw_c" ] || fail "different seed did not change fw_cfg seed"
            [ "$hwrng_a" = "$hwrng_b" ] || fail "same seed changed virtio hwrng output"
            [ "$hwrng_a" != "$hwrng_c" ] || fail "different seed did not change virtio hwrng output"
            [ "$urandom_a" = "$urandom_b" ] || fail "same seed changed guest CSPRNG output"
            [ "$urandom_a" != "$urandom_c" ] || fail "different seed did not change guest CSPRNG output"
            [ "$workload_rng_a" = "$workload_rng_b" ] || fail "same seed changed workload RNG transcript"
            [ "$workload_rng_a" != "$workload_rng_c" ] || fail "different seed did not change workload RNG transcript"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=checks.crucible.phase1.guestEntropyLaunch
            gate=gate:layer0-determinism
            tasks=T-DET-5
            guest_boot_probe=true
            firmware_entropy=fw_cfg
            fw_cfg_name=opt/crucible/seed
            fw_cfg_payload=raw-32-bytes
            firmware_seed_source=scenario-seed
            firmware_seed_hex=$fw_a
            deterministic_rng_object=rng-builtin,id=crucible-rng0
            deterministic_rng_device=virtio-rng-pci,rng=crucible-rng0
            workload=crucible.workload=httpget
            workload_binary=crucible-httpget-workload
            workload_rng_same_seed_reproducible=true
            workload_rng_different_seed_changes=true
            hwrng_same_seed_reproducible=true
            hwrng_different_seed_changes=true
            guest_csprng_same_seed_reproducible=true
            guest_csprng_different_seed_changes=true
            cpu_entropy_features=rdrand-disabled,rdseed-disabled
            guest_kernel_cmdline=stock-no-entropy-suppression
            guest_entropy_seal=host-side-qemu-icount-seeded-entropy
            host_guest_entropy_sources=disabled
            host_adversary=jitter-load-second-run
            scenario_identity_includes=guest-entropy-seed
            RESULT

            cp "$TMPDIR/run-same-a/serial.log" "$out/serial-same-a.log"
            cp "$TMPDIR/run-same-b/serial.log" "$out/serial-same-b.log"
            cp "$TMPDIR/run-different/serial.log" "$out/serial-different.log"
          '';
        }
      ];
    }
