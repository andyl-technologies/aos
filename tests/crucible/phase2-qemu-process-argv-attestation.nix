{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0035-crucible-process-argv-attestation.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  traceImporterSource = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/trace.rs;
  argvIdentitySource = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/live_runner/identity.rs;
  liveRunnerConfigSource = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/live_runner/config.rs;
  liveFingerprintGateSource = builtins.readFile ./phase2-qemu-nvcpu-fingerprint.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  pluginArgumentSources = "${liveRunnerConfigSource}\n${liveFingerprintGateSource}";
  forbiddenPluginArgumentKeys = [
    "actual_argv_digest="
    "expected_argv_digest="
    "control_digest="
    "invocation_digest="
  ];

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "process-entry capture ordered before QEMU argument parsing";
        needle = "+    crucible_capture_process_argv(argc, argv);\n     qemu_init(argc, argv);";
      }
      {
        label = "v2 raw Unix argv domain";
        needle = "crucible.qemu.raw-unix-argv.v2";
      }
      {
        label = "length-framed hashing";
        needle = "crucible_argv_hash_framed";
      }
      {
        label = "argc and argv0-inclusive loop";
        needle = "for (int index = 0; index < argc; index++)";
      }
      {
        label = "index framing";
        needle = "crucible_argv_hash_segment(checksum, \"argv-index\"";
      }
      {
        label = "raw value framing";
        needle = "crucible_argv_hash_segment(checksum, \"argv-value\"";
      }
      {
        label = "raw byte accounting without text conversion";
        needle = "length = strlen(argv[index]);";
      }
      {
        label = "public attestation structure";
        needle = "struct qemu_plugin_crucible_process_argv_attestation";
      }
      {
        label = "exported plugin API";
        needle = "+QEMU_PLUGIN_API\n+int qemu_plugin_crucible_process_argv_attestation(";
      }
      {
        label = "attestation version 2";
        needle = "*version_out = 2;";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/single_vm_fingerprint/live_runner/identity.rs" argvIdentitySource [
      {
        label = "matching v2 raw Unix argv domain";
        needle = "crucible.qemu.raw-unix-argv.v2";
      }
      {
        label = "argv0 bound separately from argv tail";
        needle = "hasher.segment(\"argv-value\", argv0_bytes);";
      }
      {
        label = "raw OsStr byte access";
        needle = "let bytes = argument.as_bytes();";
      }
      {
        label = "empty-argument framing adversary";
        needle = "argv_length_framing_defeats_concatenation_and_empty_ambiguity";
      }
      {
        label = "non-UTF8 and argv0 adversary";
        needle = "raw_non_utf8_and_argv0_bytes_are_bound";
      }
      {
        label = "empty argv0 semantics";
        needle = "RawUnixArgvIdentity::new(OsStr::new(\"\"), &[])";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" tracePluginSource [
      {
        label = "plugin queries QEMU-owned attestation";
        needle = "qemu_plugin_crucible_process_argv_attestation(";
      }
      {
        label = "plugin rejects API or version failure";
        needle = "process_argv_status != 0 || process_argv_attestation.version != 2";
      }
      {
        label = "plugin rejects empty argc";
        needle = "process_argv_attestation.argc == 0";
      }
      {
        label = "plugin rejects a zero digest";
        needle = "digest_is_zero(process_argv_attestation.sha256)";
      }
      {
        label = "plugin installation fails closed";
        needle = "invalid process argv self-attestation";
      }
      {
        label = "v6 trace schema";
        needle = "crucible.qemu.trace-fingerprint.v6";
      }
      {
        label = "trace process argv digest evidence";
        needle = "process_argv_digest";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/single_vm_fingerprint/trace.rs" traceImporterSource [
      {
        label = "v6 importer schema";
        needle = "crucible.qemu.trace-fingerprint.v6";
      }
      {
        label = "required v2 process argv definition material";
        needle = "process_argv_attestation=raw-unix-argv-v2-required";
      }
      {
        label = "required process argv evidence validation";
        needle = "fn require_process_argv(";
      }
      {
        label = "process argv digest comparison";
        needle = "actual_digest != expected.digest()";
      }
    ]
    ++ lib.concatMap (
      key:
        lib.optionals (hasInfix key pluginArgumentSources) [
          "QEMU plugin argv must not carry circular identity key `${key}`"
        ]
    )
    forbiddenPluginArgumentKeys
    ++ lib.optionals
    (hasInfix "actual_argv_hash_complete=" liveFingerprintGateSource
      && !(hasInfix "actual_argv_hash_complete=true" liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: live gate still marks actual argv attestation incomplete"
    ]
    ++ lib.optionals (!(hasInfix "process_argv_digest" liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: live gate does not require process argv trace evidence"
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU process argv attestation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-process-argv-attestation";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.pkg-config
        qemuPackage
        referenceQemu
      ];

      phases = [
        {
          name = "run-process-argv-attestation-cross-language-gate";
          script = ''
            set -eu
            cat > process-argv-probe.c <<'PROBE'
            #include <qemu-plugin.h>
            #include <inttypes.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

            static const char *
            output_path(int argc, char **argv)
            {
              static const char prefix[] = "out=";

              for (int index = 0; index < argc; index++) {
                if (strncmp(argv[index], prefix, sizeof(prefix) - 1) == 0 &&
                    argv[index][sizeof(prefix) - 1] != '\0') {
                  return argv[index] + sizeof(prefix) - 1;
                }
              }
              return NULL;
            }

            QEMU_PLUGIN_EXPORT int
            qemu_plugin_install(qemu_plugin_id_t id,
                                const qemu_info_t *info,
                                int argc,
                                char **argv)
            {
              struct qemu_plugin_crucible_process_argv_attestation attestation = {0};
              const char *path = output_path(argc, argv);
              const int status =
                  qemu_plugin_crucible_process_argv_attestation(&attestation);
              FILE *output;

              (void)id;
              (void)info;
              if (path == NULL) {
                return -1;
              }
              output = fopen(path, "wb");
              if (output == NULL) {
                return -1;
              }
              if (fprintf(output,
                          "status=%d\n"
                          "version=%" PRIu32 "\n"
                          "argc=%" PRIu64 "\n"
                          "raw_bytes=%" PRIu64 "\n"
                          "digest=",
                          status,
                          attestation.version,
                          attestation.argc,
                          attestation.raw_bytes) < 0) {
                fclose(output);
                return -1;
              }
              for (size_t index = 0; index < sizeof(attestation.sha256); index++) {
                if (fprintf(output,
                            "%02x",
                            (unsigned int)attestation.sha256[index]) < 0) {
                  fclose(output);
                  return -1;
                }
              }
              if (fputs("\n", output) == EOF || fclose(output) != 0) {
                return -1;
              }

              /* Reject installation deliberately so each QEMU run exits finitely. */
              return -1;
            }
            PROBE

            cat > stock-process-argv-probe.c <<'STOCK_PROBE'
            #include "${referenceQemu}/include/qemu-plugin.h"

            int
            stock_process_argv_probe(void)
            {
              struct qemu_plugin_crucible_process_argv_attestation attestation = {0};

              return qemu_plugin_crucible_process_argv_attestation(&attestation);
            }
            STOCK_PROBE

            cat > process-argv-launcher.c <<'LAUNCHER'
            #include <glib.h>
            #include <errno.h>
            #include <inttypes.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <unistd.h>

            static void
            hash_u64(GChecksum *checksum, uint64_t value)
            {
              unsigned char encoded[8];

              for (size_t index = 0; index < sizeof(encoded); index++) {
                encoded[sizeof(encoded) - index - 1] = value & 0xffU;
                value >>= 8;
              }
              g_checksum_update(checksum, encoded, sizeof(encoded));
            }

            static void
            hash_framed(GChecksum *checksum, const void *bytes, size_t length)
            {
              hash_u64(checksum, length);
              if (length != 0) {
                g_checksum_update(checksum, bytes, length);
              }
            }

            static void
            hash_segment(GChecksum *checksum,
                         const char *label,
                         const void *bytes,
                         size_t length)
            {
              hash_framed(checksum, label, strlen(label));
              hash_framed(checksum, bytes, length);
            }

            static void
            encode_u64(uint64_t value, unsigned char encoded[8])
            {
              for (size_t index = 0; index < 8; index++) {
                encoded[8 - index - 1] = value & 0xffU;
                value >>= 8;
              }
            }

            static int
            known_answer_test(void)
            {
              static const char domain[] = "crucible.qemu.raw-unix-argv.v2";
              static const char expected[] =
                  "6e5913d007f362002552d3dab7a38515c4d73f8fbcd6050aedecae8ad9b5fea2";
              static char raw_argv0[] = {'q', 'e', 'm', 'u', '-', (char)0xff, '\0'};
              char *vector[] = {raw_argv0, "-S", "", "ab", "c", NULL};
              GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
              unsigned char encoded[8];

              if (checksum == NULL) {
                return -1;
              }
              hash_framed(checksum, domain, sizeof(domain) - 1);
              encode_u64(5, encoded);
              hash_segment(checksum, "argc", encoded, sizeof(encoded));
              for (uint64_t index = 0; index < 5; index++) {
                encode_u64(index, encoded);
                hash_segment(checksum, "argv-index", encoded, sizeof(encoded));
                hash_segment(checksum,
                             "argv-value",
                             vector[index],
                             strlen(vector[index]));
              }
              if (strcmp(g_checksum_get_string(checksum), expected) != 0) {
                g_checksum_free(checksum);
                return -1;
              }
              g_checksum_free(checksum);
              return 0;
            }

            static int
            write_expected(const char *path, char *const child_argv[])
            {
              static const char domain[] = "crucible.qemu.raw-unix-argv.v2";
              GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
              unsigned char digest[32];
              unsigned char encoded[8];
              gsize digest_length = sizeof(digest);
              uint64_t argc = 0;
              uint64_t raw_bytes = 0;
              FILE *output;

              if (checksum == NULL) {
                return -1;
              }
              while (child_argv[argc] != NULL) {
                const size_t length = strlen(child_argv[argc]);
                if (UINT64_MAX - raw_bytes < length || argc == UINT64_MAX) {
                  g_checksum_free(checksum);
                  return -1;
                }
                raw_bytes += length;
                argc++;
              }
              hash_framed(checksum, domain, sizeof(domain) - 1);
              encode_u64(argc, encoded);
              hash_segment(checksum, "argc", encoded, sizeof(encoded));
              for (uint64_t index = 0; index < argc; index++) {
                encode_u64(index, encoded);
                hash_segment(checksum, "argv-index", encoded, sizeof(encoded));
                hash_segment(checksum,
                             "argv-value",
                             child_argv[index],
                             strlen(child_argv[index]));
              }
              g_checksum_get_digest(checksum, digest, &digest_length);
              g_checksum_free(checksum);
              if (digest_length != sizeof(digest)) {
                return -1;
              }

              output = fopen(path, "wb");
              if (output == NULL) {
                return -1;
              }
              if (fprintf(output,
                          "status=0\nversion=2\nargc=%" PRIu64
                          "\nraw_bytes=%" PRIu64 "\ndigest=",
                          argc,
                          raw_bytes) < 0) {
                fclose(output);
                return -1;
              }
              for (size_t index = 0; index < sizeof(digest); index++) {
                if (fprintf(output, "%02x", (unsigned int)digest[index]) < 0) {
                  fclose(output);
                  return -1;
                }
              }
              return fputs("\n", output) == EOF || fclose(output) != 0 ? -1 : 0;
            }

            int
            main(int argc, char **argv)
            {
              static char empty_argv0[] = "";
              static char non_utf8_argv0[] = {'q', 'e', 'm', 'u', '-', (char)0xff, '\0'};
              char *plugin_option;
              char *child_argv[10];
              char *selected_argv0;

              if (known_answer_test() != 0) {
                fprintf(stderr, "raw argv v2 known-answer test failed\n");
                return 2;
              }
              if (argc != 6) {
                fprintf(stderr,
                        "usage: %s MODE QEMU PROBE OBSERVED EXPECTED\n",
                        argv[0]);
                return 2;
              }
              if (strcmp(argv[1], "empty-argv0") == 0) {
                selected_argv0 = empty_argv0;
              } else if (strcmp(argv[1], "non-utf8-argv0") == 0) {
                selected_argv0 = non_utf8_argv0;
              } else {
                fprintf(stderr, "unknown mode: %s\n", argv[1]);
                return 2;
              }
              plugin_option = g_strdup_printf("%s,out=%s", argv[3], argv[4]);
              if (plugin_option == NULL) {
                return 2;
              }
              child_argv[0] = selected_argv0;
              child_argv[1] = "-plugin";
              child_argv[2] = plugin_option;
              child_argv[3] = "-machine";
              child_argv[4] = "none";
              child_argv[5] = "-display";
              child_argv[6] = "none";
              child_argv[7] = "-nodefaults";
              child_argv[8] = "-S";
              child_argv[9] = NULL;
              if (write_expected(argv[5], child_argv) != 0) {
                fprintf(stderr, "failed to write independent expected evidence\n");
                g_free(plugin_option);
                return 2;
              }
              execv(argv[2], child_argv);
              fprintf(stderr, "execv failed: %s\n", strerror(errno));
              g_free(plugin_option);
              return 2;
            }
            LAUNCHER

            cflags=$(pkg-config --cflags glib-2.0)
            libs=$(pkg-config --libs glib-2.0)
            cc -fPIC -shared -O2 -Wall -Wextra -Werror $cflags \
              -I${qemuPackage}/include process-argv-probe.c \
              -o process-argv-probe.so
            cc -O2 -Wall -Wextra -Werror $cflags \
              process-argv-launcher.c $libs -o process-argv-launcher
            if cc -fPIC -shared -O2 -Wall -Wextra -Werror \
              -Werror=implicit-function-declaration $cflags \
              stock-process-argv-probe.c \
              -o stock-process-argv-probe.so \
              > stock.stdout 2> stock.stderr; then
              echo "stock QEMU unexpectedly exposed process argv attestation" >&2
              exit 1
            fi

            run_case() {
              mode=$1
              observed="$PWD/$mode.observed"
              expected="$PWD/$mode.expected"
              stdout="$PWD/$mode.stdout"
              stderr="$PWD/$mode.stderr"
              rm -f "$observed" "$expected"
              status=0
              ${pkgs.coreutils}/bin/timeout 20 \
                "$PWD/process-argv-launcher" "$mode" \
                ${qemuPackage}/bin/qemu-system-x86_64 \
                "$PWD/process-argv-probe.so" "$observed" "$expected" \
                > "$stdout" 2> "$stderr" || status=$?
              if [ "$status" -eq 124 ]; then
                echo "$mode QEMU attestation probe timed out" >&2
                exit 1
              fi
              if [ "$status" -eq 0 ]; then
                echo "$mode QEMU unexpectedly accepted the rejecting probe" >&2
                exit 1
              fi
              test -s "$expected"
              test -s "$observed"
              if ! cmp -s "$expected" "$observed"; then
                echo "$mode process argv attestation mismatch" >&2
                echo "expected:" >&2
                cat "$expected" >&2
                echo "observed:" >&2
                cat "$observed" >&2
                exit 1
              fi
            }

            run_case empty-argv0
            run_case non-utf8-argv0

            mkdir -p "$out/evidence"
            cp empty-argv0.expected "$out/evidence/empty-argv0.expected"
            cp empty-argv0.observed "$out/evidence/empty-argv0.observed"
            cp non-utf8-argv0.expected "$out/evidence/non-utf8-argv0.expected"
            cp non-utf8-argv0.observed "$out/evidence/non-utf8-argv0.observed"
            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            patched_qemu_loaded_probe_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            capture_before_qemu_init=true
            raw_unix_argv_framing=v2
            shared_known_answer_vector=6e5913d007f362002552d3dab7a38515c4d73f8fbcd6050aedecae8ad9b5fea2
            empty_argv0_case=passed
            non_utf8_argv0_case=passed
            empty_tail_argument_case=not_exercised
            expected_evidence_source=independent-aos-glib-launcher
            observed_evidence_source=loaded-qemu-plugin-api
            expected_observed_comparison=byte-for-byte
            exported_api=qemu_plugin_crucible_process_argv_attestation
            production_trace_plugin_fail_closed_static_check=true
            trace_schema=v5
            circular_identity_digest_in_plugin_argv=false
            live_gate_process_argv_evidence_static_check=true
            RESULT
          '';
        }
      ];
    }
