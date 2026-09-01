{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0008-crucible-det-getrandom.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-deterministic-entropy.c;
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failuresFor = label: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${label}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  qemuNixRequirements = [
    {
      label = "deterministic getrandom patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "accelerator header include";
      needle = "#include \"qemu/accel.h\"";
    }
    {
      label = "sim getrandom guard predicate";
      needle = "crucible_guest_random_sim_requires_seed";
    }
    {
      label = "sim accelerator predicate";
      needle = "strcmp(current_accel_name(), \"sim\") == 0";
    }
    {
      label = "sim unseeded failure";
      needle = "-accel sim requires -seed for deterministic guest random";
    }
    {
      label = "fail closed return";
      needle = "return -1;";
    }
  ];

  microtestRequirements = [
    {
      label = "patched guest-random fixture include";
      needle = "#include \"util/guest-random.c\"";
    }
    {
      label = "guest-random seed entrypoint";
      needle = "qemu_guest_random_seed_main";
    }
    {
      label = "guest-random deterministic draw assertion";
      needle = "guest_random_uses_run_seed=true";
    }
    {
      label = "thread seed part1 assertion";
      needle = "guest_random_thread_seed_part1_uses_run_seed=true";
    }
    {
      label = "thread seed part2 assertion";
      needle = "guest_random_thread_seed_part2_gated=true";
    }
    {
      label = "sim unseeded guest random fails closed";
      needle = "sim_unseeded_guest_random_fails_closed=true";
    }
    {
      label = "sim unseeded suppresses host entropy";
      needle = "sim_unseeded_host_entropy_calls=0";
    }
    {
      label = "non-sim unseeded remains host crypto";
      needle = "non_sim_unseeded_guest_random_uses_host_crypto=true";
    }
    {
      label = "host entropy suppression assertion";
      needle = "host_entropy_calls=0";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-qemu-deterministic-entropy.c" microtestSource microtestRequirements;
in
  if failures != []
  then throw "crucible phase1 QEMU deterministic getrandom check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-deterministic-getrandom";
      version = "0";
      src = null;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
      ];

      phases = [
        {
          name = "run-qemu-deterministic-getrandom-microtest";
          script = ''
            set -eu

            mkdir -p crypto exec include/qemu qapi qemu util
            : > crypto/random.h
            : > exec/replay-core.h
            : > include/qemu/guest-random.h
            : > qapi/error.h
            : > qemu/accel.h
            : > qemu/cutils.h
            : > qemu/osdep.h

            cat > util/guest-random.c <<'QEMU_FIXTURE'
            /*
             * QEMU guest-visible random functions
             *
             * Copyright 2019 Linaro, Ltd.
             *
             * This program is free software; you can redistribute it and/or modify it
             * under the terms of the GNU General Public License as published by the Free
             * Software Foundation; either version 2 of the License, or (at your option)
             * any later version.
             */

            #include "qemu/osdep.h"
            #include "qemu/cutils.h"
            #include "qapi/error.h"
            #include "qemu/guest-random.h"
            #include "crypto/random.h"
            #include "exec/replay-core.h"


            static __thread GRand *thread_rand;
            static bool deterministic;

            static guint32 deterministic_glib_seed(uint64_t seed)
            {
                return (guint32)(seed ^ (seed >> 32));
            }

            static int glib_random_bytes(void *buf, size_t len)
            {
                GRand *rand = thread_rand;
                size_t i;
                uint32_t x;

                if (unlikely(rand == NULL)) {
                    /* Thread not initialized for a cpu, or main w/o -seed.  */
                    thread_rand = rand = g_rand_new();
                }

                for (i = 0; i + 4 <= len; i += 4) {
                    x = g_rand_int(rand);
                    __builtin_memcpy(buf + i, &x, 4);
                }
                if (i < len) {
                    x = g_rand_int(rand);
                    __builtin_memcpy(buf + i, &x, len - i);
                }
                return 0;
            }

            int qemu_guest_getrandom(void *buf, size_t len, Error **errp)
            {
                int ret;
                if (replay_mode == REPLAY_MODE_PLAY) {
                    return replay_read_random(buf, len);
                }
                if (unlikely(deterministic)) {
                    /* Deterministic implementation using Glib's Mersenne Twister.  */
                    ret = glib_random_bytes(buf, len);
                } else {
                    /* Non-deterministic implementation using crypto routines.  */
                    ret = qcrypto_random_bytes(buf, len, errp);
                }
                if (replay_mode == REPLAY_MODE_RECORD) {
                    replay_save_random(ret, buf, len);
                }
                return ret;
            }

            void qemu_guest_getrandom_nofail(void *buf, size_t len)
            {
                (void)qemu_guest_getrandom(buf, len, &error_fatal);
            }

            uint64_t qemu_guest_random_seed_thread_part1(void)
            {
                if (deterministic) {
                    uint64_t ret;
                    glib_random_bytes(&ret, sizeof(ret));
                    return ret;
                }
                return 0;
            }

            void qemu_guest_random_seed_thread_part2(uint64_t seed)
            {
                g_assert(thread_rand == NULL);
                if (deterministic) {
                    thread_rand =
                        g_rand_new_with_seed_array((const guint32 *)&seed,
                                                   sizeof(seed) / sizeof(guint32));
                }
            }

            int qemu_guest_random_seed_main(const char *seedstr, Error **errp)
            {
                uint64_t seed;
                if (parse_uint_full(seedstr, 0, &seed)) {
                    error_setg(errp, "Invalid seed number: %s", seedstr);
                    return -1;
                } else {
                    deterministic = true;
                    /*
                     * QEMU uses GLib's process-global PRNG for generated IDs, UUIDs, and
                     * device metadata. When -seed requests deterministic guest random,
                     * seed that global stream from the same run seed so internal device
                     * state is reproducible too.
                     */
                    g_random_set_seed(deterministic_glib_seed(seed));
                    qemu_guest_random_seed_thread_part2(seed);
                    return 0;
                }
            }
            QEMU_FIXTURE

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp "$microtestSourcePath" phase1-qemu-deterministic-entropy.c
            cc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-maybe-uninitialized \
              -DCRUCIBLE_EXPECT_SIM_GETRANDOM_GUARD \
              -I. -Iinclude \
              phase1-qemu-deterministic-entropy.c \
              -o phase1-qemu-deterministic-entropy

            mkdir -p "$out"
            ./phase1-qemu-deterministic-entropy > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^guest_random_uses_run_seed=true$' "$out/result"
            grep -q '^guest_random_thread_seed_part1_uses_run_seed=true$' "$out/result"
            grep -q '^guest_random_thread_seed_part2_gated=true$' "$out/result"
            grep -q '^different_run_seed_changes_guest_random=true$' "$out/result"
            grep -q '^unseeded_guest_random_uses_host_crypto=true$' "$out/result"
            grep -q '^host_entropy_calls=0$' "$out/result"
            grep -q '^sim_unseeded_guest_random_fails_closed=true$' "$out/result"
            grep -q '^sim_unseeded_host_entropy_calls=0$' "$out/result"
            grep -q '^non_sim_unseeded_guest_random_uses_host_crypto=true$' "$out/result"
            grep -q '^stock_sim_unseeded_negative_control_uses_host_crypto=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp util/guest-random.c "$out/guest-random.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.qemuDeterministicGetrandom
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-4,T-DET-5
            patch=0008-crucible-det-getrandom.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            qemu_guest_getrandom_sim_unseeded_policy=fail_closed
            qemu_seed_option_controls_guest_random=true
            host_entropy_calls_under_seed=0
            sim_unseeded_guest_random_fails_closed=true
            sim_unseeded_host_entropy_calls=0
            non_sim_unseeded_guest_random_uses_host_crypto=true
            sim_fail_closed_negative_control=true
            RESULT
          '';
        }
      ];
    }
