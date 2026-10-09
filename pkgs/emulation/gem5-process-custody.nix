##! Native process-image owned-file reconstruction helper and isolation check
{
  mkDerivation,
  stdenv,
  dmtcp,
  coreutils,
  diffutils,
}:
mkDerivation {
  pname = "gem5-process-custody";
  version = "1";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = [stdenv.buildPlatform.constraints.cpu];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  buildDeps = [dmtcp coreutils diffutils];
  runtimeDeps = [dmtcp];
  phases = [
    {
      name = "build";
      script = ''
        mkdir -p "$out/lib"
        cc -std=gnu11 -Wall -Wextra -Werror -fPIC -shared \
          ${./_gem5/resource-custody.c} -o "$out/lib/libcrucible-resource-custody.so"
        cc -std=gnu11 -Wall -Wextra -Werror -fPIC \
          ${./_gem5/resource-custody-check.c} -o application
      '';
    }
    {
      name = "check";
      script = ''
        mkdir -p origin child-a child-b images tmp tmp-a tmp-b
        CRUCIBLE_CAPTURE_RESOURCE_ROOT="$PWD/origin" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_launch \
          --new-coordinator --coord-port 0 --interval 0 --no-gzip \
          --with-plugin "$out/lib/libcrucible-resource-custody.so" \
          --ckptdir "$PWD/images" --tmpdir "$PWD/tmp" ./application "$PWD/origin"
        test "$(cat origin/result)" = 22
        cp origin/state origin-state-control
        set -- images/*.dmtcp
        test "$#" -eq 1
        test -s "$1"

        # DMTCP validates replacement paths before restoring saved open files.
        # These are fresh private destinations, never aliases of the original.
        : > child-a/state
        : > child-b/state
        CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-a" CRUCIBLE_TEST_COMMAND=2 \
          CRUCIBLE_TEST_COMMAND_SUFFIX=95 CRUCIBLE_TEST_LINE='first
        second' \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-a" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-a" "$1" &
        child_a_pid=$!
        CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-b" CRUCIBLE_TEST_COMMAND=9 \
          CRUCIBLE_TEST_COMMAND_SUFFIX=95 CRUCIBLE_TEST_LINE='first
        second' \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-b" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-b" "$1" &
        child_b_pid=$!
        wait "$child_a_pid"
        wait "$child_b_pid"
        test "$(cat child-a/result)" = 27
        test "$(cat child-b/result)" = 62
        test "$(cat origin/result)" = 22
        cmp origin-state-control origin/state
        test "$(od -An -tu8 child-a/state | tr -d ' ')" = 27
        test "$(od -An -tu8 child-b/state | tr -d ' ')" = 62

        # Refuse an origin alias before any owner file is reconstructed.
        if CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/origin" \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/origin" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-a" "$1"; then
          exit 1
        else
          test "$?" -eq 125
        fi
        cmp origin-state-control origin/state
        test "$(od -An -tu8 child-a/state | tr -d ' ')" = 27
        test "$(od -An -tu8 child-b/state | tr -d ' ')" = 62

        mkdir -p child-alias
        ln -s "$PWD/origin/state" child-alias/state
        if CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-alias" \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-alias" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-a" "$1"; then
          exit 1
        else
          test "$?" -eq 125
        fi
        cmp origin-state-control origin/state
        rm child-alias/state
        ln origin/state child-alias/state
        if CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-alias" \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-alias" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-a" "$1"; then
          exit 1
        else
          test "$?" -eq 125
        fi
        cmp origin-state-control origin/state
        rm child-alias/state

        # The saved-file artifact remains sufficient after every original
        # owned file and its directory have disappeared.
        rm origin/state origin/result
        rmdir origin
        mkdir -p child-c tmp-c
        : > child-c/state
        CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-c" CRUCIBLE_TEST_COMMAND=2 \
          CRUCIBLE_TEST_COMMAND_SUFFIX=95 CRUCIBLE_TEST_LINE='first
        second' \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-c" \
          ${coreutils}/bin/timeout 60 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 --tmpdir "$PWD/tmp-c" "$1"
        test "$(cat child-c/result)" = 27
        test "$(od -An -tu8 child-c/state | tr -d ' ')" = 27
        test "$(od -An -tu8 child-a/state | tr -d ' ')" = 27
        test "$(od -An -tu8 child-b/state | tr -d ' ')" = 62

        mkdir -p "$out/share"
        mkdir -p "$out/share/licenses/gem5-process-custody"
        cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-process-custody/LICENSE"
        cat > "$out/share/result.json" <<'EOF'
        {"schema":"crucible.native-custody.mechanism-check.v1","scope":"owned-open-files-and-future-paths","sourceExitedBeforeRestore":true,"concurrentDivergentRestores":2,"restoreWithoutOriginalOwnedFiles":true,"refusesFileAliases":true,"exactProfileQualified":false,"liveForkQualified":false}
        EOF
      '';
    }
  ];
  meta = {
    description = "Reconstructs owned native file resources in private incarnation roots; exact-profile admission remains separately qualified";
    license = "MIT";
  };
}
