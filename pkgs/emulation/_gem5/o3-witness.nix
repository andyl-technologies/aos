##! gem5 x86 O3/cache/DRAM process-image witness — not complete qualification
{
  mkDerivation,
  gem5,
  dmtcp,
  processCustody,
  coreutils,
  diffutils,
  grep,
  pname,
  guestIsa,
  compileGuest,
  additionalBuildDeps ? [],
}:
mkDerivation {
  inherit pname;
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

  buildDeps = [coreutils diffutils grep] ++ additionalBuildDeps;
  runtimeDeps = [gem5 dmtcp processCustody];
  phases = [
    {
      name = "build";
      script = ''
        cc -nostdlib -static -no-pie -Wl,--build-id=none \
          ${./o3-memory-workload.S} -o native-workload
        ${compileGuest}
      '';
    }
    {
      name = "check";
      script = ''
        mkdir -p images tmp origin
        ./native-workload > native.guest
        ${coreutils}/bin/timeout 180 ${gem5}/bin/gem5 \
          --outdir=baseline-output --debug-file=event.trace \
          ${./o3-continuation-check.py} ${guestIsa} baseline "$PWD/workload" "$PWD/baseline" ${./cpu-state-coverage-check.py} ${./memory-state-coverage-check.py}
        test "$(wc -c < baseline.guest)" -eq 8
        cmp native.guest baseline.guest

        cp workload origin/workload
        CRUCIBLE_CAPTURE_RESOURCE_ROOT="$PWD/origin" \
          ${coreutils}/bin/timeout 180 ${dmtcp}/bin/dmtcp_launch \
          --new-coordinator --coord-port 0 --interval 0 --no-gzip \
          --with-plugin ${processCustody}/lib/libcrucible-resource-custody.so \
          --ckpt-signal 40 --ckptdir "$PWD/images" --tmpdir "$PWD/tmp" \
          ${gem5}/bin/gem5 --outdir="$PWD/origin/output" --debug-file=event.trace \
          ${./o3-continuation-check.py} ${guestIsa} capture "$PWD/origin/workload" "$PWD/origin/capture" ${./cpu-state-coverage-check.py} ${./memory-state-coverage-check.py}
        cmp baseline.original origin/capture.original
        cmp baseline.guest origin/capture.guest
        cmp baseline-output/event.trace origin/output/event.trace
        cp origin/output/event.trace capture-continue.trace
        set -- images/*.dmtcp
        test "$#" -eq 1
        test -s "$1"

        # Restore each native output FD and every future output path into
        # separate files. Their original owned root no longer exists.
        cp -R origin child-a
        cp -R origin child-b
        : > child-a/capture.guest
        : > child-b/capture.guest
        : > child-a/output/event.trace
        : > child-b/output/event.trace
        rm -r origin
        mkdir -p tmp-a tmp-b
        CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-a" \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-a" \
          ${coreutils}/bin/timeout 180 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 \
          --tmpdir "$PWD/tmp-a" "$1" &
        child_a_pid=$!
        CRUCIBLE_RESTORE_RESOURCE_ROOT="$PWD/child-b" \
          DMTCP_PATH_MAPPING="$PWD/origin:$PWD/child-b" \
          ${coreutils}/bin/timeout 180 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 \
          --tmpdir "$PWD/tmp-b" "$1" &
        child_b_pid=$!
        wait "$child_a_pid"
        wait "$child_b_pid"
        test ! -e origin
        for child in child-a child-b; do
          cmp baseline.original "$child/capture.restored"
          cmp baseline.guest "$child/capture.guest"
          cmp capture-continue.trace "$child/output/event.trace"
        done

        mkdir -p "$out"
        cat > "$out/result.json" <<'EOF'
        {"schema":"crucible.gem5.mechanism-check.v1","scope":"${guestIsa}-o3-classic-cache-ddr3-process-image-continuation","sourceExitedBeforeRestore":true,"freshConcurrentRestores":2,"originalOwnedFilesAbsent":true,"privateOutputResources":true,"fullMicrostateFingerprintQualified":false,"fullSystemDevicesQualified":false,"exactProfileQualified":false}
        EOF
      '';
    }
  ];

  meta = {
    description = "Exercises an ${guestIsa} O3/cache/DRAM workload across durable process reconstruction without claiming full microstate/device qualification";
    license = "MIT";
  };
}
