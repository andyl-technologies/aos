##! gem5 event-loop/process-image mechanism checks — not model qualification
{
  mkDerivation,
  stdenv,
  gem5,
  dmtcp,
  coreutils,
  diffutils,
}:
mkDerivation {
  pname = "gem5-continuation-check";
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

  buildDeps = [coreutils diffutils];
  runtimeDeps = [gem5 dmtcp];
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p images tmp
        ${gem5}/bin/gem5 --outdir=baseline-output \
          ${./_gem5/event-continuation-check.py} baseline "$PWD/baseline"
        ${gem5}/bin/gem5 --outdir=bounded-output \
          ${./_gem5/event-continuation-check.py} bounded "$PWD/bounded"
        cmp baseline.original bounded.original

        # The launch returns only after the source application exits. A new
        # process then reconstructs the saved native image, twice independently.
        ${coreutils}/bin/timeout 120 ${dmtcp}/bin/dmtcp_launch \
          --new-coordinator --coord-port 0 --interval 0 --no-gzip \
          --ckpt-signal 40 \
          --ckptdir "$PWD/images" --tmpdir "$PWD/tmp" \
          ${gem5}/bin/gem5 --outdir=capture-output \
          ${./_gem5/event-continuation-check.py} capture "$PWD/capture"
        cmp baseline.original capture.original
        set -- images/*.dmtcp
        test "$#" -eq 1
        test -s "$1"
        ${coreutils}/bin/timeout 120 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 \
          --tmpdir "$PWD/tmp" "$1"
        cmp baseline.original capture.restored
        cp capture.restored first-restored
        ${coreutils}/bin/timeout 120 ${dmtcp}/bin/dmtcp_restart \
          --new-coordinator --coord-port 0 --interval 0 \
          --tmpdir "$PWD/tmp" "$1"
        cmp first-restored capture.restored
        cmp baseline.original capture.original

        mkdir -p "$out"
        cat > "$out/result.json" <<'EOF'
        {"schema":"crucible.gem5.mechanism-check.v1","scope":"native-event-boundary-and-durable-process-image","sourceExitedBeforeRestore":true,"freshRestores":2,"qualifiedCpuDevices":[],"exactProfileQualified":false}
        EOF
      '';
    }
  ];

  meta = {
    description = "Checks gem5 event boundaries and origin-death process reconstruction without advertising CPU/device exactness";
    license = "MIT";
  };
}
