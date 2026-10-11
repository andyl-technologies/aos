##! Native VirtIO queue bounds witnesses, separate from guest/device qualification
{
  mkDerivation,
  gem5,
  coreutils,
  grep,
}: let
  witness = ./_gem5/virtio-queue-check.py;
in
  mkDerivation {
    pname = "gem5-virtio-queue-check";
    version = "0";
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
    buildDeps = [coreutils grep];
    runtimeDeps = [gem5];

    phases = [
      {
        name = "check";
        script = ''
          ulimit -c 0
          for mode in modern legacy guest-used-index; do
            ${gem5}/bin/gem5 --outdir="$mode-output" \
              ${witness} "$mode" > "$mode.log" 2>&1
            grep -q '"observed":\[22,1,1,0,' "$mode.log"
          done

          for mode in invalid-size oversized-queue invalid-index cycle indirect \
            overrun unaligned live-reprogram ring-wrap legacy-wrap buffer-wrap; do
            if ${gem5}/bin/gem5 --outdir="$mode-output" \
              ${witness} "$mode" > "$mode.log" 2>&1; then
              echo "native queue accepted forbidden state: $mode" >&2
              exit 1
            fi

            case "$mode" in
              invalid-size|oversized-queue)
                expected='Invalid live or non-power-of-two queue resize' ;;
              invalid-index)
                expected='Available descriptor outside selected queue' ;;
              cycle)
                expected='Loop in descriptor chain' ;;
              indirect)
                expected='Unnegotiated indirect descriptor' ;;
              overrun)
                expected='Guest overran the available descriptor ring' ;;
              unaligned)
                expected='Invalid modern split-ring alignment' ;;
              ring-wrap)
                expected='Modern virtqueue address geometry overflows' ;;
              legacy-wrap)
                expected='Legacy virtqueue address geometry overflows' ;;
              buffer-wrap)
                expected='Descriptor buffer address span overflows' ;;
              live-reprogram)
                expected='Guest changed a ready split ring' ;;
            esac
            grep -Fq "$expected" "$mode.log"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cat > "$out/result.json" <<'EOF'
          {"schema":"crucible.gem5.virtio-queue-mechanism.v1","positiveCases":3,"negativeCases":11,"guestBootVerified":false,"deviceParityQualified":false}
          EOF
        '';
      }
    ];

    meta.description = "Exercises actual native VirtIO queue bounds without advertising guest device parity";
  }
