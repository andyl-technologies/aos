##! Checks the Lean models under `formal/`.
##!
##! Building a model checks every proof, fails on any warning (an unfinished
##! proof is one), and runs the model's axiom audit. The sandbox model's
##! executable then replays its conformance vectors, which an implementation
##! of the store helper must reproduce. See
##! `docs/engineering/sandbox/formal-model.md`.
{pkgs}: let
  # Lake's build directory is local state, never model source.
  sandboxSource = builtins.path {
    path = ../../formal/sandbox;
    name = "aos-formal-sandbox-source";
    filter = path: _type: baseNameOf path != ".lake";
  };
in {
  sandbox = pkgs.mkDerivation {
    pname = "aos-formal-sandbox-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.lean4 pkgs.jq];
    phases = [
      {
        name = "check";
        script = ''
          cp -R ${sandboxSource} project
          chmod -R u+w project
          cd project

          # Lake keeps per-user state under HOME. The project has no
          # dependencies, so it never reaches the network.
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"

          # Link the executable with the toolchain's default compiler, as the
          # Lean package's own check does, rather than the builder's CC.
          # The builder shell has no pipefail, so keep Lake's exit status.
          if ! env -u CC -u AR -u LD_LIBRARY_PATH lake build > build.log 2>&1; then
            cat build.log >&2
            exit 1
          fi
          cat build.log
          grep -E '^info: .*audited [0-9]+ Sandbox declarations$' build.log

          mkdir -p "$out"
          for input in vectors/*.input.json; do
            name=$(basename "$input" .input.json)
            .lake/build/bin/sandbox-model update "$input" | jq -S . > actual.json
            jq -S . "vectors/$name.expected.json" > expected.json
            if ! cmp -s actual.json expected.json; then
              echo "sandbox model vector $name differs from its expected output" >&2
              diff -u expected.json actual.json >&2 || true
              exit 1
            fi
            echo "$name" >> "$out/vectors"
          done

          grep -E 'audited [0-9]+ Sandbox declarations' build.log > "$out/audit"
        '';
      }
    ];
  };
}
