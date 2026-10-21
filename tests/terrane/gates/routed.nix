# These gates share actual public-API execution. Physical cache ownership and
# network provider conformance remain owned by their separate native gates.
{
  pkgs,
  sourceGate,
  ...
}: let
  proof = sourceGate "routed-store-proof" ''
    cd crates
    cargo test --frozen --offline -p terrane-sdk --features tokio \
      --test routed_store --no-run --message-format=json > "$out/build.jsonl"
    python3 ../tests/terrane/routed_proof.py
    printf '%s\n' PASS > "$out/result"
  '';
  gate = name: message:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.python3];
      phases = [
        {
          name = "qualify";
          script = ''
            test "$(cat ${proof}/result)" = PASS
            python3 - ${proof}/source-review.json ${pkgs.terrane.src} <<'PY'
            import json
            import pathlib
            import sys

            review = json.loads(pathlib.Path(sys.argv[1]).read_text())
            if review["source"] != sys.argv[2] or len(review["executed_cases"]) != 12:
                raise SystemExit("routed gate source or execution inventory mismatch")
            PY
            mkdir -p "$out/nix-support"
            printf '%s\n' ${proof} > "$out/nix-support/routed-proof"
            printf '%s\n' '${message}' > "$out/result"
          '';
        }
      ];
    };
in {
  routed-read-order = gate "routed-read-order" "PASS: configured read order, exact membership, finite deadlines and shared circuits";
  routed-write-authority = gate "routed-write-authority" "PASS: authority-only uploads acknowledge only actual authority success";
  store-ref-forwarding = gate "store-ref-forwarding" "PASS: all ref operations retain the exact original authority and outcomes";
}
