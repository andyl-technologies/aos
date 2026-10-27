# Checks host-only command-gate mechanics; VM tests supply TPM recovery proof.
{pkgs, ...}:
pkgs.runCommand "sandbox-method46-tpm-command-gate-check" {
  buildDeps = [pkgs.python3];
} ''
  mkdir relay
  cp ${../fleet/_method46-tpm-command-gate.py} relay/_method46-tpm-command-gate.py
  cp ${../fleet/_method46-tpm-command-gate-self-test.py} relay/_method46-tpm-command-gate-self-test.py
  ${pkgs.python3}/bin/python3 relay/_method46-tpm-command-gate-self-test.py > result.log 2>&1
  cat result.log
  mkdir -p "$out"
  printf 'PASS\n' > "$out/result"
''
