# Checks published metadata against the final store bytes without target execution.
{
  pkgs,
  systemd ? pkgs.systemd,
}:
pkgs.runCommand "aos-systemd-backend-policy-artifact-check" {
  buildDeps = [pkgs.python3];
} ''
  ${pkgs.python3}/bin/python3 -B - ${systemd} <<'PY'
  import hashlib
  from pathlib import Path
  import sys

  root = Path(sys.argv[1])
  policy = root / "share/aos"
  artifact = (policy / "backend-policy-artifact-v2").read_bytes()
  lines = artifact.splitlines(keepends=True)
  assert len(artifact) == 269 and len(lines) == 5, "invalid backend artifact extent"
  assert lines[0] == b"AOSBPA02\n", "invalid backend artifact version"

  for line, path in (
      (lines[1], root / "lib/systemd/systemd"),
      (lines[2], root / "bin/systemd-nspawn"),
      (lines[4], policy / "nspawn-seccomp-source-v1"),
  ):
      with path.open("rb") as source:
          actual = hashlib.file_digest(source, "sha256").hexdigest().encode() + b"\n"
      assert line == actual, f"backend artifact differs from final {path.name}"

  assert lines[3] == (policy / "payload-root-policy-v1").read_bytes(), "policy pin differs"
  assert len(lines[3]) == 65 and lines[3][-1:] == b"\n", "invalid policy pin extent"
  assert all(byte in b"0123456789abcdef" for byte in lines[3][:-1]), "invalid policy pin"
  PY
  mkdir -p "$out"
  printf 'PASS\n' > "$out/result"
''
