##! Remove compiled artifacts bundled in Cargo source crates.
{
  runCommand,
  python3,
}: {
  name,
  vendor,
  excludedFiles ? [],
}:
runCommand name {} ''
  mkdir -p "$out"
  cp -r ${vendor}/. "$out/"

  ${python3}/bin/python3 - "$out" <<'PY'
  from pathlib import Path
  import stat
  import sys

  root = Path(sys.argv[1])
  compiled_magic = (
      b"\x7fELF",
      b"\x00asm",
      b"\xca\xfe\xba\xbe",
      b"\xfe\xed\xfa\xce",
      b"\xce\xfa\xed\xfe",
      b"\xfe\xed\xfa\xcf",
      b"\xcf\xfa\xed\xfe",
      b"!<arch>\n",
      b"MZ",
  )
  compiled_suffixes = {".a", ".class", ".dll", ".exe", ".jar", ".lib", ".o", ".wasm"}

  def remove_file(path: Path) -> None:
      path.parent.chmod(path.parent.stat().st_mode | stat.S_IWUSR)
      path.unlink()

  for path in root.rglob("*"):
      if not path.is_file() or path.is_symlink():
          continue
      with path.open("rb") as source:
          header = source.read(8)
      if path.suffix in compiled_suffixes or header.startswith(compiled_magic):
          remove_file(path)

  for name in ${builtins.toJSON excludedFiles}:
      relative = Path(name)
      if relative.is_absolute() or ".." in relative.parts:
          raise SystemExit(f"Invalid source vendor exclusion: {name}")
      path = root / relative
      if not path.is_file() or path.is_symlink():
          raise SystemExit(f"Missing source vendor exclusion: {name}")
      remove_file(path)
  PY
''
