# Measure the installed auxiliary ELF after normal fixup. This dependent
# receipt is reviewed with the exact common source before its consumer runs.
{
  pkgs,
  runtimeSource,
  helper,
  worker,
}:
pkgs.runCommand "hub-worker-verification-helper-provenance" {
  buildDeps = [pkgs.python3];
} ''
  mkdir -p "$out"
  ${pkgs.python3}/bin/python3 - "$out/provenance.json" <<'VERIFICATION_HELPER_PROVENANCE'
  import hashlib, json, os, stat, sys
  from pathlib import Path

  path=Path("${helper}/bin/aos-hub-worker-verification-observation")
  with path.open("rb") as executable:
      before=os.fstat(executable.fileno())
      if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=536870912:
          raise ValueError("Installed verification ELF exceeded its selected bound")
      if executable.read(4)!=b"\x7fELF":
          raise ValueError("Verification artifact is not an installed ELF")
      executable.seek(0)
      digest=hashlib.file_digest(executable,"sha256").hexdigest()
      after=os.fstat(executable.fileno())
  if any(getattr(before,name)!=getattr(after,name)
          for name in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")):
      raise ValueError("Installed verification ELF changed during observation")
  proof={"version":1,"commonSourceStorePath":"${toString runtimeSource}",
      "workerFilteredSourceStorePath":"${worker.src}",
      "testExecutableSha256":digest,"testExecutableBytes":str(before.st_size)}
  with Path(sys.argv[1]).open("x") as output:
      json.dump(proof,output,sort_keys=True,separators=(",",":"))
      output.write("\n")
  VERIFICATION_HELPER_PROVENANCE
''
