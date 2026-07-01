##! pkgs/boot/systemd-measure.nix — expose `systemd-measure` on a `bin/` PATH.
##!
##! systemd installs `systemd-measure` under `$out/lib/systemd/`, not
##! `$out/bin`, so it is not reachable by bare name even when the systemd
##! package is already on PATH. `apr publish` / `apr release --image-format
##! uki` shells out to it by name to recompute a signed UKI's `expected_pcr11`
##! fact (see the aos-package `registry_ops::extract_expected_pcr11` path).
##!
##! This trivial wrapper symlinks just that one binary into `$out/bin` so the
##! aos CLI can place it on its hermetic PATH (via `runtimeTools` in
##! pkgs/tools/aos/aos.nix) without dumping all of systemd's internal
##! `lib/systemd` helpers onto PATH. It reuses the same systemd package that
##! `aos-uki` measures the UKI with, so the recomputed PCR-11 value stays
##! consistent with what was signed into the `.pcrsig` section. `runtimeDeps`
##! keeps the systemd reference alive through `scrubPhase`.
{
  runCommand,
  systemd,
}:
runCommand "systemd-measure"
{
  preferLocalBuild = true;
  allowSubstitutes = false;
  runtimeDeps = [systemd];
}
''
  mkdir -p "$out/bin"
  ln -s "${systemd}/lib/systemd/systemd-measure" "$out/bin/systemd-measure"
''
