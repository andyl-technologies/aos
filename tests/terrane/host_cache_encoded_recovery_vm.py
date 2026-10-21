"""Exercises genuine cold encoded recovery before and after acknowledged Resume."""

import os
import tomllib


CASES = ["encoded-recovery", "encoded-cold", "encoded-corrupt", "encoded-duplicate",
         "encoded-missing-dictionary", "encoded-unknown", "encoded-sealed", "encoded-old-range"]


def seed(vm, uuid):
    """Creates untrusted candidates before either native role starts."""
    for case in CASES:
        result = vm.run(vm.admin_command(vm.SEED_CAPS,
                        [vm.IMAGE / "bin/host_cache_fixture", "seed-encoded"]),
                        env=vm.actor_environment(case, uuid), text=True, capture_output=True)
        vm.require(result.stdout.splitlines() == [
            "SEEDED cold encoded candidates; no recovery or serving authority"],
            "missing cold encoding seed witness: " + case)
    # Ordinary cold policy is candidate data, never a native pin receipt. The
    # physical owner must reconcile this exact identity against verified bytes.
    raw = sorted((vm.root("encoded-cold") / "chunks").glob("*/*.0"))[0]
    path = vm.root("encoded-cold") / "state/cache/records.toml"
    path.write_text('version = 1\nresidences = []\n'
                    '[[pins]]\nowner = "cold-encoded"\nhash = "' + raw.stem + '"\n'
                    'expires = 9223372036854775807\n'
                    '[[leases]]\nowner = "cold-encoded"\nexpires = 9223372036854775807\n'
                    '[[reservations]]\nid = "' + 'a' * 32 + '"\nowner = "' + vm.owner("encoded-cold")
                    + '"\nbytes = 262144\n')
    vm.metadata(path, 840, 844, 0o640)
    with path.open("rb") as file:
        os.fsync(file.fileno())
    # This contradictory cold range was never durably removed. A valid sealed
    # body and standalone encoding cannot authorize recovery to erase that row.
    sealed = next(path for path in (vm.root("encoded-old-range") / "sealed").glob("*/*")
                  if path.is_file())
    path = vm.root("encoded-old-range") / "state/cache/records.toml"
    path.write_text('version = 1\npins = []\nleases = []\nreservations = []\n'
                    '[[residences]]\nchunk = "' + sealed.name + '"\nobject = "' + sealed.name
                    + '"\noffset = 0\nlength = ' + str(sealed.stat().st_size) + '\n')
    vm.metadata(path, 840, 844, 0o640)
    with path.open("rb") as file:
        os.fsync(file.fileno())


def run(vm, uuid):
    """Checks real consumer reads, unchanged source inodes and retained cold promises."""
    for case in CASES:
        recovers = case in {"encoded-recovery", "encoded-cold", "encoded-sealed"}
        before = {path: (path.stat().st_dev, path.stat().st_ino, path.read_bytes())
                  for path in (vm.root(case) / "chunks").glob("*/*") if path.is_file()}
        policy = vm.root(case) / "state/cache/records.toml"
        old = tomllib.loads(policy.read_text()) if policy.exists() else None
        output = vm.actor(case, "recover-encoded" if recovers else "refuse-encoded", uuid)
        vm.require(("original inodes served under durable consumer pins" in output) if recovers
                   else ("unresolved cold encoding refused; no Resume" in output),
                   "cold encoding recovery witness missing: " + case)
        vm.require(all(path.exists() and (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == original
                       for path, original in before.items()),
                   "cold encoding recovery changed original source: " + case)
        new = tomllib.loads(policy.read_text())
        vm.require(old is None or all(row in new[group] for group in ["pins", "leases", "reservations", "residences"]
                                      for row in old.get(group, [])),
                   "cold encoding recovery discarded old policy: " + case)
    print("PASS actual cold encoded recovery, original consumer custody and refusal controls", flush=True)
