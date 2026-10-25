##! Verifies artifacts and action reuse from three independently built Git worktrees.
{
  producer,
  consumer,
  uncached,
  system ? builtins.currentSystem,
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  builds = builtins.mapAttrs (_: path: builtins.storePath path) {
    inherit producer consumer uncached;
  };
in
  pkgs.runCommand "aos-bazel-real-worktree-cache-proof" {
    buildDeps = [pkgs.python3];
  } ''
    ${pkgs.python3}/bin/python3 ${./verify_cache.py} \
      --producer ${builds.producer} \
      --consumer ${builds.consumer} \
      --uncached ${builds.uncached} \
      --output "$out"

    ${pkgs.python3}/bin/python3 - "$out/evidence.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    evidence_path = Path(sys.argv[1])
    evidence = json.loads(evidence_path.read_text())
    metrics = {
        role: json.loads((Path(build) / "evidence/metrics.json").read_text())
        for role, build in evidence["builds"].items()
    }
    if len({item["output_base_inode"] for item in metrics.values()}) != 3:
        raise ValueError("worktree builds did not use distinct output bases")
    for namespace in ["mnt", "net", "pid"]:
        if len({item["namespaces"][namespace] for item in metrics.values()}) != 3:
            raise ValueError("worktree builds shared a sandbox namespace: " + namespace)
    if any(item["server_before"] is not None for item in metrics.values()):
        raise ValueError("worktree builds reused a running Bazel server")
    producer_cache = metrics["producer"]["disk_cache"]
    if not producer_cache or producer_cache != metrics["consumer"]["disk_cache"]:
        raise ValueError("producer and consumer did not share the selected disk cache")
    if metrics["uncached"]["disk_cache"] is not None:
        raise ValueError("uncached worktree build enabled a disk cache")
    if metrics["producer"]["finished_unix_ns"] > metrics["consumer"]["started_unix_ns"]:
        raise ValueError("consumer started before the producer finished")

    evidence["metrics"] = metrics
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
