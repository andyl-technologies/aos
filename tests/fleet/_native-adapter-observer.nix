##! Builds the package-owned independent native-adapter observation executable.
{pkgs}:
pkgs.writeTextFile {
  name = "aos-native-adapter-qualification-observer";
  destination = "/bin/aos-native-adapter-observer";
  executable = true;
  text = ''
    #!${pkgs.python3}/bin/python3
    import json
    import subprocess
    import sys
    import types


    class Runtime:
        """Runs bounded provider queries inside the qualification guest."""

        @staticmethod
        def succeed(command):
            completed = subprocess.run(
                [${builtins.toJSON "${pkgs.bash}/bin/bash"}, "-c", command],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"provider observation command failed: {completed.stderr.strip()}"
                )
            return completed.stdout


    oracle = types.ModuleType("aos_native_adapter_qualification_observer")
    exec(
        compile(
            ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-oracles.py)},
            "ability-effect-boundary-oracles.py",
            "exec",
        ),
        oracle.__dict__,
    )
    oracle.__dict__.update({
        "runtime": Runtime,
        "COREUTILS": ${builtins.toJSON "${pkgs.coreutils}/bin"},
        "FIND": ${builtins.toJSON "${pkgs.findutils}/bin/find"},
        "IP": ${builtins.toJSON "${pkgs.iproute2}/sbin/ip"},
        "KUBECTL": ${builtins.toJSON "${pkgs.kubectl}/bin/kubectl"},
        "NFT": ${builtins.toJSON "${pkgs.nftables}/sbin/nft"},
        "PG_ISREADY": ${builtins.toJSON "${pkgs.postgresql}/bin/pg_isready"},
        "SS": ${builtins.toJSON "${pkgs.iproute2}/sbin/ss"},
        "SYSTEMCTL": ${builtins.toJSON "${pkgs.systemd}/bin/systemctl"},
        "QUALIFICATION_OBSERVER_DIRECT": True,
    })

    arguments = json.load(sys.stdin)
    if set(arguments) != {"request_path"}:
        raise RuntimeError("observer arguments must contain only request_path")
    request_path = arguments["request_path"]
    if not isinstance(request_path, str) or not request_path.startswith("/"):
        raise RuntimeError("observer request path is not absolute")
    with open(request_path, encoding="utf-8") as request_file:
        request = json.load(request_file)
    if set(request) != {"adapter", "scope", "operation"}:
        raise RuntimeError("observer request is malformed")

    observation = oracle.live_observation(request["adapter"], request["operation"])
    print(json.dumps({
        "provider": request["adapter"],
        "kind": observation["kind"],
        "scope": request["scope"],
        "observation": json.dumps(
            observation, separators=(",", ":"), sort_keys=True
        ),
    }, separators=(",", ":"), sort_keys=True))
  '';
}
