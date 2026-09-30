##! Native source snapshots remain replayable after generation pruning and actual GC.
{pkgs, systems, ...}: {
  name = "config-generation-gc-roots";
  timeout = 1500;
  machines.target = {
    system = systems.server-test;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.abilities.configuration.operations.file.effects.gc-probe.input = {
          path = "/etc/config-generation-gc-generation";
          content = "one\n";
        };
      }
    '';
  };
  testScript = ''
    import base64
    import json
    import shlex

    APM = "${pkgs.aos.apm}/bin/apm"
    AOS = "${pkgs.aos}/bin/aos"
    CORE = "${pkgs.coreutils}/bin"
    NIX_STORE = "${pkgs.nix}/bin/nix-store"
    PROFILE = "/var/lib/profiles/system"

    def current_generation():
        link = target.succeed(f"{CORE}/readlink {PROFILE}/current").strip()
        return int(link.rsplit("gen-", 1)[1])

    def read_json(path):
        return json.loads(target.succeed(f"{CORE}/cat {shlex.quote(path)}"))

    def diagnostic(number):
        document = json.loads(target.succeed(
            f"{AOS} ability diagnostic {PROFILE} {number} --audience deployment"
        ))
        assert document["liveStateVerified"] is False, document
        assert document["desired"]["schema"] == "aos.package.transaction", document
        return document["desired"]

    def descriptor(number):
        document = read_json(f"{PROFILE}/gen-{number}/evaluation.json")
        assert document["schema"] == "aos.package.evaluation-input", document
        return document

    def store_root(path):
        assert path.startswith("/nix/store/"), path
        return "/nix/store/" + path[len("/nix/store/"):].split("/", 1)[0]

    def generations():
        paths = target.succeed(
            f"${pkgs.findutils}/bin/find {PROFILE} -maxdepth 1 -type d -name 'gen-*'"
        ).splitlines()
        return sorted(int(path.rsplit("gen-", 1)[1]) for path in paths)

    def switch(value):
        worktree = f"/run/config-generation-gc-{value}"
        module = "{ ... }: { aos.abilities.configuration.operations.file.effects.gc-probe.input = {" \
            + 'path = "/etc/config-generation-gc-generation"; content = ' \
            + json.dumps(value + "\n") + "; }; }\n"
        payload = base64.b64encode(module.encode()).decode()
        target.succeed(
            f"{CORE}/mkdir -m 0700 {worktree}; "
            f"printf '%s' {payload} | {CORE}/base64 -d > {worktree}/configuration.nix"
        )
        target.succeed(
            f"{APM} switch --worktree {worktree} --eval-root {worktree}-evaluation", timeout=300
        )
        number = current_generation()
        assert target.succeed(f"{CORE}/cat /etc/config-generation-gc-generation").strip() == value
        return number

    def assert_retained_inputs(number):
        desired = diagnostic(number)
        source = descriptor(number)
        directory = f"{PROFILE}/gen-{number}"
        target.succeed(f"test -L {directory}/evaluation.json")
        descriptor_path = target.succeed(f"{CORE}/readlink -f {directory}/evaluation.json").strip()
        sources = [source["library"], *source["configuration"], *source["runtimeConfiguration"]]
        inputs = set(desired["inputs"])
        assert all(store_root(path) in inputs for path in sources), (number, sources, inputs)
        for root in sorted(inputs | {store_root(descriptor_path)}):
            target.succeed(f"test -e {shlex.quote(root)}")
            # Ask the real store to prove reachability, including roots that
            # retain a source transitively through its immutable descriptor.
            roots = target.succeed(f"{NIX_STORE} --query --roots {shlex.quote(root)}").strip()
            assert roots, (number, root)
        for artifact in desired["artifacts"]:
            target.succeed(f"test -e {shlex.quote(artifact['path'])}")
        return desired, source

    target.wait_until_succeeds(
        "systemctl is-active --quiet aos-host-stage-receiver.service && "
        "systemctl is-active --quiet multi-user.target", timeout=300
    )
    target.wait_until_succeeds(f"test -L {PROFILE}/current", timeout=300)
    first = current_generation()
    second = switch("two")
    third = switch("three")
    fourth = switch("four")
    assert len({first, second, third, fourth}) == 4
    second_desired = diagnostic(second)
    second_source = descriptor(second)
    third_source = descriptor(third)
    fourth_source = descriptor(fourth)
    pruned_source = store_root(third_source["runtimeConfiguration"][0])
    assert pruned_source not in {
        store_root(path) for source in [second_source, fourth_source]
        for path in [source["library"], *source["configuration"], *source["runtimeConfiguration"]]
    }

    # Native rollback reconciles the retained older desired graph as a new
    # transaction. Its new generation must retain the original source snapshot.
    target.succeed(f"{APM} rollback --system --generation {second}", timeout=300)
    restored = current_generation()
    assert restored > fourth, (restored, fourth)
    assert diagnostic(restored) == second_desired
    assert descriptor(restored) == second_source
    assert target.succeed(f"{CORE}/cat /etc/config-generation-gc-generation").strip() == "two"
    before = generations()
    clean = json.loads(target.succeed(f"{APM} --json clean --system --generations --keep 2"))
    assert clean["current_generation"] == restored, clean
    assert clean["generations_before"] == before, clean
    assert clean["generations_after"] == [fourth, restored], clean
    assert clean["removed_generations"] == sorted(set(before) - {fourth, restored}), clean
    assert generations() == [fourth, restored]
    target.succeed(f"{APM} gc", timeout=300)
    assert_retained_inputs(restored)
    assert_retained_inputs(fourth)
    target.succeed(f"test ! -e {shlex.quote(pruned_source)}")
    target.fail(f"{NIX_STORE} --query --hash {shlex.quote(pruned_source)}")

    image_state = read_json("/var/lib/profiles/image/state.json")
    running = next(image for image in image_state["generations"] if image["number"] == image_state["running"])
    image_root = f"/var/lib/profiles/image/image-gen-{running['number']}"
    target.succeed("${pkgs.util-linux}/bin/mountpoint -q /nix/var/nix/gcroots/aos-profiles")
    target.succeed(
        f'test "$({CORE}/stat -c %d:%i /var/lib/profiles)" = '
        f'"$({CORE}/stat -c %d:%i /nix/var/nix/gcroots/aos-profiles)"'
    )
    image_roots = {
        "module-library": running["module_library"]["store_path"],
        "evaluation-descriptor": running["evaluation_descriptor"],
        "boot-artifact-contract": running["boot_artifact_contract"],
        "toplevel": running["toplevel"],
        "native-executor": running["native_executor_ref"],
    }
    for name, path in image_roots.items():
        target.succeed(f"test -L {image_root}/{name}; test -e {shlex.quote(path)}")
        assert target.succeed(f"{CORE}/readlink {image_root}/{name}").strip() == path

    target.succeed(f"{APM} rollback --system --generation {fourth}", timeout=300)
    final = current_generation()
    assert final > restored
    assert descriptor(final) == fourth_source
    assert target.succeed(f"{CORE}/cat /etc/config-generation-gc-generation").strip() == "four"
    inspection = json.loads(target.succeed(
        f"{AOS} ability journal {PROFILE}/deployment/effects.journal --format json"
    ))
    assert inspection["schema"] == "aos.activation.inspection", inspection
    assert inspection["pending"] is None and inspection["completed"] is not None, inspection
    target.succeed("systemctl is-active --quiet multi-user.target")
    target.succeed("systemctl is-active --quiet aos-test-agent.service")
  '';
}
