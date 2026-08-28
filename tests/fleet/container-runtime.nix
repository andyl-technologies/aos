##! tests/fleet/container-runtime.nix -- Production AOS OCI runtime contract.
##!
##! Loads the production scratch image into AOS-built containerd/runc through
##! AOS-built nerdctl. The guest then proves the image's exec-only PID 1,
##! daemonless Nix database, baked-root liveness, read-only admission boundary,
##! and persistent user-scope APM lifecycle.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  aosSystem = pkgs.stdenv.hostPlatform.system;
  goldenRoots = systems.server.config.environment.systemPackages;
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
  };
  container =
    (import ../../containers {
      inherit lib pkgs goldenRoots aosSystem;
    }).aos;
  containerImage = import ../../lib/containers/build.nix {
    inherit lib pkgs oci container;
    systemIdentity = {
      inherit
        (systems.server.config.aos.system)
        name
        version
        stateVersion
        moduleAbi
        ;
    };
  };
  dockerArchive = containerImage.platforms.${aosSystem}.dockerArchive;

  fixtures = import ../vm/apm/fixtures.nix {
    inherit pkgs;
    aosPkg = pkgs.aos;
  };
  fixtureTool = pkgs.mkDerivation {
    pname = "container-runtime-tool";
    version = "1.0.0";
    src = null;
    buildDeps = [pkgs.bash pkgs.coreutils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'printf "container-runtime-tool 1.0.0\\n"' \
            > "$out/bin/container-runtime-tool"
          chmod 0555 "$out/bin/container-runtime-tool"
        '';
      }
    ];
  };

  containerdPath = lib.concatStringsSep ":" [
    "${pkgs.containerd}/bin"
    "${pkgs.runc}/sbin"
    "${pkgs.coreutils}/bin"
    "${pkgs.kmod}/bin"
    "${pkgs.kmod}/sbin"
  ];
  runtimeSystem = mkSystem [
    ../../systems/server-test.nix
    {
      # Keep the daemon test-local. The production container image remains a
      # scratch image and contains none of the host runtime implementation.
      systemd.services.aos-container-runtime-test = {
        description = "AOS container runtime fleet-test daemon";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        serviceConfig = {
          Type = "notify";
          ExecStart =
            "${pkgs.containerd}/bin/containerd"
            + " --address /run/aos-containerd/containerd.sock"
            + " --root /var/lib/aos-containerd"
            + " --state /run/aos-containerd";
          Environment = ["PATH=${containerdPath}"];
          Delegate = true;
          KillMode = "process";
          Restart = "on-failure";
          RestartSec = "1s";
          StateDirectory = "aos-containerd";
          RuntimeDirectory = "aos-containerd";
        };
      };
    }
  ];

  address = "/run/aos-containerd/containerd.sock";
  nerdctl =
    "${pkgs.nerdctl}/bin/nerdctl"
    + " --address ${address}"
    + " --namespace aos-container-test"
    + " --snapshotter native";
  bash = "${pkgs.bash}/bin/bash";
  nixStore = "${pkgs.nix}/bin/nix-store";
  profileBin = "/var/lib/profiles/per-user/root/current/bin/container-runtime-tool";
in {
  name = "container-runtime";
  timeout = 1200;

  machines.runtime = {
    system = runtimeSystem;
    # The archive deliberately retains no Nix references, so the harness must
    # carry it explicitly. The fixture tool is present only on the outer VM;
    # APR publishes it into a test-local cache for the container to download.
    # The VM harness already carries coreutils as an explicit root, and its
    # reference-graph contract rejects duplicate roots. Retain every other
    # dependency declared by the shared APM fixture.
    extraClosures =
      (lib.remove pkgs.coreutils fixtures.commonDeps)
      ++ [
        dockerArchive
        fixtureTool
        pkgs.curl
        pkgs.nerdctl
        pkgs.python3
      ];
    memoryMiB = 3072;
    varSizeMiB = 6144;
  };

  testScript = ''
    import json
    import shlex
    import textwrap

    runtime.wait_for_unit("aos-container-runtime-test.service", timeout=120)
    runtime.succeed("${pkgs.containerd}/bin/containerd --version")
    runtime.succeed("${pkgs.runc}/sbin/runc --version")
    runtime.succeed("${pkgs.nerdctl}/bin/nerdctl --version")

    # Reuse the APM VM fixture's local identity/config conventions. Publishing
    # happens in the VM, using only AOS packages already carried by the fleet
    # image and the explicit fixture closure.
    runtime.succeed(textwrap.dedent(r"""
        set -eu
        ${fixtures.setupPreamble}
        export XDG_CACHE_HOME="$HOME/.cache"
        export XDG_CONFIG_HOME="$HOME/.config"
        export XDG_DATA_HOME="$HOME/.local/share"
        export XDG_STATE_HOME="$HOME/.local/state"

        "$APR" create container-runtime-reg
        REG_DIR="$REG_STORAGE/container-runtime-reg"
        "$APR" publish ${fixtureTool} \
          --name container-runtime-tool \
          --version 1.0.0 \
          --description 'Container runtime install fixture' \
          --license MIT \
          --maintainer container-test@example.invalid \
          --registry container-runtime-reg \
          --no-commit

        mkdir -p /var/lib/aos-container-fixtures
        NIX_CONFIG='experimental-features = nix-command' \
          "$APR" cache generate \
          --registry container-runtime-reg \
          --output /var/lib/aos-container-fixtures/cache \
          --cache-url http://127.0.0.1:18120 \
          --priority 45 \
          --no-commit
        ${pkgs.git}/bin/git -C "$REG_DIR" add -A
        ${pkgs.git}/bin/git -C "$REG_DIR" commit \
          -m 'release: container-runtime-tool 1.0.0'

        cp -a "$REG_DIR" /var/lib/aos-container-fixtures/registry
        PYTHONUNBUFFERED=1 ${pkgs.coreutils}/bin/nohup \
          ${pkgs.python3}/bin/python3 -m http.server 18120 \
          --bind 127.0.0.1 \
          --directory /var/lib/aos-container-fixtures/cache \
          > /var/lib/aos-container-fixtures/cache-http.log 2>&1 &
        printf '%s\n' "$!" > /var/lib/aos-container-fixtures/cache-http.pid
    """), timeout=180)
    runtime.wait_until_succeeds(
        "${pkgs.curl}/bin/curl --fail --silent "
        "http://127.0.0.1:18120/nix-cache-info",
        timeout=30,
    )

    runtime.succeed(
        "${nerdctl} load --input ${dockerArchive}/image.docker.tar",
        timeout=360,
    )
    images = runtime.succeed("${nerdctl} images --format '{{.Repository}}:{{.Tag}}'")
    assert "aos:latest" in images.splitlines(), images

    # Every command is passed as an OCI argv vector. The init process must exec
    # it directly: the chosen workload becomes PID 1 and shell punctuation in
    # an ordinary argument remains data.
    pid = runtime.succeed(
        "${nerdctl} run --rm --net none aos:latest "
        + "${bash} -c 'printf \"%s\\n\" \"$$\"'",
        timeout=120,
    )
    assert pid.strip() == "1", pid

    literal = "literal; touch /tmp/aos-container-init-reparsed"
    literal_output = runtime.succeed(
        "${nerdctl} run --rm --net none aos:latest "
        + "${pkgs.coreutils}/bin/printf '%s\\n' "
        + shlex.quote(literal),
        timeout=120,
    )
    assert literal_output.strip() == literal, literal_output

    runtime.succeed("${nerdctl} run --rm --net none aos:latest /usr/bin/aos --version")
    runtime.succeed("${nerdctl} run --rm --net none aos:latest /usr/bin/apm --help")
    runtime.succeed("${nerdctl} run --rm --net none aos:latest /usr/bin/apr --help")

    mounts = " --volume /var/lib/aos-container-fixtures/registry:/fixtures/registry:ro"
    runtime.succeed(
        "${nerdctl} run --detach --name aos-runtime-state --net host"
        + mounts
        + " aos:latest ${pkgs.coreutils}/bin/sleep infinity",
        timeout=120,
    )
    initial_installed = json.loads(
        runtime.succeed(
            "${nerdctl} exec aos-runtime-state /usr/bin/apm --json list --installed",
            timeout=60,
        )
    )
    assert isinstance(initial_installed, list), initial_installed
    runtime.succeed(
        "${nerdctl} exec aos-runtime-state ${bash} -c "
        + shlex.quote(
            "set -eu; "
            "ready=/nix/var/nix/.aos-container-ready; "
            "test -s \"$ready\"; "
            "test \"$(${pkgs.coreutils}/bin/wc -l < \"$ready\")\" -eq 2; "
            "${pkgs.grep}/bin/grep -Fx 'schema=aos.container.ready/v1' \"$ready\"; "
            "start=$(${pkgs.coreutils}/bin/cut -d ' ' -f 22 /proc/1/stat); "
            "${pkgs.grep}/bin/grep -Fx \"pid1_start_time=$start\" \"$ready\""
        )
    )

    # The image owns a local Nix database and no daemon socket. Both direct GC
    # and APM GC must retain every root named by the baked inventory.
    runtime.wait_until_succeeds(
        "${nerdctl} exec aos-runtime-state ${bash} -c "
        + shlex.quote(
            "set -eu; "
            "test \"$NIX_REMOTE\" = local; "
            "test ! -S /nix/var/nix/daemon-socket/socket; "
            "IFS= read -r root < /usr/lib/aos-container/baked-roots; "
            "test -n \"$root\"; "
            "${nixStore} --check-validity \"$root\""
        ),
        timeout=60,
    )
    runtime.succeed(
        "${nerdctl} exec aos-runtime-state ${bash} -c "
        + shlex.quote(
            "set -eu; "
            "root_dir=/nix/var/nix/gcroots/aos-container-baked; "
            "inventory=/usr/lib/aos-container/baked-roots; "
            "test -d \"$root_dir\"; "
            "test ! -L \"$root_dir\"; "
            "test \"$(${pkgs.findutils}/bin/find \"$root_dir\" -mindepth 1 -maxdepth 1 | "
            "${pkgs.coreutils}/bin/wc -l)\" -eq \"$(${pkgs.coreutils}/bin/wc -l < \"$inventory\")\"; "
            "while IFS= read -r root; do "
            "root_name=\"''${root##*/}\"; "
            "test -L \"$root_dir/$root_name\"; "
            "test \"$(${pkgs.coreutils}/bin/readlink \"$root_dir/$root_name\")\" = \"$root\"; "
            "done < \"$inventory\""
        )
    )
    for collect in [
        "${nixStore} --gc",
        "/usr/bin/apm gc",
    ]:
        runtime.succeed(
            "${nerdctl} exec aos-runtime-state ${bash} -c "
            + shlex.quote(
                "set -eu; " + collect + "; "
                "while IFS= read -r root; do "
                "${nixStore} --check-validity \"$root\"; "
                "test -e \"$root\"; "
                "done < /usr/lib/aos-container/baked-roots"
            ),
            timeout=180,
        )

    # A read-only root advertises the init-derived marker. Mutation is rejected
    # by APM before config or Nix state access, while help remains executable.
    runtime.succeed(
        "${nerdctl} run --rm --read-only --net none aos:latest /usr/bin/apm --help"
    )
    runtime.succeed(
        "set -eu; "
        "if ${nerdctl} run --rm --read-only --net none aos:latest "
        "/usr/bin/apm install container-runtime-tool --yes "
        ">/tmp/aos-container-read-only.out 2>&1; then exit 1; fi; "
        "grep -F 'this AOS container is read-only; user-scope package mutations are unavailable' "
        "/tmp/aos-container-read-only.out"
    )
    runtime.succeed(
        "${nerdctl} run --detach --name aos-runtime-read-only "
        "--read-only --net none aos:latest ${pkgs.coreutils}/bin/sleep infinity",
        timeout=120,
    )
    runtime.succeed(
        "set -eu; "
        "if ${nerdctl} exec aos-runtime-read-only /usr/bin/apm install "
        "container-runtime-tool --yes "
        ">/tmp/aos-container-read-only-exec.out 2>&1; then exit 1; fi; "
        "grep -F 'this AOS container is read-only; user-scope package mutations are unavailable' "
        "/tmp/aos-container-read-only-exec.out"
    )
    runtime.succeed("${nerdctl} rm --force aos-runtime-read-only")

    # The fixture is absent from the image. Drive its local APR/APM registry
    # through a real static-cache download, import, execution, restart, and
    # removal. The container never sees the VM's Nix database or store path.
    runtime.succeed(
        "${nerdctl} exec aos-runtime-state /usr/bin/apm registry add "
        "--no-verify file:///fixtures/registry --name container-runtime-reg"
    )
    apr_list = json.loads(
        runtime.succeed(
            "${nerdctl} exec aos-runtime-state /usr/bin/apr --json list"
        )
    )
    assert any(
        registry.get("name") == "container-runtime-reg"
        for registry in apr_list
    ), apr_list
    search = json.loads(
        runtime.succeed(
            "${nerdctl} exec aos-runtime-state /usr/bin/apm --json search "
            "container-runtime-tool --registry container-runtime-reg"
        )
    )
    assert any(
        package.get("name") == "container-runtime-tool"
        for package in search
    ), search
    runtime.fail(
        "${nerdctl} exec aos-runtime-state ${nixStore} "
        "--check-validity ${fixtureTool}"
    )
    runtime.succeed(
        "${nerdctl} exec aos-runtime-state /usr/bin/apm install "
        "container-runtime-tool --registry container-runtime-reg --yes "
        "> /tmp/aos-container-install.out 2>&1",
        timeout=120,
    )
    runtime.succeed(
        "${pkgs.grep}/bin/grep -F 'Downloading 1 NAR' "
        "/tmp/aos-container-install.out"
    )
    runtime.succeed(
        "${pkgs.grep}/bin/grep -E 'GET /[^ ]+\\.narinfo HTTP/' "
        "/var/lib/aos-container-fixtures/cache-http.log"
    )
    runtime.succeed(
        "${pkgs.grep}/bin/grep -E 'GET /nar/[^ ]+\\.nar\\.zst HTTP/' "
        "/var/lib/aos-container-fixtures/cache-http.log"
    )
    runtime.succeed(
        "${nerdctl} exec aos-runtime-state ${nixStore} "
        "--check-validity ${fixtureTool}"
    )
    assert "container-runtime-tool 1.0.0" in runtime.succeed(
        "${nerdctl} exec aos-runtime-state ${profileBin}"
    )

    runtime.succeed("${nerdctl} stop --time 10 aos-runtime-state", timeout=60)
    runtime.succeed("${nerdctl} start aos-runtime-state", timeout=120)
    runtime.wait_until_succeeds(
        "${nerdctl} inspect --format '{{.State.Status}}' aos-runtime-state | grep -Fx running",
        timeout=60,
    )
    installed = json.loads(
        runtime.succeed(
            "${nerdctl} exec aos-runtime-state /usr/bin/apm --json list --installed"
        )
    )
    assert any(
        package.get("name") == "container-runtime-tool"
        for package in installed
    ), installed
    assert "container-runtime-tool 1.0.0" in runtime.succeed(
        "${nerdctl} exec aos-runtime-state ${profileBin}"
    )

    runtime.succeed(
        "${nerdctl} exec aos-runtime-state /usr/bin/apm remove "
        "container-runtime-tool --yes",
        timeout=120,
    )
    runtime.fail("${nerdctl} exec aos-runtime-state ${profileBin}")
    runtime.succeed("${nerdctl} rm --force aos-runtime-state")
  '';
}
