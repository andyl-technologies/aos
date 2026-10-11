##! Native Hub OCI service qualification with the AOS container runtime.
##!
##! Checks environment configuration, runtime-only credentials, initialization,
##! authenticated serving, and restart persistence with a read-only image.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  aosSystem = pkgs.stdenv.hostPlatform.system;
  containerImage = systems.server.build.containers.aos-hub;
  dockerArchive = containerImage.platforms.${aosSystem}.dockerArchive;
  bootstrapImage = systems.server.build.containers.aos-hub-bootstrap;
  bootstrapArchive = bootstrapImage.platforms.${aosSystem}.dockerArchive;
  containerPlatform =
    if pkgs.stdenv.hostPlatform.isAarch64
    then "linux/arm64"
    else "linux/amd64";
  containerdConfig = pkgs.writeTextFile {
    name = "hub-native-container-runtime.toml";
    destination = "/config.toml";
    text = ''
      version = 3
      [[plugins."io.containerd.transfer.v1.local".unpack_config]]
        platform = "${containerPlatform}"
        snapshotter = "native"
    '';
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
      systemd.services.hub-container-runtime = {
        description = "Native Hub OCI test runtime";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        serviceConfig = {
          Type = "notify";
          ExecStart =
            "${pkgs.containerd}/bin/containerd"
            + " --config ${containerdConfig}/config.toml"
            + " --address /run/hub-containerd/containerd.sock"
            + " --root /var/lib/hub-containerd"
            + " --state /run/hub-containerd";
          Environment = ["PATH=${containerdPath}"];
          Delegate = true;
          KillMode = "process";
          Restart = "on-failure";
          StateDirectory = "hub-containerd";
          RuntimeDirectory = "hub-containerd";
        };
      };
    }
  ];
  nerdctl =
    "${pkgs.nerdctl}/bin/nerdctl"
    + " --address /run/hub-containerd/containerd.sock"
    + " --namespace aos-hub-container-test --snapshotter native";
in {
  name = "hub-native-container";
  timeout = 600;
  bootTimeout = 300;
  machines.runtime = {
    system = runtimeSystem;
    extraClosures = [dockerArchive bootstrapArchive pkgs.curl pkgs.nerdctl pkgs.grep pkgs.sed];
    memoryMiB = 2048;
    varSizeMiB = 4096;
  };

  testScript = ''
    import json
    import textwrap

    runtime.wait_for_unit("hub-container-runtime.service", timeout=120)
    runtime.succeed("${nerdctl} load --input ${dockerArchive}/image.docker.tar", timeout=120)
    runtime.succeed("${nerdctl} load --input ${bootstrapArchive}/image.docker.tar", timeout=120)
    image = json.loads(runtime.succeed("${nerdctl} image inspect aos-hub:latest"))[0]
    assert image["Config"]["Entrypoint"] == ["/usr/bin/aos-hub"], image["Config"]
    assert image["Config"]["Cmd"] == ["serve"], image["Config"]
    bootstrap = json.loads(runtime.succeed("${nerdctl} image inspect aos-hub-bootstrap:latest"))[0]
    assert bootstrap["Config"]["Entrypoint"] == ["/usr/bin/aos-hub"], bootstrap["Config"]
    assert bootstrap["Config"]["Cmd"] == ["init"], bootstrap["Config"]

    runtime.succeed(textwrap.dedent("""
        set -eu
        install -d -m 0700 /var/lib/hub-container-state /var/lib/hub-container-credentials
        printf '%s' 'hub-container-stable-jwt-key-with-thirty-two-bytes' \\
          > /var/lib/hub-container-credentials/jwt
        printf '%s' '{"activeVersion":1,"keys":[{"version":1,"keyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}' \\
          > /var/lib/hub-container-credentials/routes
        printf '%s' '[]' > /var/lib/hub-container-credentials/probe-signers
        printf '%s' '1111111111111111111111111111111111111111111111111111111111111111' \\
          > /var/lib/hub-container-credentials/seal
        printf '%s\\n' 'container-bootstrap-password' \\
          > /var/lib/hub-container-credentials/root-password
        chmod 0600 /var/lib/hub-container-credentials/*
        ${nerdctl} run --rm --net host --read-only --tmpfs /tmp \\
          --mount type=bind,src=/var/lib/hub-container-state,dst=/state \\
          --mount type=bind,src=/var/lib/hub-container-credentials,dst=/credentials,readonly \\
          --env HUB_ROOT=/state \\
          --env HUB_BOOTSTRAP_ROOT_EMAIL=container-root@example.test \\
          --env HUB_BOOTSTRAP_ROOT_PASSWORD_FILE=/credentials/root-password \\
          aos-hub-bootstrap:latest
    """), timeout=120)

    runtime.succeed(textwrap.dedent("""
        ${nerdctl} run --detach --name native-hub --net host --read-only --tmpfs /tmp \\
          --mount type=bind,src=/var/lib/hub-container-state,dst=/state \\
          --mount type=bind,src=/var/lib/hub-container-credentials,dst=/credentials,readonly \\
          --env HUB_ROOT=/state --env HUB_LISTEN=127.0.0.1:8080 \\
          --env HUB_TOPOLOGY=native \\
          --env HUB_EXTERNAL_URL=http://127.0.0.1:8080 \\
          --env HUB_JWT_SECRET_FILE=/credentials/jwt \\
          --env AOS_HUB_SECRET_KEY_FILE=/credentials/seal \\
          --env HUB_ROUTE_RESERVATION_KEYS_FILE=/credentials/routes \\
          --env HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE=/credentials/probe-signers \\
          --env HUB_DNS_JSON_ENDPOINT=https://dns.google/resolve \\
          aos-hub:latest
    """), timeout=120)
    try:
        runtime.wait_until_succeeds(
            "${pkgs.curl}/bin/curl -fsS http://127.0.0.1:8080/healthz", timeout=90
        )
    except Exception:
        print(runtime.succeed("${nerdctl} logs native-hub"))
        print(runtime.succeed("${nerdctl} inspect native-hub"))
        raise
    runtime.succeed(textwrap.dedent("""
        set -eu
        ${pkgs.curl}/bin/curl -fsS -D /tmp/hub-bootstrap-login.headers -o /dev/null \\
          --data-urlencode email=container-root@example.test \\
          --data-urlencode password=container-bootstrap-password \\
          http://127.0.0.1:8080/login/password
        ${pkgs.grep}/bin/grep -qi '^set-cookie:' /tmp/hub-bootstrap-login.headers

        printf '%s\\n' 'container-test-password' \\
          > /var/lib/hub-container-credentials/root-password
        ${nerdctl} run --rm --net host \\
          --mount type=bind,src=/var/lib/hub-container-state,dst=/state \\
          --mount type=bind,src=/var/lib/hub-container-credentials,dst=/credentials,readonly \\
          --env HUB_ROOT=/state aos-hub:latest \\
          reset-root --email container-root@example.test --password-file /credentials/root-password

        ${pkgs.curl}/bin/curl -fsS -D /tmp/hub-container-login.headers -o /dev/null \\
          --data-urlencode email=container-root@example.test \\
          --data-urlencode password=container-test-password \\
          http://127.0.0.1:8080/login/password
        cookie=$(${pkgs.sed}/bin/sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' /tmp/hub-container-login.headers | head -n 1)
        test -n "$cookie"
        printf '%s' "$cookie" > /tmp/hub-container-cookie
        ${pkgs.curl}/bin/curl -fsS -H "Cookie: $cookie" \\
          http://127.0.0.1:8080/-/instance | ${pkgs.grep}/bin/grep -q '<html'
        test -s /var/lib/hub-container-state/hub.db
        test ! -e /var/lib/hub-container-state/secret.key
    """), timeout=90)

    runtime.succeed("${nerdctl} restart native-hub", timeout=90)
    runtime.wait_until_succeeds(
        "${pkgs.curl}/bin/curl -fsS -H \"Cookie: $(cat /tmp/hub-container-cookie)\" "
        "http://127.0.0.1:8080/-/instance | ${pkgs.grep}/bin/grep -q '<html'",
        timeout=90,
    )
    runtime.succeed("${nerdctl} rm --force native-hub", timeout=60)

    def assert_startup_rejected(command, expected_error):
        # Budget cold image unpacking separately from the application's rejection.
        status, stdout, stderr = runtime.execute(command, timeout=120)
        output = (stdout + stderr).decode("utf-8", errors="replace")
        assert status != 0, output
        assert expected_error in output, output

    assert_startup_rejected(
        "${nerdctl} run --rm --net host --env HUB_TOPOLOGY=hybrid "
        "--env HUB_EXTERNAL_URL=https://hub.example.test "
        "--env HUB_HYBRID_ORIGIN_URL=https://native.example.test aos-hub:latest",
        "hybrid serving requires a PostgreSQL HUB_DATABASE_URL",
    )
    hybrid_command = (
        "${nerdctl} run --rm --net host --env HUB_TOPOLOGY=hybrid "
        "--env HUB_EXTERNAL_URL=https://hub.example.test "
        "--env HUB_HYBRID_ORIGIN_URL=https://native.example.test "
        "--env HUB_DATABASE_URL=postgresql://postgres@127.0.0.1:1/postgres "
    )
    assert_startup_rejected(
        hybrid_command + "aos-hub:latest",
        "hybrid serving requires a stable HUB_JWT_SECRET_FILE",
    )
    assert_startup_rejected(
        hybrid_command + "--env HUB_JWT_SECRET_FILE=/missing-jwt aos-hub:latest",
        "hybrid serving requires a stable AOS_HUB_SECRET_KEY_FILE",
    )
    print("Native Hub OCI initialization, authenticated restart, and hybrid configuration fence: passed")
  '';
}
