##! Application-container foreground-process and reference nginx qualification.
##!
##! Runs the production supervisor in an OCI application container. Separate
##! exec sessions prove durable adoption after the starting controller exits,
##! idempotent start, exact-command rejection, live HTTP service, and bounded
##! stop with durable absence.
{
  lib,
  mkSystem,
  pkgs,
}: let
  reference = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
  };
  containerSystem = mkSystem (reference.runtimeModules ++ [
    {
      environment.systemPackages = reference.packageRoots ++ [pkgs.aos.testSupport];
    }
  ]);
  containerImage = containerSystem.config.system.build.defaultContainer;
  aosSystem = pkgs.stdenv.hostPlatform.system;
  dockerArchive = containerImage.platforms.${aosSystem}.dockerArchive;
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
      systemd.services.aos-foreground-containerd = {
        description = "AOS foreground application-container qualification runtime";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        serviceConfig = {
          Type = "notify";
          ExecStart =
            "${pkgs.containerd}/bin/containerd"
            + " --address /run/aos-foreground-containerd/containerd.sock"
            + " --root /var/lib/aos-foreground-containerd"
            + " --state /run/aos-foreground-containerd";
          Environment = ["PATH=${containerdPath}"];
          Delegate = true;
          KillMode = "process";
          StateDirectory = "aos-foreground-containerd";
          RuntimeDirectory = "aos-foreground-containerd";
        };
      };
    }
  ];
  nerdctl =
    "${pkgs.nerdctl}/bin/nerdctl"
    + " --address /run/aos-foreground-containerd/containerd.sock"
    + " --namespace aos-foreground-qualification"
    + " --snapshotter native";
  fixtureCommand = "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture";
  stateRoot = "/var/lib/aos/ability-runtime/foreground-process";
in {
  name = "ability-native-foreground-container";
  timeout = 1200;

  machines.runtime = {
    system = runtimeSystem;
    extraClosures = [dockerArchive pkgs.curl pkgs.nerdctl];
    memoryMiB = 3072;
    varSizeMiB = 6144;
  };

  testScript = reference.testPrelude + ''
    import json
    import shlex
    import textwrap

    runtime.wait_for_unit("aos-foreground-containerd.service", timeout=120)
    publish_reference_packages()
    runtime.succeed("${nerdctl} load --input ${dockerArchive}/image.docker.tar", timeout=360)
    runtime.succeed(textwrap.dedent(r"""
      install -d -m 0755 /var/lib/aos-foreground-nginx
      cat > /var/lib/aos-foreground-nginx/nginx.conf <<'EOF'
      worker_processes 1;
      pid /tmp/aos-foreground-nginx.pid;
      error_log stderr notice;
      events { worker_connections 64; }
      http {
        access_log off;
        server {
          listen 127.0.0.1:18082;
          location /health {
            default_type text/plain;
            return 200 "aos foreground reference nginx\n";
          }
        }
      }
      EOF
    """))
    runtime.succeed(
        "${nerdctl} run --detach --name foreground-nginx --net host "
        "--volume /var/lib/aos-foreground-nginx:/etc/nginx:ro "
        "--volume /var/lib/ability-reference-registry:/var/lib/ability-reference-registry:ro "
        "--volume /var/lib/apm:/var/lib/apm:rw "
        "--volume /var/cache/apm:/var/cache/apm:rw "
        "aos:latest ${pkgs.coreutils}/bin/sleep infinity",
        timeout=120,
    )

    arguments = [
        "${fixtureCommand}",
        "foreground-process",
        "start",
        "${stateRoot}",
        "${pkgs.nginx}",
        "bin/nginx",
        "-c",
        "/etc/nginx/nginx.conf",
        "-p",
        "/tmp/",
        "-g",
        "daemon off;",
    ]
    command = "${nerdctl} exec foreground-nginx " + " ".join(
        shlex.quote(argument) for argument in arguments
    )
    started = json.loads(runtime.succeed(command, timeout=60))
    assert started["schema"] == "aos.ability.foreground-process-observation/v1", started
    assert started["running"] is True, started
    assert started["process_identity"], started

    observed_arguments = arguments.copy()
    observed_arguments[2] = "observe"
    observe = "${nerdctl} exec foreground-nginx " + " ".join(
        shlex.quote(argument) for argument in observed_arguments
    )
    observed = json.loads(runtime.succeed(observe, timeout=60))
    assert observed == started, (started, observed)

    repeated = json.loads(runtime.succeed(command, timeout=60))
    assert repeated == started, (started, repeated)
    body = runtime.succeed("${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:18082/health")
    assert body == "aos foreground reference nginx\n", body

    foreign_arguments = observed_arguments.copy()
    foreign_arguments[-1] = "daemon off; worker_processes 2;"
    foreign = "${nerdctl} exec foreground-nginx " + " ".join(
        shlex.quote(argument) for argument in foreign_arguments
    )
    runtime.fail(foreign, timeout=60)
    runtime.succeed("${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:18082/health")

    stop_arguments = arguments.copy()
    stop_arguments[2] = "stop"
    stop = "${nerdctl} exec foreground-nginx " + " ".join(
        shlex.quote(argument) for argument in stop_arguments
    )
    stopped = json.loads(runtime.succeed(stop, timeout=60))
    assert stopped["running"] is False, stopped
    absent = json.loads(runtime.succeed(observe, timeout=60))
    assert absent == stopped, (stopped, absent)
    runtime.fail("${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:18082/health")

    runtime.succeed("${nerdctl} rm --force foreground-nginx", timeout=60)
  '';
}
