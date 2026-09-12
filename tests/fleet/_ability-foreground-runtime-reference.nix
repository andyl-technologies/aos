##! Containerized system activation for foreground native-adapter qualification.
{
  lib,
  mkSystem,
  pkgs,
  guestTools ? false,
  effectQualification ? false,
  transitionTransform ? transition: transition,
}: let
  reference = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs guestTools effectQualification transitionTransform;
  };
  observerConfiguration = ''{"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}'';
  observerClientModule = ''
    environment.etc."aos/ability-execution-observer.json" = {
      text = ${builtins.toJSON observerConfiguration};
      mode = "0600";
    };
  '';
  containerRuntimeModules =
    [
      ../../systems/server.nix
      {
        aos.roles.server.enable = true;
      }
    ]
    ++ builtins.tail reference.runtimeModules
    ++ [
      {
        environment.etc."aos/ability-execution-observer.json" = {
          text = observerConfiguration;
          mode = "0600";
        };
      }
    ];
  containerSystem = mkSystem containerRuntimeModules;
  containerToplevel = containerSystem.config.system.build.toplevel;
  baseContainerSystem = mkSystem [../../systems/server.nix];
  containerImage = baseContainerSystem.config.system.build.defaultContainer;
  aosSystem = pkgs.stdenv.hostPlatform.system;
  dockerArchive = containerImage.platforms.${aosSystem}.dockerArchive;
  containerdPath = lib.concatStringsSep ":" [
    "${pkgs.containerd}/bin"
    "${pkgs.runc}/sbin"
    "${pkgs.coreutils}/bin"
    "${pkgs.kmod}/bin"
    "${pkgs.kmod}/sbin"
  ];
  containerdService = {
    description = "AOS foreground effect qualification container runtime";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    serviceConfig = {
      Type = "notify";
      ExecStart =
        "${pkgs.containerd}/bin/containerd"
        + " --address /run/aos-foreground-effect-containerd/containerd.sock"
        + " --root /var/lib/aos-foreground-effect-containerd"
        + " --state /run/aos-foreground-effect-containerd";
      Environment = ["PATH=${containerdPath}"];
      Delegate = true;
      KillMode = "process";
      StateDirectory = "aos-foreground-effect-containerd";
      RuntimeDirectory = "aos-foreground-effect-containerd";
    };
  };
  runtimeModules = [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.nerdctl];
      systemd.services.aos-foreground-effect-containerd = containerdService;
    }
  ];
  nerdctl =
    "${pkgs.nerdctl}/bin/nerdctl"
    + " --address /run/aos-foreground-effect-containerd/containerd.sock"
    + " --namespace aos-foreground-effect-qualification"
    + " --snapshotter native";
  containerInit = pkgs.writeShellScriptBin "aos-foreground-effect-container-init" ''
        set -eu

        system_root=/run/etc/system-0
        config_root=/run/etc/config-0
        upper_root=/run/etc/upper-0

        ${pkgs.coreutils}/bin/mkdir -p \
          "$system_root/metadata" "$system_root/content" "$config_root/etc" \
          "$upper_root/dir" "$upper_root/work" /var/etc
        ${pkgs.util-linux}/bin/mount --bind \
          ${containerToplevel}/etc-basedir "$system_root/content"
        ${pkgs.util-linux}/bin/mount -t erofs -o ro,nodev,nosuid \
          ${containerToplevel}/etc-metadata.erofs "$system_root/metadata"
        ${pkgs.util-linux}/bin/mount -t overlay overlay -o \
    nodev,nosuid,metacopy=on,redirect_dir=on,\
    lowerdir+=/var/etc,\
    lowerdir+="$config_root/etc",\
    lowerdir+="$system_root/metadata",\
    datadir+="$system_root/content",\
    upperdir="$upper_root/dir",\
    workdir="$upper_root/work" \
          /etc

        ${pkgs.coreutils}/bin/ln -sfn system-0 /run/etc/system
        ${pkgs.coreutils}/bin/ln -sfn config-0 /run/etc/config
        ${pkgs.coreutils}/bin/ln -sfn upper-0 /run/etc/upper
        ${pkgs.coreutils}/bin/ln -sfn ${containerToplevel} /aos-toplevel
        ${pkgs.coreutils}/bin/ln -sfn ${containerToplevel} /run/current-system
        ${pkgs.iproute2}/sbin/ip link set lo up

        exec ${pkgs.systemd}/lib/systemd/systemd
  '';
  qualificationSetupBody =
    reference.qualificationSetupBody
    + ''
      environment.systemPackages = [ ${pkgs.nerdctl} ];
      systemd.services.aos-foreground-effect-containerd = {
        description = "AOS foreground effect qualification container runtime";
        wantedBy = [ "multi-user.target" ];
        after = [ "local-fs.target" ];
        serviceConfig = {
          Type = "notify";
          ExecStart = "${pkgs.containerd}/bin/containerd --address /run/aos-foreground-effect-containerd/containerd.sock --root /var/lib/aos-foreground-effect-containerd --state /run/aos-foreground-effect-containerd";
          Environment = [ "PATH=${containerdPath}" ];
          Delegate = true;
          KillMode = "process";
          StateDirectory = "aos-foreground-effect-containerd";
          RuntimeDirectory = "aos-foreground-effect-containerd";
        };
      };
    '';
  containerClosures = [
    dockerArchive
    containerInit
    containerToplevel
    pkgs.bash
    pkgs.nerdctl
  ];
in {
  inherit
    containerImage
    containerInit
    containerRuntimeModules
    containerToplevel
    dockerArchive
    nerdctl
    observerClientModule
    runtimeModules
    ;
  inherit (reference) packageRoots packageSet qualificationCandidateRuntimeCompanions;

  extraClosures = reference.extraClosures ++ containerClosures;
  qualificationExtraClosures = reference.qualificationExtraClosures ++ containerClosures;
  inherit qualificationSetupBody;

  testPrelude =
    reference.testPrelude
    + # python
    ''
      FOREGROUND_EFFECT_CONTAINER = "aos-foreground-effect-runtime"
      FOREGROUND_EFFECT_NERDCTL = ${builtins.toJSON nerdctl}
      FOREGROUND_EFFECT_BASH = "${pkgs.bash}/bin/bash"
      FOREGROUND_OBSERVER_CLIENT_MODULE = ${builtins.toJSON observerClientModule}

      runtime.wait_for_unit(
          "aos-foreground-effect-containerd.service", timeout=180
      )
      runtime.wait_for_unit(
          "aos-ability-boundary-controller.service", timeout=180
      )
      runtime.succeed(
          f"{COREUTILS}/mkdir -p "
          "/var/lib/aos/ability-boundary-test /run/aos-instrumentation"
      )
      runtime.succeed(
          f"{FOREGROUND_EFFECT_NERDCTL} load --input "
          "${dockerArchive}/image.docker.tar",
          timeout=360,
      )
      runtime.succeed(
          f"{FOREGROUND_EFFECT_NERDCTL} run --detach --privileged "
          f"--name {FOREGROUND_EFFECT_CONTAINER} --hostname aos-effect-container "
          "--net none --cgroupns private "
          "--volume /sys/fs/cgroup:/sys/fs/cgroup:rw "
          # The disposable VM shares its store with the container so the
          # candidate package runtime and generated activation stay exact.
          "--volume /nix:/nix:rw "
          "--volume /run/aos-instrumentation:/run/aos-instrumentation:rw "
          "--volume /var/lib/aos/ability-boundary-test:"
          "/var/lib/aos/ability-boundary-test:rw "
          "--entrypoint ${containerInit}/bin/aos-foreground-effect-container-init "
          "aos:latest",
          timeout=180,
      )
      runtime.wait_until_succeeds(
          f"{FOREGROUND_EFFECT_NERDCTL} exec {FOREGROUND_EFFECT_CONTAINER} "
          f"{FOREGROUND_EFFECT_BASH} -lc "
          + shlex.quote(
              "systemctl is-system-running --wait 2>/dev/null "
              "| grep -Eq '^(running|degraded)$'"
          ),
          timeout=300,
      )

      host_runtime = runtime


      class ForegroundContainerTarget:
          """Runs system activation and observations in the real OCI boundary."""

          def __init__(self, machine):
              self.machine = machine

          def command(self, command):
              return (
                  f"{FOREGROUND_EFFECT_NERDCTL} exec "
                  f"{FOREGROUND_EFFECT_CONTAINER} "
                  f"{FOREGROUND_EFFECT_BASH} -lc {shlex.quote(command)}"
              )

          def succeed(self, command, **arguments):
              return self.machine.succeed(self.command(command), **arguments)

          def fail(self, command, **arguments):
              return self.machine.fail(self.command(command), **arguments)

          def wait_until_succeeds(self, command, **arguments):
              return self.machine.wait_until_succeeds(
                  self.command(command), **arguments
              )

          def wait_for_unit(self, unit, timeout=900):
              return self.wait_until_succeeds(
                  f"systemctl is-active --quiet {shlex.quote(unit)}",
                  timeout=timeout,
              )

          def guest_tool(self, name):
              return self.machine.guest_tool(name)

          def guest_package_runtime(self):
              return self.machine.guest_package_runtime()

          def candidate_handler_packages(self, packages):
              return self.machine.candidate_handler_packages(packages)


      runtime = ForegroundContainerTarget(host_runtime)

      reference_write_activation_host = write_activation_host


      def write_activation_host(path, activation, extra_module=""):
          reference_write_activation_host(
              path,
              activation,
              FOREGROUND_OBSERVER_CLIENT_MODULE + extra_module,
          )
    '';
}
