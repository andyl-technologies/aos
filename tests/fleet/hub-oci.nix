##! tests/fleet/hub-oci.nix -- Native Hub OCI production qualification.
##!
##! Runs the packaged native Hub behind an AOS-built TLS edge, publishes the
##! production AOS container graph, pulls it with daemonless AOS porcelain and
##! containerd/nerdctl, and exercises every container-administration CLI leaf.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  containerPublicationInputs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  aosSystem = pkgs.stdenv.hostPlatform.system;
  goldenRoots = systems.server.config.environment.systemPackages;
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
  };
  container =
    (import ../../containers {
      inherit lib pkgs goldenRoots aosSystem;
    })
    .aos;
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
  productionLayout = containerImage.platforms.${aosSystem}.ociLayout;
  fixtures = import ../vm/apm/fixtures.nix {
    inherit pkgs;
    aosPkg = pkgs.aos;
  };
  fixtureTool = pkgs.mkDerivation {
    pname = "hub-oci-container-tool";
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
            'printf "hub-oci-container-tool 1.0.0\\n"' \
            > "$out/bin/hub-oci-container-tool"
          chmod 0555 "$out/bin/hub-oci-container-tool"
        '';
      }
    ];
  };

  # Deterministic qualification CA. The private key is public test material,
  # never a deployment credential. The leaf is generated at VM runtime so the
  # test crosses the same file/credential interface as an operator TLS edge.
  tlsCa = pkgs.writeTextFile {
    name = "hub-oci-qualification-ca";
    destination = "/ca.crt";
    text = ''
      -----BEGIN CERTIFICATE-----
      MIIDHzCCAgegAwIBAgIEB1vNFTANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxB
      T1MgVGVzdCBVbnRydXN0ZWQgUm9vdEltYWdlMB4XDTI2MDYxODEzMjgyOFoXDTM2
      MDYxNTEzMjgyOFowJzElMCMGA1UEAwwcQU9TIFRlc3QgVW50cnVzdGVkIFJvb3RJ
      bWFnZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnmzOy6TN0du3f9
      UPhB+QuNNNSdFsIk1q+SXyDdky1TwoqiFDhqTA8DxyirtyHCm942+lZTdiAl+CNs
      AW2e95ba9Mo6h63YlvjEI+194gs2K/4K2SQd8L2ca4kTEK/RzJvnnMbRdqNYrnBB
      4BmGdHwvwnJjvNSv8+OQosrr7g1JpOCdkvaIv0N4kC5rD6S5aIs3Pbn1EuwraPVd
      8jF97i/dve4/xEnbCkTtRZY5FKT6IMeVAJmdCGsl/s9ZGzsK+ETllFdakXYnQNq9
      3pSdIzlSjxyLr4yhOoW5S2ZipwFoaIqD5Y8M/9NUBWdtaAbwF2G0Sbstopviuzfw
      TtDInfUCAwEAAaNTMFEwHQYDVR0OBBYEFKbYs+MTbZpdos0cmveR4g3Iw049MB8G
      A1UdIwQYMBaAFKbYs+MTbZpdos0cmveR4g3Iw049MA8GA1UdEwEB/wQFMAMBAf8w
      DQYJKoZIhvcNAQELBQADggEBAKuo0WhnQaUUDV4pw7W8tSm4S/MMfxwf7IbhYbhN
      fB9QOHK4HrL5XuPtLviFe1m5tEaLT8UJxAf1MOZGtjbZrvMyM2erKJznpPYMzGuH
      L6OoBKpqy+jj9Tc2fWqJ++Cc3cYWYbqT3j64LxtKnXgVupPwou1vMoSbtQoL6B9X
      6NMDaKWEekkA9gN8gG0oQHoGJ9BuANq/6WQajWmHQSj35+BOuoBLREGCt3+boiXV
      VXmMO9a57Idz4SaiM7+PazqjUHY/TwzQt8wZ1XmnfF6m9DfnyJ2rHFoHPMo3siMZ
      Hm4HoUiqbsjn/ojh4G5jF7O52NmARcWLE+9eDRkSQ0BZdqI=
      -----END CERTIFICATE-----
    '';
  };
  tlsKey = pkgs.writeTextFile {
    name = "hub-oci-qualification-ca-key";
    destination = "/ca.key";
    text = ''
      -----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC55szsukzdHbt3
      /VD4QfkLjTTUnRbCJNavkl8g3ZMtU8KKohQ4akwPA8coq7chwpveNvpWU3YgJfgj
      bAFtnveW2vTKOoet2Jb4xCPtfeILNiv+CtkkHfC9nGuJExCv0cyb55zG0XajWK5w
      QeAZhnR8L8JyY7zUr/PjkKLK6+4NSaTgnZL2iL9DeJAuaw+kuWiLNz259RLsK2j1
      XfIxfe4v3b3uP8RJ2wpE7UWWORSk+iDHlQCZnQhrJf7PWRs7CvhE5ZRXWpF2J0Da
      vd6UnSM5Uo8ci6+MoTqFuUtmYqcBaGiKg+WPDP/TVAVnbWgG8BdhtEm7LaKb4rs3
      8E7QyJ31AgMBAAECggEATn+UcbO7SDVJV4H6YlItUQDn2Y2ZshIvK0UR8UVO4/l1
      8Oc+xZGxGzf7rYNQ2asc+Sja7X/hpfKShJaTRdA1+Rfs/MXZTAHkwhfEmgCpZhWS
      XvwCs9sGsHIwAFoyFiPvk7ep/lQtlg0Y36MZd33MizH5mCbgcij4QdPtweT9CNOj
      Ch7DBtSpxx1LkCZhhfml6sLlalG+ntreUsHSyLY5BJB6hYlDQzg/7L5dNM/Z7JUI
      XI/9Mrab0e8tVW2ueAQTULoAhKmfQgxds4iD5XYNxx6793aLvTcjvbImgkSUS52X
      //e+0cM5MVb4Rf7QEqICzymENRfWo2IVQ67SOiMrswKBgQDmwQkgXxtUaivFoPB3
      nGtqrP/gHMUb7omVMFLkdS339Hnrj5oFV+JuWL+lwdKs3K66He/7xnxHV9L39hA8
      r5iv5XkJded4JqfZ54b1Mfx6j/WAidTtLjq+41E39AJ1pNtLh5Uhl3qmmHG+zHBy
      rjfS+EPrrC4CuglcGbcfBnH/EwKBgQDOPYka2PZh9NDJx92Ijqt9YYJKUdMoTjJi
      /jAtK1NdLkEBf1Y+C7TfuKFoKptlYLlKer18D2JkdiByJ/6LmKM2G+jErE2JeokY
      N9INN9pIth/w8iFiya6gCZvRaUWwW7vKmvwPjgCBsl1iKLaM65Q1W/1wBcGysjcO
      kvsLtoKn1wKBgQCVImU3msAbCpNHowBHDb0OsMiem3l41+3rkdPA+0q+Wi8B40lz
      8pzRHGKgSmhSeD4k43xaiKmBom0i/ND5p7NS20giqST0LmeFGXHLvoai36+XZ31J
      3PryrA+tzfJY/jcM1Y+4qiIG0beRzKdQNvC1VObwxdLmyD2MXMJRNuUuKQKBgQCE
      WbcHlJ4gZKQsKWfAP5ZLouyi1vnEDtKE9oxiIECiNpGe7WGh9Y9AVtK170nD+BtQ
      cY3x9El3INtXhtTyLqTmj2iD9fLYO9uIwCG7O9GIAeBjlm7YX4cBysjEzWLcdzH/
      JhCFxuIKWTVWTbxAmNmGmJ7+aaNREs8EOkyCyr/0BwKBgQCSah2AXSkO28mhVeJG
      tFZepK3ihjEOcMDUvk7/zidiZ+4u37NCXwRw80JEOQd3WphCt9QFNdIw6Va932Jg
      nVrhhHy6v1QKrbg1jGifXUXxj3WKABR4oirec0o296PMuerpwZdeRsqfkz/w1xEE
      0aUgiWsMJ84tK4V3EWAEBVP33Q==
      -----END PRIVATE KEY-----
    '';
  };
  tlsSetup = pkgs.writeShellScriptBin "hub-oci-tls-setup" ''
    set -euo pipefail
    install -d -m 0700 /run/aos-hub-tls
    install -m 0600 "$CREDENTIALS_DIRECTORY/ca-key" /run/aos-hub-tls/server.key
    ${pkgs.openssl}/bin/openssl req -new \
      -key /run/aos-hub-tls/server.key \
      -subj /CN=hub \
      -out /run/aos-hub-tls/server.csr
    printf '%s\n' \
      'subjectAltName=DNS:hub,IP:192.168.50.11' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' \
      > /run/aos-hub-tls/server.ext
    ${pkgs.openssl}/bin/openssl x509 -req -sha256 -days 3650 \
      -in /run/aos-hub-tls/server.csr \
      -CA "$CREDENTIALS_DIRECTORY/ca-cert" \
      -CAkey "$CREDENTIALS_DIRECTORY/ca-key" \
      -set_serial 8420 \
      -extfile /run/aos-hub-tls/server.ext \
      -out /run/aos-hub-tls/server.crt
  '';
  nginxConfig = pkgs.writeTextFile {
    name = "hub-oci-nginx.conf";
    destination = "/nginx.conf";
    text = ''
      daemon off;
      pid /run/aos-hub-tls/nginx.pid;
      error_log stderr info;
      events {}
      http {
        access_log /dev/stdout;
        client_body_temp_path /run/aos-hub-tls/client-body;
        proxy_temp_path /run/aos-hub-tls/proxy;
        client_max_body_size 2g;
        server {
          listen 8443 ssl;
          server_name hub 192.168.50.11;
          ssl_certificate /run/aos-hub-tls/server.crt;
          ssl_certificate_key /run/aos-hub-tls/server.key;
          location / {
            proxy_pass http://127.0.0.1:8420;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_request_buffering off;
            proxy_buffering off;
          }
        }
      }
    '';
  };

  containerdPath = lib.concatStringsSep ":" [
    "${pkgs.containerd}/bin"
    "${pkgs.runc}/sbin"
    "${pkgs.coreutils}/bin"
    "${pkgs.kmod}/bin"
    "${pkgs.kmod}/sbin"
  ];
  consumerSystem = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.aos
        pkgs.curl
        pkgs.jq
        pkgs.nerdctl
      ];
      aos.security.pki.certificateFiles = ["${tlsCa}/ca.crt"];
      systemd.services.aos-container-runtime-test = {
        description = "AOS OCI qualification container runtime";
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

  hubOciModule = {
    aos.firewall.allowedTCP = [8443];
    aos.security.pki.certificateFiles = ["${tlsCa}/ca.crt"];
    systemd.services.aos-hub.serviceConfig.Environment = [
      "HUB_OCI_PULL_ENABLED=true"
      "HUB_OCI_PUSH_ENABLED=true"
      "HUB_OCI_VERIFIED_PUBLICATION_ENABLED=true"
      "HUB_OCI_ADMINISTRATION_ENABLED=true"
      "HUB_OCI_GC_ENABLED=true"
    ];
    systemd.services.aos-hub-oci-tls = {
      description = "TLS edge for native Hub OCI qualification";
      wantedBy = ["multi-user.target"];
      after = ["aos-hub.service"];
      requires = ["aos-hub.service"];
      serviceConfig = {
        Type = "simple";
        LoadCredential = [
          "ca-cert:${tlsCa}/ca.crt"
          "ca-key:${tlsKey}/ca.key"
        ];
        ExecStartPre = "${tlsSetup}/bin/hub-oci-tls-setup";
        ExecStart = "${pkgs.nginx}/bin/nginx -c ${nginxConfig}/nginx.conf";
        Restart = "on-failure";
        RuntimeDirectory = "aos-hub-tls";
      };
    };
  };
  publisherPkiModule = {
    aos.security.pki.certificateFiles = ["${tlsCa}/ca.crt"];
  };

  address = "/run/aos-containerd/containerd.sock";
  nerdctl =
    "${pkgs.nerdctl}/bin/nerdctl"
    + " --address ${address}"
    + " --namespace aos-hub-oci"
    + " --snapshotter native";
in {
  name = "hub-oci";
  timeout = 5400;

  machines = {
    hub = {
      system = fixture.hubSystem;
      extraModules = [hubOciModule];
      memoryMiB = 4096;
      varSizeMiB = 12288;
    };
    publisher = {
      system = fixture.publisherSystem;
      extraModules = [publisherPkiModule];
      hostStoreMount = true;
      memoryMiB = 3072;
      varSizeMiB = 8192;
    };
    consumer = {
      system = consumerSystem;
      extraClosures =
        (lib.remove pkgs.coreutils fixtures.commonDeps)
        ++ [
          fixtureTool
          pkgs.python3
        ];
      memoryMiB = 4096;
      varSizeMiB = 12288;
    };
  };

  testScript = ''
    import json
    import shlex
    import textwrap

    AOS = "${pkgs.aos}/bin/aos"
    APR = "${pkgs.aos}/bin/apr"
    CURL = "${pkgs.curl}/bin/curl"
    JQ = "${pkgs.jq}/bin/jq"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    HUB = "http://hub:8420"
    OCI = "https://hub:8443"
    PRIVATE_OCI = "https://192.168.50.11:8443"
    LAYOUT = "/run/aos-host-store/${baseNameOf productionLayout}"
    PUBLICATION_INPUTS = "/run/aos-host-store/${baseNameOf containerPublicationInputs}"

    def hub_command(subcommand, token, mutation=""):
        suffix = f" {mutation}" if mutation else ""
        return (
            f"{AOS} --json --progress off --color never hub {subcommand} "
            f"--hub {shlex.quote(HUB)} --token {shlex.quote(token)}{suffix}"
        )

    def reviewed(machine, label, subcommand, token, timeout=180):
        planned = json.loads(machine.succeed(
            hub_command(
                subcommand,
                token,
                f"--plan --idempotency-key {shlex.quote(label + '-plan')}",
            ),
            timeout=timeout,
        ))
        plan = planned["data"]["plan"]
        assert plan["effects"], plan
        return json.loads(machine.succeed(
            hub_command(
                subcommand,
                token,
                " ".join([
                    "--plan-id", shlex.quote(plan["plan_id"]),
                    "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
                    "--yes --idempotency-key", shlex.quote(label + "-apply"),
                ]),
            ),
            timeout=timeout,
        ))

    def reviewed_control(machine, label, plan_command, apply_command, token, timeout=180):
        planned = json.loads(machine.succeed(
            hub_command(
                plan_command,
                token,
                f"--idempotency-key {shlex.quote(label + '-plan')}",
            ),
            timeout=timeout,
        ))
        plan = planned["data"]["plan"]
        assert plan["effects"], plan
        return json.loads(machine.succeed(
            hub_command(
                apply_command,
                token,
                " ".join([
                    "--plan-id", shlex.quote(plan["plan_id"]),
                    "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
                    "--yes --idempotency-key", shlex.quote(label + "-apply"),
                ]),
            ),
            timeout=timeout,
        ))

    # The fleet image and generated identity are part of this qualification,
    # not host conveniences. The TLS client must trust only the normal AOS PKI
    # bundle, and all three guests must receive their runtime fleet identity.
    for machine, expected_name in (
        (hub, "hub"),
        (publisher, "publisher"),
        (consumer, "consumer"),
    ):
        assert machine.succeed("cat /etc/hostname").strip() == expected_name
        machine.succeed(f"grep -F ' {expected_name}' /etc/hosts")
        machine.succeed("test -L /etc/resolv.conf && test -s /etc/resolv.conf")
        machine.succeed("grep -q 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt")

    hub.wait_for_unit("aos-hub.service", timeout=120)
    hub.wait_for_unit("aos-hub-oci-tls.service", timeout=120)
    hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)
    publisher.wait_until_succeeds(f"{CURL} -fsS {OCI}/healthz", timeout=120)
    consumer.succeed(f"{CURL} -fsS {OCI}/healthz")
    consumer.fail(f"SSL_CERT_FILE=/dev/null {CURL} -fsS {OCI}/healthz")

    # Initialize the real packaged service as its service identity with its
    # sole SQLite writer stopped. No seed state or direct database edits exist.
    hub.succeed(textwrap.dedent("""
        set -eu
        systemctl stop aos-hub.service
        printf '%s\n' 'fleet-root-password' | \
          ${pkgs.systemd}/bin/systemd-run --pipe --wait --collect \
            --uid=aos-hub --gid=aos-hub \
            ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \
              --root-email fleet-root@example.test --root-password-stdin
        install -d -o aos-hub -g aos-hub -m 0750 \
          /var/lib/aos-hub/storage/public \
          /var/lib/aos-hub/storage/private
        systemctl start aos-hub.service
    """), timeout=180)
    hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)

    token = hub.succeed(textwrap.dedent(f"""
        set -eu
        headers=/tmp/hub-oci-login.headers
        page=/tmp/hub-oci-console.html
        {CURL} -sS -D "$headers" -o /dev/null -X POST \
          --data-urlencode 'email=fleet-root@example.test' \
          --data-urlencode 'password=fleet-root-password' \
          {HUB}/login/password
        cookie=$(sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' "$headers" | head -n1)
        test -n "$cookie"
        {CURL} -sS -H "Cookie: $cookie" {HUB}/-/instance > "$page"
        csrf=$(sed -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' "$page" | head -n1)
        test -n "$csrf"
        {CURL} -fsS -X POST \
          -H "Cookie: $cookie" \
          -H 'Origin: {HUB}' \
          -H "x-aos-csrf: $csrf" \
          -H 'x-aos-console-route: /-/instance' \
          {HUB}/-/auth/session-token | {JQ} -er .accessToken
    """), timeout=120).strip()
    assert token.startswith("ey"), "browser session did not mint a JWT"

    # The publisher alone sees the host-built production artifact. Consumers
    # can acquire it only through the Hub Distribution route.
    publisher.succeed(textwrap.dedent(f"""
        set -eu
        mkdir -p /run/aos-host-store
        {MOUNT} -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \
          aos-host-store /run/aos-host-store
        test -f {LAYOUT}/oci-layout
        test -f {LAYOUT}/index.json
        test -d {LAYOUT}/blobs/sha256
        test -f {PUBLICATION_INPUTS}/oci-layout/oci-layout
        test -f {PUBLICATION_INPUTS}/image.oci.tar
        test -f {PUBLICATION_INPUTS}/evidence-layout/oci-layout
        test -f {PUBLICATION_INPUTS}/evidence.oci.tar
        test -f {PUBLICATION_INPUTS}/signature-input.json
        test -f {PUBLICATION_INPUTS}/signing-request.json
        test -f {PUBLICATION_INPUTS}/publication-roots.json
        test -f {PUBLICATION_INPUTS}/EXTERNAL-SIGNING-REQUIRED
    """), timeout=120)
    consumer.fail(f"test -e /nix/store/${baseNameOf productionLayout}")

    # Generate real APR signing identities before the registries establish
    # their trust roots. These test keys also drive the external container
    # finalizer once the production publication-input bundle is available.
    public_trust = publisher.succeed(textwrap.dedent(f"""
        set -eu
        export HOME=/var/lib/aos-oci-publisher USER=publisher
        mkdir -p "$HOME"
        output=$({APR} keys generate initial --registry containers 2>&1)
        printf '%s\n' "$output" >&2
        printf '%s\n' "$output" | awk '/Public key:/ {{print $NF; exit}}'
    """), timeout=120).strip()
    private_trust = publisher.succeed(textwrap.dedent(f"""
        set -eu
        export HOME=/var/lib/aos-oci-publisher USER=publisher
        output=$({APR} keys generate initial --registry containers-private 2>&1)
        printf '%s\n' "$output" >&2
        printf '%s\n' "$output" | awk '/Public key:/ {{print $NF; exit}}'
    """), timeout=120).strip()
    assert public_trust.startswith("containers:Ed25519:"), public_trust
    assert private_trust.startswith("containers-private:Ed25519:"), private_trust

    # Production Nix stops at private-key-free publication inputs. A
    # qualification-only external key signs the exact emitted PAE at runtime;
    # AOS then verifies that SSHSIG and atomically assembles the final bundle.
    finalized = json.loads(publisher.succeed(textwrap.dedent(f"""
        set -euo pipefail
        export HOME=/var/lib/aos-oci-publisher USER=publisher
        export PATH=${pkgs.git}/bin:${pkgs.openssh}/bin:$PATH
        mkdir -p "$HOME"
        key="$HOME/.config/apm/keys/containers-initial.key"
        test -f "$key"
        rm -rf /var/tmp/container-final /var/tmp/container-publication-surface
        rm -f /var/tmp/container-signature.pae /var/tmp/container-signature.pae.sig
        {AOS} --json --progress off --color never container prepare-signature \
          {PUBLICATION_INPUTS} --output /var/tmp/container-signature.pae
        ${pkgs.openssh}/bin/ssh-keygen -Y sign -f "$key" \
          -n aos-container-signature-dsse-v1 \
          /var/tmp/container-signature.pae
        {AOS} --json --progress off --color never container finalize-signature \
          {PUBLICATION_INPUTS} \
          --signer {shlex.quote(public_trust)} \
          --signature /var/tmp/container-signature.pae.sig \
          --output /var/tmp/container-final
    """), timeout=900).splitlines()[-1])
    assert finalized["verification"] == "verified-external-sshsig", finalized
    signed_release = finalized["release_identity"]
    signed_root = finalized["index_digest"]
    assert signed_root.startswith("sha256:"), finalized
    publisher.fail(
        f"{AOS} --json --progress off --color never container finalize-signature "
        f"{PUBLICATION_INPUTS} --signer {shlex.quote(public_trust)} "
        "--signature /var/tmp/container-signature.pae.sig "
        "--output /var/tmp/container-final"
    )

    # The verified container sidecar crosses the ordinary signed APR release
    # and managed Hub publication boundary before the OCI tag is committed.
    publisher.succeed(textwrap.dedent(f"""
        set -euo pipefail
        export HOME=/var/lib/aos-oci-publisher USER=publisher
        export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
        export NIX_REMOTE=""
        export NIX_CONF_DIR="$HOME/.config/nix"
        mkdir -p "$NIX_CONF_DIR"
        printf '%s\n' \
          'experimental-features = nix-command' \
          'sandbox = false' \
          'build-users-group =' \
          > "$NIX_CONF_DIR/nix.conf"
        git config --global user.name 'OCI Qualification Publisher'
        git config --global user.email 'oci-publisher@example.test'
        key="$HOME/.config/apm/keys/containers-initial.key"
        {APR} create containers --trust-key {shlex.quote(public_trust)} \
          --trust-key-id initial --key "$key"
        {APR} release {shlex.quote(signed_release)} --registry containers \
          --container-release /var/tmp/container-final/container-release.json \
          --container-signature-input /var/tmp/container-final/signature-input.json \
          --channel stable --init-channel --key "$key" \
          --upload-url file:///var/tmp/container-publication-surface
        {APR} verify --registry containers
    """), timeout=900)

    reviewed(
        publisher,
        "oci-org-create",
        "org create --slug acme --display-name 'Acme OCI qualification'",
        token,
    )
    org = json.loads(
        publisher.succeed(hub_command("org show acme", token))
    )["data"]["organization"]
    org_scope = org["stable_id"]

    reviewed_control(
        publisher,
        "oci-controller-account",
        "org service-account create plan acme oci-controller",
        "org service-account create apply",
        token,
    )
    reviewed_control(
        publisher,
        "oci-controller-membership",
        "org member set-role plan --principal-kind service_account "
        f"--principal acme/oci-controller --scope {shlex.quote(org_scope)} "
        "--role owner --if-version absent",
        "org member set-role apply",
        token,
    )
    controller_token_response = reviewed_control(
        publisher,
        "oci-controller-token",
        f"access-token issue plan {shlex.quote(org_scope)} "
        "--owner service_account:acme/oci-controller "
        "--permission endpoint.read --permission endpoint.manage "
        "--ttl-secs 3600 --comment 'OCI topology controller'",
        "access-token issue apply",
        token,
    )
    controller_secret = controller_token_response["data"]["result"]["secret"]
    controller_grant = json.loads(publisher.succeed(
        f"{CURL} -fsS -X POST "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        f"-H 'Authorization: Bearer {controller_secret}' "
        "--data-urlencode "
        "'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
        f"{HUB}/oauth2/token"
    ))
    controller_token = controller_grant["access_token"]

    client_token_response = reviewed_control(
        publisher,
        "oci-client-token",
        f"access-token issue plan {shlex.quote(org_scope)} "
        "--owner service_account:acme/oci-controller "
        "--permission read --permission publish --ttl-secs 3600 "
        "--comment 'OCI standard client'",
        "access-token issue apply",
        token,
    )
    client_secret = client_token_response["data"]["result"]["secret"]
    assert client_secret.startswith("aos_"), client_token_response

    def prepare_registry(slug, visibility, prefix, trust):
        reviewed(
            publisher,
            f"{slug}-registry-create",
            f"registry create --org acme --name {slug} --visibility {visibility} "
            f"--trust-key {shlex.quote(trust)}",
            token,
        )
        reviewed(
            publisher,
            f"{slug}-placement-create",
            f"placement add registry:acme/{slug} primary --binding instance-default "
            f"--prefix {prefix} --kind complete --desired-state active --read enabled",
            token,
        )
        placement = json.loads(publisher.succeed(
            hub_command(f"placement show registry:acme/{slug} primary", token)
        ))["data"]["placement"]
        reviewed(
            publisher,
            f"{slug}-placement-scan",
            f"placement scan registry:acme/{slug} primary --wait --timeout 2m "
            f"--if-version {shlex.quote(placement['resource_version'])}",
            token,
            timeout=240,
        )
        placement = json.loads(publisher.succeed(
            hub_command(f"placement show registry:acme/{slug} primary", token)
        ))["data"]["placement"]
        reviewed(
            publisher,
            f"{slug}-placement-promote",
            f"placement promote registry:acme/{slug} primary "
            f"--if-version {shlex.quote(placement['resource_version'])}",
            token,
        )

    prepare_registry("containers", "public", "public", public_trust)
    prepare_registry("containers-private", "private", "private", private_trust)

    endpoints = [
        ("oci-public", "https://hub:8443", "hub-oci-public"),
        ("oci-private", "https://192.168.50.11:8443", "hub-oci-private"),
    ]
    endpoint_generations = {}
    for stable_id, origin, certificate_ref in endpoints:
        reviewed(
            publisher,
            f"{stable_id}-endpoint-create",
            f"endpoint add {origin} --stable-id {stable_id} --org acme "
            "--network-policy instance:public@1 --ingress layer7 "
            "--listener-provider layer7 --listener-resource-id aos-hub-oci-tls.service "
            f"--tls-provider external --certificate-ref {certificate_ref} "
            "--probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 "
            "--probe-public-key ${fixture.probePublicKey}",
            token,
        )
        endpoint = json.loads(publisher.succeed(
            hub_command(f"endpoint show {stable_id}", token)
        ))["data"]["endpoint"]
        generation = int(endpoint["desired_generation"])
        endpoint_generations[stable_id] = generation
        publisher.succeed(f"{CURL} -fsS {origin}/healthz")
        observation = {
            "stableId": stable_id,
            "expectedObservationVersion": endpoint["resource_version"],
            "controllerLeaseId": "fleet-oci-controller",
            "controllerGeneration": 1,
            "observation": {
                "observedGeneration": generation,
                "boundaryRevision": endpoint["desired"]["boundary_revision"],
                "state": "healthy",
                "listenerObserved": True,
                "tlsObserved": True,
            },
        }
        publisher.succeed(
            f"{CURL} -fsS -X POST "
            "-H 'Content-Type: application/json' "
            "-H 'Connect-Protocol-Version: 1' "
            f"-H 'Authorization: Bearer {controller_token}' "
            f"--data {shlex.quote(json.dumps(observation))} "
            f"{HUB}/aos.hub.v1.DeliveryControllerService/ReportEndpoint"
        )

    for slug, stable_id, access in (
        ("containers", "oci-public", "public"),
        ("containers-private", "oci-private", "hub-auth"),
    ):
        generation = endpoint_generations[stable_id]
        route_id = f"{stable_id}-route"
        reviewed(
            publisher,
            f"{route_id}-create",
            f"route add registry:acme/{slug} --stable-id {route_id} "
            f"--endpoint {stable_id}@{generation} --base-path "
            + shlex.quote("")
            + " "
            + f"--mode hub-proxy --placement primary --serves oci --access {access}",
            token,
        )
        routes = json.loads(publisher.succeed(
            hub_command(f"route list registry:acme/{slug}", token)
        ))["data"]["routes"]
        route = next(item for item in routes if item["stable_id"] == route_id)
        reviewed(
            publisher,
            f"{route_id}-enable",
            f"route enable {route_id} --if-version {shlex.quote(route['resource_version'])}",
            token,
        )
        publisher.wait_until_succeeds(
            hub_command(f"route list registry:acme/{slug}", token)
            + f" | {JQ} -e '.data.routes[] | select(.stable_id == \"{route_id}\") "
            "| .observation.state == \"healthy\"'",
            timeout=180,
        )

    push = json.loads(publisher.succeed(
        f"{AOS} --json --progress off --color never container push {LAYOUT} "
        "hub:8443/aos:latest --hub https://hub:8443 "
        f"--token {shlex.quote(token)}",
        timeout=900,
    ))
    root_digest = push["index_digest"]
    manifest_digest = push["manifest_digest"]
    assert root_digest.startswith("sha256:"), push
    assert manifest_digest.startswith("sha256:"), push
    shared_push = json.loads(publisher.succeed(
        f"{AOS} --json --progress off --color never container push {LAYOUT} "
        "hub:8443/shared:latest --mount-from aos --hub https://hub:8443 "
        f"--token {shlex.quote(token)}",
        timeout=900,
    ))
    assert shared_push["index_digest"] == root_digest, shared_push

    private_push = json.loads(publisher.succeed(
        f"{AOS} --json --progress off --color never container push {LAYOUT} "
        "192.168.50.11:8443/aos:private --hub https://192.168.50.11:8443 "
        f"--token {shlex.quote(token)}",
        timeout=900,
    ))
    assert private_push["index_digest"] == root_digest, private_push
    assert signed_root == root_digest, (signed_root, root_digest)

    signed_publish = (
        f"{AOS} --json --progress off --color never container publish aos "
        "hub:8443/aos:stable "
        "--release /var/tmp/container-final/container-release.json "
        "--release-layout /var/tmp/container-final/layout "
        "--signature-input /var/tmp/container-final/signature-input.json "
        "--registry acme/containers "
        "--registry-origin https://hub:8443 "
        f"--registry-token {shlex.quote(token)} "
    )
    staged = json.loads(publisher.succeed(
        signed_publish
        + "--stage-only --idempotency-key hub-oci-signed-stage",
        timeout=900,
    ))
    assert staged["state"] == "staged", staged
    assert staged["index_digest"] == signed_root, staged
    indexed = json.loads(publisher.succeed(
        hub_command(
            "registry publish upload acme/containers",
            token,
            "--root /var/tmp/container-publication-surface",
        ),
        timeout=900,
    ))["data"]
    assert indexed["state"] == "ready", indexed
    verified_publish = json.loads(publisher.succeed(
        signed_publish
        + f"--hub {HUB} --token {shlex.quote(token)} "
        + "--idempotency-key hub-oci-signed-commit",
        timeout=900,
    ))
    assert verified_publish["verification"] == "verified", verified_publish
    assert verified_publish["index_digest"] == signed_root, verified_publish
    publication_id = verified_publish["publication_id"]
    assert publication_id, verified_publish

    # Build a second platform manifest through the public Distribution API.
    # Its config declares arm64 and its layers are the exact production AOS
    # layers; the qualification pulls but never executes this synthetic graph.
    # The independently flake-qualified cross output owns runnable arm64 bytes.
    multi_root = publisher.succeed(textwrap.dedent(f"""
        set -euo pipefail
        work=/var/tmp/aos-multi-platform
        rm -rf "$work"
        mkdir -p "$work"
        cp {LAYOUT}/index.json "$work/production-index.json"
        amd64_manifest=$(jq -er \
          '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' \
          "$work/production-index.json")
        amd64_blob={LAYOUT}/blobs/sha256/$(printf '%s' "$amd64_manifest" | cut -d: -f2)
        cp "$amd64_blob" "$work/amd64-manifest.json"
        config_digest=$(jq -er .config.digest "$work/amd64-manifest.json")
        config_blob={LAYOUT}/blobs/sha256/$(printf '%s' "$config_digest" | cut -d: -f2)
        jq -cS '.architecture = "arm64"' "$config_blob" > "$work/arm64-config.json"
        arm64_config_digest=sha256:$(sha256sum "$work/arm64-config.json" | cut -d' ' -f1)
        arm64_config_size=$(wc -c < "$work/arm64-config.json")
        jq -cS \
          --arg digest "$arm64_config_digest" \
          --argjson size "$arm64_config_size" \
          '.config.digest = $digest | .config.size = $size' \
          "$work/amd64-manifest.json" > "$work/arm64-manifest.json"
        arm64_manifest_digest=sha256:$(sha256sum "$work/arm64-manifest.json" | cut -d' ' -f1)
        arm64_manifest_size=$(wc -c < "$work/arm64-manifest.json")
        jq -cS \
          --arg digest "$arm64_manifest_digest" \
          --argjson size "$arm64_manifest_size" \
          '.manifests += [(.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest = $digest | .size = $size | .platform.architecture = "arm64")]' \
          "$work/production-index.json" > "$work/multi-index.json"
        multi_digest=sha256:$(sha256sum "$work/multi-index.json" | cut -d' ' -f1)

        upload_blob() {{
          file=$1
          digest=$2
          headers="$work/upload.headers"
          {CURL} -fsS -D "$headers" -o /dev/null -X POST \
            -H 'Content-Length: 0' \
            -H 'Authorization: Bearer {token}' \
            {OCI}/v2/aos/blobs/uploads/
          location=$(sed -n 's/^location: *//ip' "$headers" | tr -d '\r' | tail -n1)
          test -n "$location"
          case "$location" in http*) ;; *) location={OCI}$location ;; esac
          {CURL} -fsS -o /dev/null -X PATCH \
            -H 'Content-Type: application/octet-stream' \
            -H 'Authorization: Bearer {token}' \
            --data-binary @"$file" "$location"
          case "$location" in *\?*) separator='&' ;; *) separator='?' ;; esac
          {CURL} -fsS -o /dev/null -X PUT \
            -H 'Content-Length: 0' \
            -H 'Authorization: Bearer {token}' \
            "$location$separator"digest="$digest"
        }}

        upload_blob "$work/arm64-config.json" "$arm64_config_digest"
        {CURL} -fsS -o /dev/null -X PUT \
          -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
          -H 'Authorization: Bearer {token}' \
          --data-binary @"$work/arm64-manifest.json" \
          {OCI}/v2/aos/manifests/$arm64_manifest_digest
        {CURL} -fsS -o /dev/null -X PUT \
          -H 'Content-Type: application/vnd.oci.image.index.v1+json' \
          -H 'Authorization: Bearer {token}' \
          --data-binary @"$work/multi-index.json" \
          {OCI}/v2/aos/manifests/multi
        printf '%s\n' "$multi_digest"
    """), timeout=900).strip()
    assert multi_root.startswith("sha256:"), multi_root

    def repository_token(machine, origin, service, repository, actions, secret=None):
        authorization = ""
        if secret is not None:
            authorization = f"-u qualification:{shlex.quote(secret)} "
        query = (
            f"service={service}&scope=repository:{repository}:{actions}"
        )
        response = machine.succeed(
            f"{CURL} -fsS {authorization}{shlex.quote(origin + '/v2/token?' + query)}"
        )
        return json.loads(response)["token"]

    public_pull_token = repository_token(
        consumer, OCI, "hub:8443", "aos", "pull"
    )
    multi_index = json.loads(consumer.succeed(
        f"{CURL} -fsS "
        "-H 'Accept: application/vnd.oci.image.index.v1+json' "
        f"-H 'Authorization: Bearer {public_pull_token}' "
        f"{OCI}/v2/aos/manifests/multi"
    ))
    multi_platforms = {
        (item["platform"]["os"], item["platform"]["architecture"])
        for item in multi_index["manifests"]
    }
    assert multi_platforms == {("linux", "amd64"), ("linux", "arm64")}, multi_index
    manifest_headers = consumer.succeed(
        f"{CURL} -fsS -D - -o /var/tmp/aos-index.json "
        "-H 'Accept: application/vnd.oci.image.index.v1+json' "
        f"-H 'Authorization: Bearer {public_pull_token}' "
        f"{OCI}/v2/aos/manifests/latest"
    )
    assert "200" in manifest_headers.splitlines()[0], manifest_headers
    fetched_index_sha256 = consumer.succeed(
        f"{pkgs.coreutils}/bin/sha256sum /var/tmp/aos-index.json"
    ).split()[0]
    assert root_digest == f"sha256:{fetched_index_sha256}", root_digest

    index = json.loads(consumer.succeed("cat /var/tmp/aos-index.json"))
    amd64_descriptor = next(
        descriptor
        for descriptor in index["manifests"]
        if descriptor.get("platform", {}).get("architecture") == "amd64"
    )
    amd64_digest = amd64_descriptor["digest"]
    consumer.succeed(
        f"{CURL} -fsS -o /var/tmp/aos-manifest.json "
        "-H 'Accept: application/vnd.oci.image.manifest.v1+json' "
        f"-H 'Authorization: Bearer {public_pull_token}' "
        f"{OCI}/v2/aos/manifests/{amd64_digest}"
    )
    image_manifest = json.loads(consumer.succeed("cat /var/tmp/aos-manifest.json"))
    first_layer = image_manifest["layers"][0]["digest"]
    range_headers = consumer.succeed(
        f"{CURL} -fsS -D - -o /var/tmp/aos-layer-prefix "
        "-H 'Range: bytes=0-63' "
        f"-H 'Authorization: Bearer {public_pull_token}' "
        f"{OCI}/v2/aos/blobs/{first_layer}"
    )
    assert "206" in range_headers.splitlines()[0], range_headers
    assert "content-range: bytes 0-63/" in range_headers.lower(), range_headers
    consumer.succeed("test $(wc -c < /var/tmp/aos-layer-prefix) -eq 64")
    # ORAS compatibility is exercised at its standard Distribution/referrers
    # protocol boundary; the repository deliberately ships no ORAS binary.
    referrers = json.loads(consumer.succeed(
        f"{CURL} -fsS "
        "-H 'Accept: application/vnd.oci.image.index.v1+json' "
        f"-H 'Authorization: Bearer {public_pull_token}' "
        f"{OCI}/v2/aos/referrers/{signed_root}"
    ))
    assert referrers["manifests"], referrers

    # A wrong digest never aliases valid bytes. A resumable upload survives
    # client disconnect between PATCH requests, reports its durable offset,
    # and rejects a final digest that does not match the accumulated bytes.
    push_token = repository_token(
        consumer, OCI, "hub:8443", "resume", "pull,push", client_secret
    )
    consumer.succeed(textwrap.dedent(f"""
        set -euo pipefail
        headers=/var/tmp/resume-start.headers
        {CURL} -fsS -D "$headers" -o /dev/null -X POST \
          -H 'Content-Length: 0' \
          -H 'Authorization: Bearer {push_token}' \
          {OCI}/v2/resume/blobs/uploads/
        location=$(sed -n 's/^location: *//ip' "$headers" | tr -d '\r' | tail -n1)
        test -n "$location"
        case "$location" in http*) ;; *) location={OCI}$location ;; esac
        printf first > /var/tmp/resume-first
        {CURL} -fsS -o /dev/null -X PATCH \
          -H 'Content-Type: application/octet-stream' \
          -H 'Authorization: Bearer {push_token}' \
          --data-binary @/var/tmp/resume-first "$location"
        {CURL} -fsS -D /var/tmp/resume-status.headers -o /dev/null \
          -H 'Authorization: Bearer {push_token}' "$location"
        grep -Eiq '^range: *(bytes=)?0-4\r?$' /var/tmp/resume-status.headers
        printf second > /var/tmp/resume-second
        {CURL} -fsS -o /dev/null -X PATCH \
          -H 'Content-Type: application/octet-stream' \
          -H 'Authorization: Bearer {push_token}' \
          --data-binary @/var/tmp/resume-second "$location"
        wrong=sha256:0000000000000000000000000000000000000000000000000000000000000000
        if {CURL} -fsS -o /var/tmp/resume-wrong.out -X PUT \
          -H 'Content-Length: 0' \
          -H 'Authorization: Bearer {push_token}' \
          "$location&digest=$wrong"; then
          exit 1
        fi
        {CURL} -fsS -o /dev/null -X DELETE \
          -H 'Authorization: Bearer {push_token}' "$location"
    """))

    consumer.succeed(
        f"{AOS} --json --progress off --color never container pull "
        "hub:8443/aos:latest --hub https://hub:8443 "
        "--platform linux/amd64 --format oci-layout "
        "--output /var/tmp/aos-public-tag",
        timeout=900,
    )
    consumer.succeed(
        f"{AOS} --json --progress off --color never container pull "
        f"hub:8443/aos@{root_digest} --hub https://hub:8443 "
        "--platform linux/amd64 --format oci-layout "
        "--output /var/tmp/aos-public-digest",
        timeout=900,
    )
    consumer.succeed(
        f"{AOS} --json --progress off --color never container pull "
        "hub:8443/aos:stable --hub https://hub:8443 "
        "--platform linux/amd64 --format oci-layout "
        "--output /var/tmp/aos-signed-stable",
        timeout=900,
    )
    for architecture in ("amd64", "arm64"):
        consumer.succeed(
            f"{AOS} --json --progress off --color never container pull "
            "hub:8443/aos:multi --hub https://hub:8443 "
            f"--platform linux/{architecture} --format oci-layout "
            f"--output /var/tmp/aos-multi-{architecture}",
            timeout=900,
        )
    consumer.fail(
        f"{AOS} --json --progress off --color never container pull "
        "hub:8443/aos@sha256:0000000000000000000000000000000000000000000000000000000000000000 "
        "--hub https://hub:8443 --output /var/tmp/aos-wrong-digest"
    )
    consumer.fail(
        f"{AOS} --json --progress off --color never container pull "
        "192.168.50.11:8443/aos:private --hub https://192.168.50.11:8443 "
        "--output /var/tmp/aos-private-anonymous"
    )
    client_grant = json.loads(consumer.succeed(
        f"{CURL} -fsS -X POST "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        f"-H 'Authorization: Bearer {client_secret}' "
        "--data-urlencode "
        "'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
        f"{HUB}/oauth2/token"
    ))
    client_bearer = client_grant["access_token"]
    consumer.succeed(
        f"{AOS} --json --progress off --color never container pull "
        "192.168.50.11:8443/aos:private --hub https://192.168.50.11:8443 "
        f"--token {shlex.quote(client_bearer)} --output /var/tmp/aos-private",
        timeout=900,
    )
    consumer.succeed(
        f"{AOS} --json --progress off --color never container pull "
        f"192.168.50.11:8443/aos@{root_digest} "
        "--hub https://192.168.50.11:8443 "
        f"--token {shlex.quote(client_bearer)} "
        "--output /var/tmp/aos-private-digest",
        timeout=900,
    )

    # Positive read/admin porcelain. The graph is a real production image;
    # repository and tag mutations use the reviewed plan/apply contract.
    repositories = json.loads(publisher.succeed(
        hub_command("registry container repository list acme/containers", token)
    ))["data"]["repositories"]
    assert any(item["name"] == "aos" for item in repositories), repositories
    repository = json.loads(publisher.succeed(
        hub_command("registry container repository show acme/containers aos", token)
    ))["data"]["repository"]
    assert repository["distribution_reference"] == "hub:8443/aos", repository
    reviewed(
        publisher,
        "aos-repository-description",
        "registry container repository update acme/containers aos "
        "--description 'Production AOS base image'",
        token,
    )
    reviewed(
        publisher,
        "empty-repository-create",
        "registry container repository create acme/containers empty "
        "--description 'Delete lifecycle fixture'",
        token,
    )
    publisher.succeed(hub_command(
        "registry container repository show acme/containers empty", token
    ))
    reviewed(
        publisher,
        "empty-repository-update",
        "registry container repository update acme/containers empty "
        "--clear-description",
        token,
    )
    reviewed(
        publisher,
        "empty-repository-delete",
        "registry container repository delete acme/containers empty",
        token,
    )

    tags = json.loads(publisher.succeed(hub_command(
        "registry container tag list acme/containers aos", token
    )))["data"]["tags"]
    latest = next(item for item in tags if item["name"] == "latest")
    assert latest["digest"] == root_digest, latest
    publisher.succeed(hub_command(
        "registry container tag show acme/containers aos latest", token
    ))
    publisher.succeed(hub_command(
        "registry container tag resolve acme/containers aos latest", token
    ))
    publisher.succeed(hub_command(
        "registry container tag history acme/containers aos latest", token
    ))
    stable = json.loads(publisher.succeed(hub_command(
        "registry container tag show acme/containers aos stable", token
    )))["data"]["tag"]
    assert stable["digest"] == signed_root, stable
    publisher.fail(hub_command(
        "registry container tag set acme/containers aos stable "
        f"--digest {signed_root} --plan --idempotency-key signed-tag-set-denied",
        token,
    ))
    publisher.fail(hub_command(
        "registry container tag unset acme/containers aos stable "
        f"--if-digest {signed_root} --plan --idempotency-key signed-tag-unset-denied",
        token,
    ))
    reviewed(
        publisher,
        "candidate-tag-set",
        "registry container tag set acme/containers aos candidate "
        f"--digest {root_digest}",
        token,
    )
    reviewed(
        publisher,
        "candidate-tag-unset",
        "registry container tag unset acme/containers aos candidate "
        f"--if-digest {root_digest}",
        token,
    )

    publisher.succeed(hub_command(
        "registry container manifest show acme/containers aos latest", token
    ))
    platforms = json.loads(publisher.succeed(hub_command(
        f"registry container platform list acme/containers aos {root_digest}", token
    )))["data"]["platforms"]
    assert any(item["architecture"] == "amd64" for item in platforms), platforms
    platform = json.loads(publisher.succeed(hub_command(
        f"registry container platform show acme/containers aos {root_digest} linux/amd64",
        token,
    )))["data"]["platform"]
    assert platform["manifest_digest"] == manifest_digest, platform
    multi_hub_platforms = json.loads(publisher.succeed(hub_command(
        f"registry container platform list acme/containers aos {multi_root}", token
    )))["data"]["platforms"]
    assert {item["architecture"] for item in multi_hub_platforms} == {"amd64", "arm64"}, multi_hub_platforms
    arm64_platform = json.loads(publisher.succeed(hub_command(
        f"registry container platform show acme/containers aos {multi_root} linux/arm64",
        token,
    )))["data"]["platform"]
    assert arm64_platform["architecture"] == "arm64", arm64_platform
    layers = json.loads(publisher.succeed(hub_command(
        f"registry container layer list acme/containers aos {root_digest} "
        "--platform linux/amd64",
        token,
    )))["data"]["layers"]
    assert layers, layers
    assert any(item["shared_repository_count"] >= 2 for item in layers), layers
    layer = layers[0]
    publisher.succeed(hub_command(
        f"registry container layer show acme/containers aos {root_digest} "
        f"{manifest_digest} {layer['digest']}",
        token,
    ))
    signed_referrers = json.loads(publisher.succeed(hub_command(
        f"registry container referrer list acme/containers aos {signed_root}", token
    )))["data"]["referrers"]
    assert signed_referrers, signed_referrers
    publications = json.loads(publisher.succeed(hub_command(
        "registry container publication list acme/containers --repository aos", token
    )))["data"]["publications"]
    assert any(item["publication_id"] == publication_id for item in publications), publications
    publisher.succeed(hub_command(
        f"registry container publication show acme/containers {publication_id}", token
    ))
    publisher.succeed(hub_command(
        f"registry container provenance show acme/containers aos {signed_root} "
        f"--release {shlex.quote(signed_release)}",
        token,
    ))
    publisher.fail(hub_command(
        "registry container publication show acme/containers missing-publication", token
    ))
    publisher.fail(hub_command(
        f"registry container provenance show acme/containers aos {root_digest} "
        "--release unverified-manual-push",
        token,
    ))

    consumer.wait_for_unit("aos-container-runtime-test.service", timeout=120)
    consumer.succeed("${pkgs.containerd}/bin/containerd --version")
    consumer.succeed("${pkgs.runc}/sbin/runc --version")
    consumer.succeed("${pkgs.nerdctl}/bin/nerdctl --version")
    consumer.succeed(
        f"printf '%s\\n' {shlex.quote(client_secret)} | "
        f"${nerdctl} login --username qualification --password-stdin "
        "192.168.50.11:8443"
    )
    consumer.succeed(
        "${nerdctl} pull --platform linux/amd64 hub:8443/aos:latest",
        timeout=900,
    )
    consumer.succeed(
        "${nerdctl} pull --platform linux/amd64 hub:8443/aos:stable",
        timeout=900,
    )
    consumer.succeed(
        "${nerdctl} pull --platform linux/amd64 hub:8443/aos:multi",
        timeout=900,
    )
    consumer.succeed(
        "${nerdctl} pull --platform linux/arm64 hub:8443/aos:multi",
        timeout=900,
    )
    consumer.succeed(
        f"${nerdctl} pull --platform linux/amd64 hub:8443/aos@{root_digest}",
        timeout=900,
    )
    consumer.succeed(
        "${nerdctl} pull --platform linux/amd64 192.168.50.11:8443/aos:private",
        timeout=900,
    )
    consumer.succeed(
        f"${nerdctl} pull --platform linux/amd64 "
        f"192.168.50.11:8443/aos@{root_digest}",
        timeout=900,
    )

    # Seed one real APR/static-cache package outside the image. The pulled AOS
    # container must initialize a daemonless local Nix database, download it,
    # retain it across restart, execute it, and remove it.
    consumer.succeed(textwrap.dedent(r"""
        set -eu
        ${fixtures.setupPreamble}
        export XDG_CACHE_HOME="$HOME/.cache"
        export XDG_CONFIG_HOME="$HOME/.config"
        export XDG_DATA_HOME="$HOME/.local/share"
        export XDG_STATE_HOME="$HOME/.local/state"
        "$APR" create hub-oci-runtime
        REG_DIR="$REG_STORAGE/hub-oci-runtime"
        "$APR" publish ${fixtureTool} \
          --name hub-oci-container-tool \
          --version 1.0.0 \
          --description 'Hub OCI container install fixture' \
          --license MIT \
          --maintainer hub-oci@example.invalid \
          --registry hub-oci-runtime \
          --no-commit
        mkdir -p /var/lib/hub-oci-container-fixtures
        NIX_CONFIG='experimental-features = nix-command' \
          "$APR" cache generate \
          --registry hub-oci-runtime \
          --output /var/lib/hub-oci-container-fixtures/cache \
          --cache-url http://127.0.0.1:18120 \
          --priority 45 \
          --no-commit
        ${pkgs.git}/bin/git -C "$REG_DIR" add -A
        ${pkgs.git}/bin/git -C "$REG_DIR" commit \
          -m 'release: hub-oci-container-tool 1.0.0'
        cp -a "$REG_DIR" /var/lib/hub-oci-container-fixtures/registry
        PYTHONUNBUFFERED=1 ${pkgs.coreutils}/bin/nohup \
          ${pkgs.python3}/bin/python3 -m http.server 18120 \
          --bind 127.0.0.1 \
          --directory /var/lib/hub-oci-container-fixtures/cache \
          > /var/lib/hub-oci-container-fixtures/cache-http.log 2>&1 &
    """), timeout=240)
    consumer.wait_until_succeeds(
        f"{CURL} -fsS http://127.0.0.1:18120/nix-cache-info",
        timeout=60,
    )

    # Without the operator-provided AOS PKI bundle the private qualification
    # CA is rejected. Mounting that normal input makes the same AOS CLI call
    # succeed from inside the scratch image.
    consumer.fail(
        "${nerdctl} run --rm --net host --add-host hub:192.168.50.11 "
        "hub:8443/aos:latest /usr/bin/aos --json container inspect "
        "hub:8443/aos:latest --hub https://hub:8443"
    )
    mounts = (
        " --volume /var/lib/hub-oci-container-fixtures/registry:/fixtures/registry:ro"
        " --volume /etc/ssl/certs/ca-certificates.crt:"
        "/etc/ssl/certs/ca-certificates.crt:ro"
    )
    consumer.succeed(
        "${nerdctl} run --detach --name aos-hub-runtime --hostname aos-qualified "
        "--net host --add-host hub:192.168.50.11"
        + mounts
        + " hub:8443/aos:latest ${pkgs.coreutils}/bin/sleep infinity",
        timeout=180,
    )
    consumer.wait_until_succeeds(
        "${nerdctl} inspect --format '{{.State.Status}}' aos-hub-runtime "
        "| grep -Fx running",
        timeout=120,
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime ${pkgs.bash}/bin/bash -c "
        + shlex.quote(
            "set -eu; "
            "test \"$(cat /etc/hostname)\" = aos-qualified; "
            "grep -F aos-qualified /etc/hosts; "
            "test -s /etc/resolv.conf; "
            "grep -q MIIDHzCCAgeg /etc/ssl/certs/ca-certificates.crt; "
            "grep -q MIIDHzCCAgeg /etc/ssl/certs/ca-bundle.crt; "
            "grep -q MIIDHzCCAgeg /etc/pki/tls/certs/ca-bundle.crt; "
            "test \"$NIX_REMOTE\" = local; "
            "test ! -S /nix/var/nix/daemon-socket/socket; "
            "test -s /nix/var/nix/.aos-container-ready"
        )
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/aos --version"
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/apm --json list --installed"
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/apr --help"
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/aos --json container inspect "
        "hub:8443/aos:latest --hub https://hub:8443",
        timeout=900,
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/apm registry add "
        "--no-verify file:///fixtures/registry --name hub-oci-runtime"
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/apm install "
        "hub-oci-container-tool --registry hub-oci-runtime --yes",
        timeout=180,
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime "
        "/var/lib/profiles/per-user/root/current/bin/hub-oci-container-tool"
    )
    consumer.succeed("${nerdctl} stop --time 10 aos-hub-runtime", timeout=60)
    consumer.succeed("${nerdctl} start aos-hub-runtime", timeout=180)
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime "
        "/var/lib/profiles/per-user/root/current/bin/hub-oci-container-tool"
    )
    consumer.succeed(
        "${nerdctl} exec aos-hub-runtime /usr/bin/apm remove "
        "hub-oci-container-tool --yes",
        timeout=180,
    )
    consumer.fail(
        "${nerdctl} exec aos-hub-runtime "
        "/var/lib/profiles/per-user/root/current/bin/hub-oci-container-tool"
    )
    consumer.succeed("${nerdctl} rm --force aos-hub-runtime")

    publisher.succeed(hub_command(
        "registry container retention show acme/containers", token
    ))
    reviewed(
        publisher,
        "container-retention-set",
        "registry container retention set acme/containers "
        "--untagged-grace 1h --deleted-tag-history 1h "
        "--recent-manual-tag-revisions 2 --retain-referrers enabled",
        token,
    )

    registry = json.loads(publisher.succeed(
        hub_command("registry show acme/containers", token)
    ))["data"]["registry"]
    registry_version = registry["resource_version"]
    gc_plan = json.loads(publisher.succeed(hub_command(
        "registry container gc plan acme/containers "
        f"--if-version {shlex.quote(registry_version)} "
        "--idempotency-key hub-oci-gc-plan",
        token,
    ), timeout=240))["data"]
    gc_run = gc_plan["run"]
    gc_review = gc_plan["plan"]
    gc_run_id = gc_run["run_id"]
    publisher.succeed(hub_command(
        f"registry container gc get acme/containers {gc_run_id}", token
    ))
    publisher.succeed(hub_command(
        "registry container gc list acme/containers --resource runs", token
    ))
    publisher.succeed(hub_command(
        f"registry container gc list acme/containers --resource blockers "
        f"--run-id {gc_run_id}",
        token,
    ))
    # A retained live tag makes this a non-destructive plan. A mismatched
    # confirmation is rejected before any applying state or provider effect.
    assert gc_run["candidate_object_count"] == 0, gc_run
    publisher.fail(hub_command(
        "registry container gc apply "
        f"--plan-id {gc_review['plan_id']} "
        "--confirm-hash sha256:0000000000000000000000000000000000000000000000000000000000000000 "
        "--idempotency-key hub-oci-gc-wrong-confirm --yes",
        token,
    ))
    publisher.fail(hub_command(
        "registry container gc requeue acme/containers missing-run missing-action "
        "--if-version 1 --idempotency-key hub-oci-requeue-missing --yes",
        token,
    ))

    untracked = json.loads(publisher.succeed(hub_command(
        "registry container gc untracked list acme/containers", token
    )))["data"]
    assert not untracked.get("objects", []), untracked
    publisher.fail(hub_command(
        "registry container gc untracked repair acme/containers "
        "--placement-id 1 --inventory-generation-id missing-generation "
        "--object-key oci/blobs/sha256/"
        "0000000000000000000000000000000000000000000000000000000000000000 "
        "--if-version 1 --plan --idempotency-key hub-oci-untracked-missing",
        token,
    ))
    publisher.fail(hub_command(
        "registry container gc untracked repair-status missing-repair", token
    ))

    # Purge-fence review is intentionally not applied successfully: the live
    # public tag, catalog identity, and retained container graph are blockers.
    purge = json.loads(publisher.succeed(hub_command(
        "registry container gc purge-fence plan acme/containers "
        f"--action begin --if-version {shlex.quote(registry_version)} "
        "--idempotency-key hub-oci-purge-plan",
        token,
    )))["data"]["plan"]
    publisher.succeed(hub_command(
        f"registry container gc purge-fence status {purge['plan_id']}", token
    ))
    publisher.fail(hub_command(
        "registry container gc purge-fence apply "
        f"--plan-id {purge['plan_id']} "
        "--confirm-hash sha256:0000000000000000000000000000000000000000000000000000000000000000 "
        f"--if-version {shlex.quote(registry_version)} "
        "--idempotency-key hub-oci-purge-wrong-confirm --yes",
        token,
    ))
  '';
}
