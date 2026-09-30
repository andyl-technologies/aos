##! Synthetic package fixtures used beside the production nginx provider stack.
{
  bash,
  coreutils,
  mkDerivation,
  nginx,
  python3,
  service-management,
}: let
  mkFixture = {
    pname,
    module,
    src,
    moduleDeps ? [],
  }:
    mkDerivation {
      inherit pname module src moduleDeps;
      version = "1.0.0";
      runtimeDeps = [python3];

      phases = [
        {
          name = "check-native-handler";
          script = ''
            ${python3}/bin/python3 ${./.}/test-binding-handler.py
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${pname}" "$out/bin"
            printf '%s\n' '#!${python3}/bin/python3' > "$out/bin/aos-reference-binding"
            cat ${./binding-handler.py} >> "$out/bin/aos-reference-binding"
            chmod 0555 "$out/bin/aos-reference-binding"
            printf '%s\n' 'synthetic nginx composition fixture' > "$out/share/${pname}/README"
          '';
        }
      ];

      meta = {
        description = "Synthetic nginx composition fixture";
        license = "Apache-2.0";
        mainProgram = "aos-reference-binding";
      };
    };
  backendRegistry = mkFixture {
    pname = "ability-reference-http-backend-registry";
    module = ./modules/backend-registry;
    src = ./modules/backend-registry;
  };
in {
  consumer = mkFixture {
    pname = "ability-reference-nginx-consumer";
    module = ./modules/consumer;
    moduleDeps = [service-management];
    src = ./modules/consumer;
  };

  backend-consumer = mkFixture {
    pname = "ability-reference-nginx-backend-consumer";
    module = ./modules/backend-consumer;
    moduleDeps = [service-management backendRegistry];
    src = ./modules/backend-consumer;
  };

  backend-registry = backendRegistry;

  runtime-services = mkDerivation {
    pname = "ability-reference-runtime-services";
    version = "1.0.0";
    src = ./modules/runtime-services;
    module = ./modules/runtime-services;
    moduleDeps = [service-management];
    runtimeDeps = [coreutils nginx python3];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"

          cat > "$out/bin/ability-reference-setup" <<'SCRIPT'
          #!${bash}/bin/bash
          set -eu

          ${coreutils}/bin/install -d -o root -g root -m 0700 \
            /var/lib/aos \
            /var/lib/aos/ability-reference \
            /var/lib/aos/ability-reference/nginx-main \
            /var/lib/aos/ability-reference/nginx-secondary \
            /var/lib/aos/ability-runtime/managed-configuration \
            /var/lib/aos/ability-runtime/managed-configuration/candidates \
            /var/lib/aos/ability-runtime/managed-configuration/revisions \
            /var/lib/aos/ability-runtime/nginx \
            /var/lib/aos/ability-runtime/nginx/candidates \
            /var/lib/aos/ability-runtime/nginx/validations \
            /var/lib/aos/ability-runtime/nginx/associations \
            /var/lib/aos/ability-runtime/nginx/sandbox
          ${coreutils}/bin/install -d -o root -g root -m 0755 \
            /var/lib/aos/ability-reference/backends \
            /var/lib/aos/ability-reference/backends/app-a \
            /var/lib/aos/ability-reference/backends/app-b \
            /var/lib/aos/ability-reference/backends/app-c
          SCRIPT

          cat > "$out/bin/ability-reference-matrix-start" <<'SCRIPT'
          #!${bash}/bin/bash
          exec ${coreutils}/bin/sleep infinity
          SCRIPT

          cat > "$out/bin/ability-reference-matrix-reload" <<'SCRIPT'
          #!${bash}/bin/bash
          set -eu

          ${coreutils}/bin/touch "/run/$1.reloaded"
          SCRIPT

          cat > "$out/bin/ability-reference-nginx-start" <<'SCRIPT'
          #!${bash}/bin/bash
          set -eu

          instance=$1
          exec ${nginx}/bin/nginx \
            -c "/var/lib/aos/ability-reference/$instance.conf" \
            -p "/var/lib/aos/ability-reference/$instance" \
            -g 'daemon off;'
          SCRIPT

          cat > "$out/bin/ability-reference-nginx-reload" <<'SCRIPT'
          #!${bash}/bin/bash
          set -eu

          instance=$1
          printf '%s\n' "$instance" >> /run/ability-nginx-reload.calls
          if [ "$instance" = nginx-secondary ] \
              && [ -e /run/ability-force-native-reload-failure ]; then
            echo "deliberate native reload failure for $instance" >&2
            exit 70
          fi

          exec ${nginx}/bin/nginx \
            -c "/var/lib/aos/ability-reference/$instance.conf" \
            -p "/var/lib/aos/ability-reference/$instance" \
            -s reload
          SCRIPT

          cat > "$out/bin/ability-reference-http-backend" <<'SCRIPT'
          #!${bash}/bin/bash
          set -eu

          application=$1
          port=$2
          exec ${python3}/bin/python3 -m http.server "$port" \
            --bind 127.0.0.1 \
            --directory "/var/lib/aos/ability-reference/backends/$application"
          SCRIPT

          chmod 0555 "$out"/bin/*
        '';
      }
    ];

    meta = {
      description = "Package-owned services for native ability reference tests";
      license = "Apache-2.0";
    };
  };
}
