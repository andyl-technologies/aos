##! Envoy proxy — pre-built binary for L7 traffic management
##!
##! Building Envoy from source requires 80+ external dependencies, 5 language
##! toolchains (C++20, Rust, Go, Python, Java 11), and 30-60 min on a 16-core
##! machine.  This uses the official pre-built binary from GitHub releases.
##! TODO: replace with from-source build when AOS has the full toolchain.
{
  mkDerivation,
  fetchurl,
  lib,
}:
let
  version = "1.37.0";

  archFiles = {
    "x86_64-linux" = {
      url = "https://github.com/envoyproxy/envoy/releases/download/v${version}/envoy-${version}-linux-x86_64";
      hash = "sha256-Clcp7k6YDTRuvO6A8Y5+/lIyuRFBu0x3bsOtzKeG5gw=";
    };
    "aarch64-linux" = {
      url = "https://github.com/envoyproxy/envoy/releases/download/v${version}/envoy-${version}-linux-aarch_64";
      hash = "sha256-9KEqySEbwO53yN2oaXIrbSih6dm2LNuX7I8g3oIA+ig=";
    };
  };

  files = archFiles.${lib.system} or (throw "envoy: unsupported system '${lib.system}'");
in
mkDerivation {
  pname = "envoy";
  inherit version;

  src = fetchurl {
    urls = [ files.url ];
    hash = files.hash;
  };

  buildDeps = [ ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cp $src $out/bin/envoy
        chmod u+wx $out/bin/envoy

        # Patch dynamic linker — envoy links only against glibc
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        BT_LIB=$(dirname "$INTERP")
        patchelf --set-interpreter "$INTERP" \
                 --set-rpath "$BT_LIB" \
                 $out/bin/envoy
      '';
    }
  ];

  meta = {
    description = "Envoy proxy — high-performance L7 proxy and communication bus";
    homepage = "https://www.envoyproxy.io";
    license = "Apache-2.0";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkVMTest {
        name = "networking-envoy-version";
        rootfsDeps = [ self ];
        testScript = ''
          OUTPUT=$(envoy --version 2>&1)
          case "$OUTPUT" in
            *"1.37"*)
              echo "==> envoy version: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected envoy version: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };

      validate-config = testing.mkVMTest {
        name = "networking-envoy-validate-config";
        rootfsDeps = [ self ];
        testScript = ''
          # Write a minimal Envoy config
          mkdir -p /tmp/envoy
          cat > /tmp/envoy/config.yaml << 'YAML'
          static_resources:
            listeners:
            - name: test_listener
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 10000
              filter_chains:
              - filters:
                - name: envoy.filters.network.http_connection_manager
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    stat_prefix: ingress_http
                    route_config:
                      name: local_route
                      virtual_hosts:
                      - name: local_service
                        domains: ["*"]
                        routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: "hello"
                    http_filters:
                    - name: envoy.filters.http.router
                      typed_config:
                        "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          YAML

          envoy --mode validate -c /tmp/envoy/config.yaml 2>&1
          case "$?" in
            0)
              echo "==> envoy validate-config: PASS"
              ;;
            *)
              echo "==> ERROR: envoy config validation failed" >&2
              exit 1
              ;;
          esac
        '';
      };
    };
}
