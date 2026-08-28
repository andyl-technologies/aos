# Configure Envoy

Install `envoy`, then configure its package-owned `envoy.*` module interface
from `host.nix` or an applied runtime module. The service validates every
candidate bootstrap with Envoy before activation.

```nix
{
  aos.apm.desiredPackages = ["envoy"];
  aos.firewall.allowedTCPPorts = [10000];

  envoy = {
    enable = true;
    node = {
      id = "edge-proxy-1";
      cluster = "edge";
    };

    listeners.http = {
      address = "0.0.0.0";
      port = 10000;
      filterChains.http.virtualHosts.local = {
        domains = ["*"];
        routes.health = {
          match.path = "/health";
          match.prefix = null;
          directResponse = {
            status = 200;
            body = "healthy";
          };
        };
      };
    };
  };
}
```

Listeners, clusters, endpoints, virtual hosts, routes, health checks, circuit
breakers, runtime layers, ADS/LDS/CDS/SDS, the loopback admin interface, and a
StatsD sink are typed. A filter chain selects exactly one HTTP virtual-host set
or TCP proxy cluster, and each HTTP route selects exactly one match and action.
Cross-references and duplicate listener sockets fail evaluation.

The administration access log defaults to
`/var/log/aos-pkg-envoy/admin-access.log`, in Envoy's systemd-managed log
directory. Set `envoy.admin.accessLogPath` to `/dev/null` to disable it.

Listener ports are runtime values and do not silently expand the package's
signed network permissions. Add externally reachable ports explicitly through
the AOS firewall module, as in the example.

## TLS and xDS credentials

TLS certificate, private-key, and validation-CA values are opaque references;
secret bytes are never valid Nix values. Static TLS contexts refer to the
signed optional handles `tls-certificate`, `tls-private-key`, and
`validation-ca` through `envoy.credentials`:

```nix
{
  envoy.credentials = {
    tls-certificate.ref = "system-credential:envoy-certificate";
    tls-private-key.ref = "system-credential:envoy-private-key";
    validation-ca.ref = "tpm2-credstore:envoy-validation-ca";
  };
}
```

The handles become systemd credential bindings only when a configured TLS
context references them. HTTP-only configurations do not require TLS files.
SDS values name xDS resources, not secret contents, and require ADS to be
enabled. The administration API is restricted to a loopback address.

See [Manage secrets](secrets.md) for credential providers and rotation.
