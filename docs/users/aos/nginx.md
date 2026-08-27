# Configure nginx

The `nginx` package owns the typed `nginx.*` configuration interface. Installing
the package makes the interface available; nginx starts only when the operator
sets `nginx.enable = true` and defines at least one virtual host.

```nix
{
  aos.apm.desiredPackages = ["nginx"];

  nginx = {
    enable = true;

    upstreams.application = {
      servers = [
        {address = "127.0.0.1:3000";}
        {
          address = "127.0.0.1:3001";
          backup = true;
        }
      ];
      keepalive = 16;
    };

    virtualHosts.default = {
      listen = [8080];
      serverNames = ["service.example.test"];
      locations = {
        "/" = {
          proxyPass = "http://application";
          proxySetHeaders.Host = "$host";
        };
        "/health"."return" = {
          code = 200;
          body = "healthy\n";
        };
      };
    };
  };
}
```

AOS renders `/etc/nginx/nginx.conf`, validates it with `nginx -t` before the
service starts or reloads, and reloads a running master in place when the
configuration changes. The service uses a systemd dynamic user and package
state directory; access and error logs go to the journal. The signed package
permission manifest grants host networking and `CAP_NET_BIND_SERVICE`, while
the service filesystem remains read-only except for its state and runtime
directories.

## Compose virtual hosts and upstreams

The package owns global policy and service enablement. It exposes only these
shared-root contribution surfaces to other authenticated packages:

- `nginx.virtualHosts.*`
- `nginx.upstreams.*`

A web application meta-package can therefore contribute its named virtual host
and upstream without enabling nginx or replacing global HTTP policy. The
operator must still install nginx and set `nginx.enable = true`.

## TLS credentials

TLS virtual hosts reserve certificate and private-key material through opaque
`nginx.tlsCredentials.certificate.ref` and
`nginx.tlsCredentials.privateKey.ref` values. Plaintext key or certificate
contents are not valid module values and never enter Nix evaluation, the Nix
store, or the signed configuration manifest.

The signed expose manifest declares both handles as optional. HTTP-only
configurations therefore add no systemd credential dependency. Enabling TLS
projects `tls-certificate` and `tls-private-key` from the two opaque references
before starting or reloading `nginx.service`; an absent or invalid reference
fails before the candidate generation is committed.

Resolved bytes exist only in the mode-`0600` volatile paths under
`/run/credstore/nginx/` and in systemd's per-service credential directory.
They disappear with the runtime filesystem at reboot. These destinations are
intentionally plaintext: using the encrypted credstore would implicitly
require a measured-boot PCR policy and would make ordinary runtime package
installation fail on hosts without one.

```nix
{
  nginx = {
    tlsCredentials = {
      certificate.ref = "system-credential:nginx-certificate";
      privateKey.ref = "system-credential:nginx-private-key";
    };

    virtualHosts.secure = {
      listen = [443];
      serverNames = ["secure.example.test"];
      tls.enable = true;
      locations."/"."return" = {
        code = 200;
        body = "secure\n";
      };
    };
  };
}
```

See [Manage secrets](secrets.md) for supported reference providers and
credential rotation behavior.
