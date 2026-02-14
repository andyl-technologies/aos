# Deployment

> Part of the [AOS Cache Design](README.md)

## Minimal (development)

```sh
# Subdirectories (gcroots/{view}/{bin,src}/, meta/{view}/{bin,src}/, views/) auto-created
aos serve --config ./cache.toml
# Serves on http://127.0.0.1:5000
```

## Production

```
   Internet
      │
      ▼
  ┌────────┐
  │ Caddy  │  (TLS termination, rate limiting)
  │ :443   │
  └───┬────┘
      │ proxy_pass
      ▼
  ┌──────────────┐
  │ aos serve    │
  │ :5000 or     │
  │ /run/aos/    │
  └──────────────┘

  systemd unit: aos-serve.service
  systemd timer: aos-gc.timer (hourly GC)
```

## systemd unit

See §15.5 for the full systemd service definition with graceful shutdown
(`KillMode=mixed`, `TimeoutStopSec=90s`, `Type=notify`). The service runs
as a dedicated `aos-serve` user in the `nix-daemon` group.

## Client configuration

```nix
# On a client machine, add the cache as a substituter:
nix.settings = {
  substituters = [ "https://cache.example.com/ci" ];
  trusted-public-keys = [ "cache.example.com-1:AAAA..." ];
};
```

Or per-command:
```sh
nix build --substituters 'http://cache:5000/ci?auth=TOKEN' \
          --trusted-public-keys 'cache-1:AAAA...'
```
