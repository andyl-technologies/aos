# Run a local AOS Hub

This tutorial starts a disposable native Hub with a real signed registry. It is
the shortest route to the web interface, API, and registry facade.

You need Nix with flakes enabled and a Linux builder.

## Build and start the Hub

From the repository root:

```sh
nix build .#pkg-aos-hub
./result/bin/aos-hub --root ./hub-demo serve --dev --seed
```

The first run creates demo data and prints a one-time publish token. Record the
token if you plan to continue into producer workflows. Leave the server running
while you work through the rest of the tutorial.

Open <http://127.0.0.1:8420/demo/cdn/>. Sign in with:

```text
Email:    demo@example.com
Password: demo
```

The seeded `demo/cdn` registry contains `curl`, `openssl`, and `jq`, along with
a signed `1.0.0` release and a `stable` channel.

## Check the HTTP surfaces

The health endpoint should report a healthy database:

```sh
curl -fsS http://127.0.0.1:8420/healthz
```

Read the registry through the unary JSON API:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"slug":"demo/cdn"}' \
  http://127.0.0.1:8420/aos.registry.v1.RegistryService/GetRegistry
```

## Stop and clean up

Stop the server with Ctrl-C. The Hub state is under `./hub-demo`; remove that
directory when you no longer need it.

`--dev` is deliberately not a production mode. It uses development-only secret
sealing and writes sign-in links to the process log. Use the
[native deployment guide](native.md) for a persistent instance.
