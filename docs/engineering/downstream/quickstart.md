# Build with AOS as your only flake input

AOS builds every package from source, starting from an audited bootstrap
seed, without nixpkgs or host tools. A downstream repository can use the same
toolchains and builders by taking AOS as its only flake input. This guide
starts such a repository, explains the cache settings it needs, and shows how
to test it against a local AOS checkout.

The builders and package attributes used here are a versioned contract,
described in the [downstream flake API](flake-api.md). Anything else in the
AOS flake may change without notice.

## Start a repository

Create the repository from the AOS template:

```sh
mkdir hello && cd hello
git init
nix flake init -t github:andyl-technologies/aos
git add .
nix build
./result/bin/hello
```

The template contains a `flake.nix` and a C program under `src/`. Its flake
has a single input:

```nix
inputs.aos.url = "github:andyl-technologies/aos";
```

Pin a release tag or commit in that URL, or rely on `flake.lock`, so every
machine builds against the same toolchains.

## Use the builders

Builders live in `aos.lib.<system>` and packages in
`aos.legacyPackages.<system>`. The template enumerates the supported systems
from `aos.lib`, then builds a package with the default phases:

```nix
packages = forAllSystems (system: let
  aosLib = aos.lib.${system};
in {
  hello = aosLib.mkDerivation {
    pname = "hello";
    version = "0.1.0";
    src = ./src;
  };
});
```

AOS builders use their own dialect rather than the nixpkgs one:

- `buildDeps` lists tools needed while building, `runtimeDeps` lists what the
  output uses at run time, and `propagatedDeps` lists what packages that
  depend on this one also need.
- `phases` is a list of `{ name; script; }` records. Replace one with
  `replacePhase`, or write the whole list.
- After the install phase, AOS strips binaries and rewrites store references
  that the output did not declare. A tool the program runs must therefore
  appear in `runtimeDeps`, or the reference is removed.

Language builders such as `mkCargoPackage` and `mkGoPackage` generate the
phases and take vendored dependencies from the matching fetcher. See the
[builder arguments](flake-api.md#builder-arguments).

A development shell uses `mkShell`:

```nix
devShells = forAllSystems (system: let
  aosPkgs = aos.legacyPackages.${system};
in {
  default = aos.lib.${system}.mkShell {
    buildDeps = [aosPkgs.cc aosPkgs.gnumake];
  };
});
```

## Configure the binary cache

Without a binary cache, the first build compiles the complete AOS toolchain
from the bootstrap seed, which takes hours. AOS publishes its packages to a
signed Nix cache. Nix reads `nixConfig` only from the flake being built, never
from its inputs, so the template repeats the AOS settings:

```nix
nixConfig = {
  extra-substituters = ["https://cdn.aos.andyl.org/andyl/experimental/"];
  extra-trusted-public-keys = [
    "andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I="
  ];
  fallback = true;
};
```

Nix asks before it applies these settings. Accept them when prompted, or pass
`--accept-flake-config`. On a multi-user installation the daemon applies them
only for trusted users; otherwise add the substituter and key to the daemon's
own `nix.conf`. `fallback = true` lets Nix build a path from source when the
cache does not have it.

## Test against a local AOS checkout

Override the input to build against uncommitted AOS changes without editing
`flake.nix`:

```sh
nix build --override-input aos path:/src/aos
nix flake check --override-input aos path:/src/aos
```

A `path:` input copies the checkout as it is on disk, including uncommitted
changes. A `git+file:` URL uses only committed files. To keep the override,
record it in the lock file:

```sh
nix flake lock --override-input aos path:/src/aos
```

Run `nix flake update aos` to return to the URL in `flake.nix`.

Packages that change in the checkout are not in the binary cache and build
locally. Unchanged toolchains still download.
