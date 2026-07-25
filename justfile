# AOS Build System
# Thin convenience layer over the `aos` CLI

set positional-arguments

AOS := "nix run . --"

default:
    @just --list

# ===========================================================================
# Package Building
# ===========================================================================

# Build a specific package
build pkg:
    {{AOS}} build {{pkg}}

# Build all packages
build-all:
    {{AOS}} build --all

# Show package metadata
show pkg:
    {{AOS}} show {{pkg}}

# Show dependency graph
graph pkg:
    {{AOS}} graph {{pkg}}

# Show dependency graph in DOT format
graph-dot pkg:
    {{AOS}} graph {{pkg}} --dot

# Validate package definitions
lint pkg="":
    {{AOS}} lint {{pkg}}

# ===========================================================================
# System Operations
# ===========================================================================

# Build the default system closure
system-build:
    {{AOS}} system build

# Build the default bootable disk image
system-image:
    {{AOS}} system image

# Evaluate a system configuration (show as JSON)
system-eval:
    {{AOS}} system eval

# ===========================================================================
# Testing
# ===========================================================================

# Run all test layers (eval → build → vm → fleet)
test:
    {{AOS}} test

# Run the native cache-validation smoke matrix against the zlib witness
cache-validation-smoke:
    nix run . -- nix-diff --smoke --cache-validation --mode=byte -- default.nix

# Run eval checks only
test-eval:
    {{AOS}} test eval

# Run build checks only
test-build:
    {{AOS}} test build

# Run VM integration tests (all suites or a specific one)
test-vm suite="":
    {{AOS}} test vm {{suite}}

# Run fleet integration tests (all suites or a specific one)
test-fleet suite="":
    {{AOS}} test fleet {{suite}}

# Run the deployed-Worker e2e: boots the wasm artifact under workerd+miniflare
# and asserts the live request surface. Built in-sandbox, exec'd outside it
# (workerd's tcmalloc needs /sys, like fleet VM tests need /dev/kvm).
test-worker-e2e:
    bin=`nix-build -A pkgs.aos-hub-worker-e2e --no-out-link`; exec "$bin/bin/aos-hub-worker-e2e"

# Run the deployed-Worker DO-SQLite e2e: boots the wasm under the from-source
# workerd with a real SQLite-backed HubDb Durable Object (enableSql) and asserts
# the managed-registry bootstrap (create org -> binding-less managed registry ->
# ListRegistries/GetRegistry reads). Regression guard for the bound-NULL
# corruption (#138-adjacent). Exec'd outside the sandbox (workerd needs /sys).
test-worker-do-e2e:
    bin=`nix-build -A pkgs.aos-hub-worker-do-e2e --no-out-link`; exec "$bin/bin/aos-hub-worker-do-e2e"

# ===========================================================================
# Worker (serverless) deployment
# ===========================================================================

# Run the bundled hub installer (wrangler + node + the Worker wasm). Forwards
# args to `aos-hub`, e.g.:
#   just hub worker install --external-url https://reg.example.com --root-email a@b.c --root-password-stdin
#   just hub worker deploy  --external-url https://reg.example.com
#   just hub init --target d1:aos-hub --root-email a@b.c --root-password-stdin
#   just hub reset-root --target d1:aos-hub --email a@b.c --password-stdin
# Requires CLOUDFLARE_API_TOKEN (or `wrangler login`). See
# crates/aos-hub-worker/deploy/DEPLOY.md.
hub *args:
    `nix-build -A pkgs.aos-hub-cloudflare --no-out-link`/bin/aos-hub {{args}}

# ===========================================================================
# Development
# ===========================================================================

# Enter development shell
shell:
    nix develop

# Interactive Nix REPL with full system loaded
repl:
    {{AOS}} repl

# Debug why a package depends on another
why-depends pkg dep:
    {{AOS}} why-depends {{pkg}} {{dep}}

# Show repository info
describe:
    {{AOS}} describe

# ===========================================================================
# Maintenance
# ===========================================================================

# Garbage-collect old store paths
gc:
    {{AOS}} gc

# List system generations
gc-list:
    {{AOS}} gc --list-generations

# ===========================================================================
# CLI
# ===========================================================================

# Build the aos CLI from source
cli-build:
    cargo build --manifest-path crates/Cargo.toml -p aos --release

# Generate shell completions
completions shell="bash":
    {{AOS}} completions {{shell}}

# ===========================================================================
# Quick Workflows
# ===========================================================================

# Build the default image
quick:
    {{AOS}} system image

# Full pipeline: run tests, then build the default image
full: test
    {{AOS}} system image

# ===========================================================================
# Direct Nix (bypass CLI)
# ===========================================================================

# Build a package directly via nix-build
nix-build attr:
    nix-build -A {{attr}}

# Evaluate an attribute to JSON
nix-eval attr:
    nix-instantiate --eval --strict --json -A {{attr}}
