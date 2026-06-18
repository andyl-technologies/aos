# AOS Build System
# Thin convenience layer over the `aos` CLI

set positional-arguments

AOS := "./cli/target/release/aos"

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

# Build a system variant closure
system-build variant="server":
    {{AOS}} system build {{variant}}

# Build a bootable disk image
system-image variant="server":
    {{AOS}} system image {{variant}}

# Evaluate a system configuration (show as JSON)
system-eval variant="server":
    {{AOS}} system eval {{variant}}

# ===========================================================================
# Testing
# ===========================================================================

# Run all test layers (eval → build → vm → fleet)
test:
    {{AOS}} test

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
    bin=`nix-build -A pkgs.aos-registry-worker-e2e --no-out-link`; exec "$bin/bin/aos-registry-worker-e2e"

# ===========================================================================
# Worker (serverless) deployment
# ===========================================================================

# Run the bundled hub installer (wrangler + node + the Worker wasm). Forwards
# args to `aos-registry-hub`, e.g.:
#   just hub worker install --external-url https://reg.example.com --root-email a@b.c --root-password-stdin
#   just hub worker deploy  --external-url https://reg.example.com
#   just hub init --target d1:aos-registry-hub --root-email a@b.c --root-password-stdin
#   just hub reset-root --target d1:aos-registry-hub --email a@b.c --password-stdin
# Requires CLOUDFLARE_API_TOKEN (or `wrangler login`). See
# crates/aos-registry-worker/deploy/DEPLOY.md.
hub *args:
    `nix-build -A pkgs.aos-registry-hub-cloudflare --no-out-link`/bin/aos-registry-hub {{args}}

# ===========================================================================
# Development
# ===========================================================================

# Enter development shell
shell:
    {{AOS}} shell

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
    cd cli && cargo build --release

# Generate shell completions
completions shell="bash":
    {{AOS}} completions {{shell}}

# ===========================================================================
# Quick Workflows
# ===========================================================================

# Build CLI + specific image in one step
quick variant="server": cli-build
    {{AOS}} system image {{variant}}

# Full pipeline: build CLI, run tests, build server image
full: cli-build test
    {{AOS}} system image server

# ===========================================================================
# Direct Nix (bypass CLI)
# ===========================================================================

# Build a package directly via nix-build
nix-build attr:
    nix-build -A {{attr}}

# Evaluate an attribute to JSON
nix-eval attr:
    nix-instantiate --eval --strict --json -A {{attr}}
