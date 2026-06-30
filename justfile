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
