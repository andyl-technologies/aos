"""Adds explicit license ownership to ordinary Rust and native compilation."""

load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library")
load("@rules_rust//rust:defs.bzl", _rust_binary = "rust_binary", _rust_library = "rust_library", _rust_proc_macro = "rust_proc_macro")
load(":license.bzl", "license_tags")

def rust_library(name, license_domain = "apache-host", tags = [], **kwargs):
    _rust_library(name = name, tags = license_tags(tags, license_domain), **kwargs)

def rust_binary(name, license_domain = "apache-host", tags = [], **kwargs):
    _rust_binary(name = name, tags = license_tags(tags, license_domain), **kwargs)

def rust_proc_macro(name, license_domain = "apache-host", tags = [], **kwargs):
    _rust_proc_macro(name = name, tags = license_tags(tags, license_domain), **kwargs)

def cc_library(name, license_domain = "apache-host", tags = [], **kwargs):
    _cc_library(name = name, tags = license_tags(tags, license_domain), **kwargs)

def cc_binary(name, license_domain = "apache-host", tags = [], **kwargs):
    _cc_binary(name = name, tags = license_tags(tags, license_domain), **kwargs)
