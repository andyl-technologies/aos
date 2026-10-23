"""Adds explicit license ownership to ordinary Rust and native compilation."""

load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library")
load("@rules_rust//rust:defs.bzl", _rust_binary = "rust_binary", _rust_library = "rust_library", _rust_proc_macro = "rust_proc_macro", _rust_shared_library = "rust_shared_library")
load(":license.bzl", "license_tags")
load(":rust_package.bzl", "rust_package_attributes")

def _rust_attributes(package, license_domain, tags, attributes):
    if package != None:
        if license_domain != None and license_domain != package.license_domain:
            fail("Rust target conflicts with package license domain: " + package.name)
        license_domain = package.license_domain
        attributes = rust_package_attributes(package, attributes)
    attributes["tags"] = license_tags(tags, license_domain or "apache-host")
    return attributes

def rust_library(name, package = None, license_domain = None, tags = [], **kwargs):
    _rust_library(name = name, **_rust_attributes(package, license_domain, tags, kwargs))

def rust_binary(name, package = None, license_domain = None, tags = [], **kwargs):
    _rust_binary(name = name, **_rust_attributes(package, license_domain, tags, kwargs))

def rust_proc_macro(name, package = None, license_domain = None, tags = [], **kwargs):
    _rust_proc_macro(name = name, **_rust_attributes(package, license_domain, tags, kwargs))

def rust_shared_library(name, package = None, license_domain = None, tags = [], **kwargs):
    _rust_shared_library(name = name, **_rust_attributes(package, license_domain, tags, kwargs))

def cc_library(name, license_domain = "apache-host", tags = [], **kwargs):
    _cc_library(name = name, tags = license_tags(tags, license_domain), **kwargs)

def cc_binary(name, license_domain = "apache-host", tags = [], **kwargs):
    _cc_binary(name = name, tags = license_tags(tags, license_domain), **kwargs)
