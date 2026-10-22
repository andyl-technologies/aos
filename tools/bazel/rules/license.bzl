"""Rejects incompatible license domains along compiled dependency edges."""

AosLicenseInfo = provider(fields = ["domains"])

DOMAINS = ["apache-host", "permissive-protocol", "gpl-qemu"]

def license_tags(tags, domain):
    if domain not in DOMAINS:
        fail("unknown AOS license domain: " + domain)
    if any([tag.startswith("aos-license:") for tag in tags]):
        fail("use license_domain instead of overriding license tags")
    return tags + ["aos-license:" + domain]

def check_domains(owner, domain, dependencies):
    allowed = [domain, "permissive-protocol"]
    for dependency in dependencies:
        if dependency not in allowed:
            fail("AOS license boundary: %s (%s) cannot link %s" % (owner, domain, dependency))

def _license_impl(target, ctx):
    if ctx.rule == None:
        return [AosLicenseInfo(domains = depset())]
    inherited = []
    for name in ["deps", "implementation_deps", "link_deps", "dynamic_deps", "crate", "actual"]:
        value = getattr(ctx.rule.attr, name, [])
        for dependency in value if type(value) == "list" else [value]:
            if type(dependency) == "Target" and AosLicenseInfo in dependency:
                inherited.append(dependency[AosLicenseInfo].domains)
    dependencies = depset(transitive = inherited)
    domains = [tag[len("aos-license:"):] for tag in getattr(ctx.rule.attr, "tags", []) if tag.startswith("aos-license:")]
    if not domains and str(target.label) in [
        "@@bazel_tools//tools/cpp:malloc",
        "@@bazel_tools//tools/cpp:link_extra_lib",
        "@@rules_cc+//:link_extra_lib",
        "@@rules_cc+//:empty_lib",
        "@@rules_rust+//ffi/rs:empty_allocator_libraries",
        "@@rules_rust+//ffi/rs:empty",
    ]:
        # These pinned Apache-licensed rule support targets are not first-party
        # application code. Other compiled dependencies require declarations.
        domains = ["permissive-protocol"]
    compiled = ctx.rule.kind in ["rust_library", "rust_binary", "rust_proc_macro", "rust_test", "cc_library", "cc_binary", "cc_shared_library", "cc_import"]
    if compiled and len(domains) != 1:
        fail("AOS license boundary: compiled target requires one license_domain: " + str(target.label))
    if len(domains) > 1 or any([domain not in DOMAINS for domain in domains]):
        fail("AOS license boundary: invalid license declaration: " + str(target.label))
    for domain in domains:
        check_domains(target.label, domain, dependencies.to_list())
    return [AosLicenseInfo(domains = depset(domains, transitive = inherited))]

# Generators and compiler plugins execute in separate processes. Their inputs
# are not linked into the consumer; each compiled plugin is checked on its own.
aos_license_aspect = aspect(
    implementation = _license_impl,
    attr_aspects = ["deps", "implementation_deps", "link_deps", "dynamic_deps", "crate", "actual", "proc_macro_deps"],
)
