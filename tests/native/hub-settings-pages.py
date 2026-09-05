"""Audits every canonical Hub settings page without mutating fixture state.

The driver reuses the real Chrome DevTools transport from ``hub-settings-browser``.
It signs in to an isolated native fixture, discovers each scope's visible settings
navigation and create links, then records page semantics, layout width, requests,
and a bounded desktop/narrow screenshot set.  It never submits a mutation form.
"""

import argparse
import base64
import importlib.util
import json
from pathlib import Path
import time
import urllib.parse


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hub_settings_browser", HERE / "hub-settings-browser.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load hub-settings-browser.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ChromePipe = MODULE.ChromePipe
DevToolsError = MODULE.DevToolsError


# Keep the browser matrix explicit rather than deriving it from the visible
# navigation. Create pages are deliberately absent from persistent navigation,
# and a permissions change must not silently reduce coverage. These paths mirror
# the final route contract in aos-hub-console-contract.
INSTANCE_SUFFIXES = (
    "",
    "bindings", "bindings/new", "domains", "domains/new",
    "network-policies", "network-policies/new", "endpoints", "endpoints/new",
    "gateways", "gateways/new", "topology-defaults", "identity-and-signup",
    "tokens", "resource-defaults", "branding", "operations",
)
ORGANIZATION_SUFFIXES = (
    "", "projects", "projects/new", "registries", "registries/new", "caches",
    "caches/new", "bindings", "bindings/new", "domains", "domains/new",
    "network-policies", "network-policies/new", "endpoints", "endpoints/new",
    "gateways", "gateways/new", "topology-defaults", "identity-and-access",
    "members", "sso", "signing-keys", "tokens", "webhooks", "operations",
    "audit-log", "danger",
)
REGISTRY_SUFFIXES = (
    "", "placements", "delivery", "caches", "access", "signing-keys", "tokens",
    "containers", "mirror", "configuration", "changes", "publish-history", "operations",
    "danger",
)
CACHE_SUFFIXES = (
    "", "placements", "delivery", "objects", "integrations", "access",
    "signing-keys", "tokens", "retention", "garbage-collection", "operations", "danger",
)

# These endpoints use 404 to express an optional, not-yet-configured resource.
# The page must still render a normal empty/configuration state; unknown 4xx/5xx
# responses remain failures.
EXPECTED_ABSENCE_PATHS = {
    "/aos.hub.v1.IdentityService/GetIdentityProvider",
    "/aos.hub.v1.SigningKeyService/GetSigningKeyUsage",
}


class Audit:
    def __init__(self, chrome, url, email, password, output, timeout):
        self.chrome, self.url = chrome, url.rstrip("/")
        self.email, self.password, self.output, self.timeout = email, password, output, timeout
        self.checks, self.pages, self.failures, self.screenshots = [], [], [], []
        self.expected_absences = []

    def check(self, condition, detail):
        if not condition:
            raise AssertionError(detail)
        self.checks.append(detail)
        print(f"PASS {detail}", flush=True)

    def wait(self, expression, detail):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                if self.chrome.evaluate(expression):
                    return
            except DevToolsError:
                pass
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for {detail}")

    def navigate(self, path):
        self.chrome.call("Page.navigate", {"url": urllib.parse.urljoin(self.url + "/", path.lstrip("/"))})
        self.wait("document.readyState === 'complete'", path)
        self.wait("document.querySelector('main.settings-body, form[action=\"/login/password\"]') !== null", path)
        self.chrome.drain_events(0.15)

    def redirect(self, path, destination):
        self.chrome.call("Page.navigate", {"url": urllib.parse.urljoin(self.url + "/", path.lstrip("/"))})
        self.wait("document.readyState === 'complete'", path)
        self.wait(f"location.pathname === {json.dumps(destination)}", f"{path} redirect")
        self.check(True, f"{path} redirects to its public catalog")

    def login(self):
        self.navigate("/login?next=/-/instance")
        email, password = json.dumps(self.email), json.dumps(self.password)
        self.chrome.evaluate(f'''(() => {{
          const f=document.querySelector('form[action="/login/password"]');
          const put=(n,v)=>{{const s=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;s.call(n,v);n.dispatchEvent(new Event('input',{{bubbles:true}}));}};
          put(f.elements.email,{email}); put(f.elements.password,{password}); f.requestSubmit(); return true;
        }})()''')
        self.wait("location.pathname === '/-/instance' && document.querySelector('main.settings-body') !== null", "authenticated shell")

    def links(self):
        return self.chrome.evaluate("Array.from(document.querySelectorAll('.settings-nav a[href], main a[href]'), a => a.getAttribute('href')).filter(Boolean)") or []

    def screenshot(self, label):
        safe = "".join(c if c.isalnum() else "-" for c in label).strip("-")[:72]
        for suffix, width, height in (("desktop", 1440, 1000), ("narrow", 390, 844)):
            self.chrome.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": suffix == "narrow"})
            self.check(self.chrome.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), f"{label} {suffix} has no horizontal overflow")
            shot = self.chrome.call("Page.captureScreenshot", {"format": "png", "fromSurface": True, "captureBeyondViewport": True})
            target = self.output / f"{len(self.screenshots)//2 + 1:02d}-{safe}-{suffix}.png"
            target.write_bytes(base64.b64decode(shot["data"]))
            self.screenshots.append(str(target))
        self.chrome.call("Emulation.clearDeviceMetricsOverride")

    def inspect(self, path):
        self.navigate(path)
        self.wait("document.querySelector('.scope-header') !== null", f"{path} scope header")
        self.wait("document.querySelector('.loading-row') === null", f"{path} data")
        state = self.chrome.evaluate("""(() => ({
          path: location.pathname, heading: document.querySelector('.scope-header h1')?.textContent.trim() || '',
          forms: document.querySelectorAll('form').length,
          fields: document.querySelectorAll('input, select, textarea').length,
          buttons: document.querySelectorAll('button, input[type="submit"]').length,
          disabledControls: document.querySelectorAll('button:disabled, input:disabled, select:disabled, textarea:disabled').length,
          details: document.querySelectorAll('details').length,
          openDetails: document.querySelectorAll('details[open]').length,
          empty: Array.from(document.querySelectorAll('.empty-state,.muted')).map(x=>x.textContent.trim()).filter(Boolean).slice(0,4),
          errors: Array.from(document.querySelectorAll('.fatal-page,.inline-error')).map(x=>x.textContent.trim()),
          width: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
        }))()""")
        self.check(bool(state["heading"]), f"{path} has a scope heading")
        if state["errors"]:
            self.failures.append(f"{path}: {' | '.join(state['errors'])}")
            print(f"FAIL {path} rendered error", flush=True)
        else:
            self.check(True, f"{path} has no rendered error")
        self.check(state["scrollWidth"] <= state["width"], f"{path} fits its current viewport")
        self.pages.append(state)
        if state["details"]:
            self.chrome.evaluate("document.querySelectorAll('details').forEach(detail => detail.open = true)")
            self.wait(
                f"document.querySelectorAll('details[open]').length === {state['details']}",
                f"{path} advanced disclosures",
            )
            state["openDetails"] = self.chrome.evaluate("document.querySelectorAll('details[open]').length")
            self.check(state["openDetails"] == state["details"], f"{path} opens its advanced disclosures")
        self.screenshot(path)

    def exercise(self):
        self.login()
        def paths(base, suffixes):
            return [base if not suffix else f"{base}/{suffix}" for suffix in suffixes]

        canonical_paths = ["/-/orgs", "/-/orgs/new", "/-/caches"]
        canonical_paths += paths("/-/instance", INSTANCE_SUFFIXES)
        canonical_paths += paths("/-/org/workflow-test", ORGANIZATION_SUFFIXES)
        canonical_paths += paths("/workflow-test/main/-/settings", REGISTRY_SUFFIXES)
        canonical_paths += paths("/-/org/workflow-test/caches/builds", CACHE_SUFFIXES)
        self.check(len(canonical_paths) == 73, "canonical route matrix contains all 73 settings pages")
        for path in canonical_paths:
            self.inspect(path)
        catalog_redirects = {
            "/workflow-test/main/-/settings/packages": "/workflow-test/main/-/packages",
            "/workflow-test/main/-/settings/documentation": "/workflow-test/main/-/docs",
            "/workflow-test/main/-/settings/images": "/workflow-test/main/-/images",
            "/workflow-test/main/-/settings/channels": "/workflow-test/main/-/channels",
        }
        for old_path, destination in catalog_redirects.items():
            self.redirect(old_path, destination)
        self.chrome.drain_events(0.25)
        self.check(not self.chrome.javascript_errors, "no JavaScript exceptions during settings audit")
        self.check(not self.chrome.console_errors, "no console errors during settings audit")
        unexpected_network_failures = []
        for failure in self.chrome.network_failures:
            if failure["status"] == 404 and failure["path"] in EXPECTED_ABSENCE_PATHS:
                self.expected_absences.append(failure)
            else:
                unexpected_network_failures.append(failure)
        self.check(
            not unexpected_network_failures,
            "no unexpected failed tracked settings requests during audit",
        )
        if self.failures:
            raise AssertionError("settings page failures: " + "; ".join(self.failures))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--browser", required=True); p.add_argument("--url", required=True)
    p.add_argument("--email", required=True); p.add_argument("--password-file", required=True)
    p.add_argument("--output-dir", required=True); p.add_argument("--timeout", type=float, default=30)
    a = p.parse_args(); output = Path(a.output_dir); output.mkdir(parents=True, exist_ok=True)
    chrome = ChromePipe(a.browser, output, a.timeout); audit = Audit(chrome, a.url, a.email, Path(a.password_file).read_text().strip(), output, a.timeout)
    failure = None
    try:
        chrome.start(); audit.exercise()
    except BaseException as error:
        failure = str(error)
    finally:
        chrome.drain_events(); (output / "report.json").write_text(json.dumps({"checks": audit.checks, "pages": audit.pages, "pageFailures": audit.failures, "screenshots": audit.screenshots, "requestTimings": chrome.request_timing_report(), "requestTimingSummary": chrome.request_timing_summary(), "javascriptErrors": chrome.javascript_errors, "consoleErrors": chrome.console_errors, "networkFailures": chrome.network_failures, "expectedAbsenceRequests": audit.expected_absences, "failure": failure}, indent=2) + "\n"); chrome.close()
    if failure: raise SystemExit(f"FAIL {failure}; inspect {output / 'report.json'}")
    print(f"PASS {len(audit.checks)} audit checks across {len(audit.pages)} pages; evidence in {output}")


if __name__ == "__main__": main()
