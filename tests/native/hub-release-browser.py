"""Checks release browsing against an isolated native ``serve --dev --seed`` Hub.

Run with the AOS Python package and an installed Chrome binary. The seeded
config-demo package exercises canonical document verification, a 137-child
subtree, structured option panels, historical links, and private-registry
visibility through the real HTTP handlers. Reports and screenshots are written
to the supplied output directory.
"""

import argparse
import base64
import html
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hub_settings_browser", HERE / "hub-settings-browser.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load Chrome transport")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BrowserAudit:
    def __init__(self, chrome, origin, output, timeout):
        self.chrome, self.origin, self.output, self.timeout = chrome, origin, output, timeout
        self.checks, self.captures = [], []
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.base = "/demo/cdn/-/docs?release=1.0.0"

    def check(self, condition, message):
        if not condition:
            raise AssertionError(message)
        self.checks.append(message)
        print(f"PASS {message}", flush=True)

    def get(self, path):
        try:
            with self.http.open(self.origin + path, timeout=self.timeout) as response:
                return response.status, response.read(), response.headers, response.url
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers, error.url

    def wait(self, expression, message):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                if self.chrome.evaluate(expression):
                    return
            except MODULE.DevToolsError:
                pass
            time.sleep(.05)
        raise AssertionError(f"timed out waiting for {message}")

    def navigate(self, path, selector="[data-doc-browser]"):
        self.chrome.call("Page.navigate", {"url": self.origin + path})
        expected = json.dumps(urllib.parse.urlsplit(path).path)
        self.wait(f"location.pathname === {expected} && document.readyState === 'complete' && document.querySelector({json.dumps(selector)}) !== null", path)
        self.chrome.drain_events()

    def child_page(self, root=None, cursor=None, private=False):
        query = {"release": "1.0.0"}
        if root:
            query["root"] = root
        if cursor:
            query["cursor"] = cursor
        registry = "private-images" if private else "cdn"
        return self.get(f"/demo/{registry}/-/docs/children?" + urllib.parse.urlencode(query))

    def screenshot(self, label):
        for suffix, width, height in (("desktop", 1440, 1000), ("mobile", 390, 844)):
            self.chrome.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": suffix == "mobile"})
            self.chrome.evaluate("window.scrollTo(0, 0)")
            metrics = self.chrome.evaluate("({width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth})")
            self.check(metrics["scroll"] <= metrics["width"] + 1, f"{label} fits {suffix} width")
            name = f"{label}-{suffix}.png"
            image = self.chrome.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
            (self.output / name).write_bytes(base64.b64decode(image["data"]))
            self.captures.append(name)
        self.chrome.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})

    def run(self):
        for section in ("packages", "docs", "images"):
            status, body, _, url = self.get(f"/demo/cdn/-/{section}")
            self.check(status == 200 and "release=1.0.0" in url, f"{section} initial URL pins its release")
            self.check(b"?release=1.0.0" in body, f"{section} navigation carries its release")
            self.check(b"index state: failed" not in body, f"{section} retains a verified index after publication")
        status, body, _, _ = self.get("/demo/cdn/-/releases/1.0.0")
        self.check(status == 200 and b"Release notes" in body and b"Current rollout" in body, "individual release exposes notes, contents, and live channel context")
        status, _, _, _ = self.get("/demo/cdn/-/docs?release=9.9.9")
        self.check(status == 404, "unknown release never falls back")
        self.check(self.child_page(private=True)[0] == 404, "private child endpoint hides registry from anonymous readers")

        status, body, headers, _ = self.child_page()
        roots = json.loads(body)
        self.check(status == 200 and len(roots["items"]) == 1, "root request loads immediate children only")
        self.check(headers.get("Cache-Control") == "private, no-store", "session-visible tree JSON cannot enter a shared cache")
        services = roots["items"][0]["key"]
        demo = json.loads(self.child_page(services)[1])["items"][0]["key"]
        siblings = json.loads(self.child_page(demo)[1])["items"]
        workers = next(node["key"] for node in siblings if node["label"] == "workers")
        storage = next(node["key"] for node in siblings if node["label"] == "storage")
        backend = json.loads(self.child_page(storage)[1])["items"][0]["key"]
        page = json.loads(self.child_page(workers)[1])
        self.check(len(page["items"]) == 50 and bool(page["next_cursor"]), "wide child endpoint returns 50 items and a continuation")
        self.check(self.child_page(services, page["next_cursor"])[0] == 400, "a cursor cannot be moved to another subtree")
        seen = [node["key"] for node in page["items"]]
        while page["next_cursor"]:
            page = json.loads(self.child_page(workers, page["next_cursor"])[1])
            seen.extend(node["key"] for node in page["items"])
        self.check(len(seen) == len(set(seen)) == 137, "HTTP child pagination covers all 137 branches exactly once")

        search = self.base + "&q=worker"
        count = 0
        while search:
            status, body, _, _ = self.get(search)
            text = body.decode()
            page_count = text.count('class="doc-result"')
            self.check(status == 200 and 0 < page_count <= 50, "search response stays within one 50-result page")
            count += page_count
            next_link = re.search(r'<a href="([^"]+)">Next results', text)
            search = html.unescape(next_link[1]) if next_link else None
        self.check(count == 137, "release search includes all paginated worker options")
        status, body, _, _ = self.get(self.base + "&root=" + storage + "&scope=subtree&q=worker")
        self.check(status == 200 and b"No matching documentation" in body, "subtree search excludes matches outside its ancestry")

        status, body, _, _ = self.get(self.base)
        text = body.decode()
        self.check(status == 200 and "data-doc-folder" in text and text.count('class="doc-folder-branch"') == 1, "root reader lists its children as a folder")
        self.check("Open a child to explore" not in text, "a branch never renders an empty reader")
        status, body, _, _ = self.get(self.base + "&root=" + workers)
        text = body.decode()
        self.check(status == 200 and text.count('class="doc-folder-branch"') == 50 and 'class="doc-more"' in text, "folder children page is bounded with a continuation")
        flat = self.base + "&root=" + workers + "&view=all"
        total, pages = 0, 0
        while flat:
            status, body, _, _ = self.get(flat)
            text = body.decode()
            rows = text.count('class="doc-folder-option"')
            self.check(status == 200 and 0 < rows <= 50 and 'aria-current="true">Options' in text, "flattened subtree page stays within one 50-option page")
            total += rows
            pages += 1
            next_link = re.search(r'<a class="doc-more" href="([^"]+)">Next options', text)
            flat = html.unescape(next_link[1]) if next_link else None
        self.check(total == 137 and pages == 3, "flattened subtree pagination covers all 137 worker options once")
        status, body, _, _ = self.get(self.base + "&root=" + demo + "&view=all")
        text = body.decode()
        self.check(status == 200 and ">workers.worker000.enable</a>" in text and ">storage.backend</a>" in text, "flattened rows show dotted paths relative to the scope")
        self.check("<code>bool</code>" in text, "flattened rows carry the representative option type")

        status, _, _, url = self.get("/demo/cdn/-/docs?release=stable")
        self.check(status == 200 and "release=1.0.0" in url and "release=stable" not in url, "channel name resolves to its exact release and redirects")
        status, body, _, _ = self.get(self.base)
        text = body.decode()
        self.check('class="release-pill"' in text and "stable <strong>1.0.0</strong>" in text, "selector shows channel targets as pills")
        self.check("data-release-jump" in text and '"channels":[{"name":"stable","release":"1.0.0"}]' in text, "selector offers a typed jump backed by a compact release index")
        self.check('<optgroup label="Channels">' in text and text.count("<option ") <= 12, "selector offers grouped releases instead of every tag")

        self.navigate(self.base)
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-tree-list > li').length") == 1, "initial browser DOM contains no expanded descendants")
        self.check(self.chrome.evaluate("performance.getEntriesByType('resource').filter(x => x.name.includes('/docs/children')).length") == 0, "browser does not prefetch subtrees")
        for key, expected in ((services, 1), (demo, 2), (workers, 3)):
            self.chrome.evaluate(f"document.querySelector('[data-doc-expand=\"{key}\"]').click()")
            self.wait(f"document.querySelector('[data-node=\"{key}\"] > .doc-subtree > ul') !== null && !document.querySelector('[aria-busy=\"true\"]')", "lazy branch expansion")
            self.check(self.chrome.evaluate("performance.getEntriesByType('resource').filter(x => x.name.includes('/docs/children')).length") == expected, "each expansion makes exactly one child request")
        count_expression = f"document.querySelectorAll('[data-node=\"{workers}\"] > .doc-subtree > ul > li').length"
        self.check(self.chrome.evaluate(count_expression) == 50, "expanded wide branch initially inserts only 50 children")
        for expected in (100, 137):
            self.chrome.evaluate(f"document.querySelector('[data-node=\"{workers}\"] > .doc-subtree > .doc-more').click()")
            self.wait(f"{count_expression} === {expected}", "additional child page")
        self.check(self.chrome.evaluate(count_expression) == 137, "load-more appends bounded child pages")
        requests_before = self.chrome.evaluate("performance.getEntriesByType('resource').length")
        self.chrome.evaluate(f"document.querySelector('[data-doc-expand=\"{workers}\"]').click(); document.querySelector('[data-doc-expand=\"{workers}\"]').click()")
        self.check(self.chrome.evaluate("performance.getEntriesByType('resource').length") == requests_before, "collapse and reopen reuse already loaded children")
        self.screenshot("lazy-tree")

        self.navigate(self.base)
        page_loads = "performance.getEntriesByType('resource').filter(x => x.name.includes('/-/docs?')).length"
        before = self.chrome.evaluate(page_loads)
        self.chrome.evaluate(f"document.querySelector('.doc-tree li[data-node=\"{services}\"] > a').click()")
        self.wait(f"document.querySelector('#doc-folder-title')?.textContent === 'services' && location.search.includes('root={services}')", "in-place scope navigation")
        self.check(self.chrome.evaluate(page_loads) == before + 1, "choosing a scope fetches one page and swaps only the reader")
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-tree > .doc-tree-list > li').length") == 1, "the tree keeps its own state across reader navigation")
        self.wait(f"document.querySelector('.doc-tree li[data-node=\"{services}\"]').getAttribute('aria-current') === 'location' && document.querySelector('[data-node=\"{services}\"] > .doc-subtree > ul') !== null", "the chosen scope is marked and expanded in the tree")
        self.chrome.evaluate(f"document.querySelector('[data-doc-folder] tr[data-node=\"{demo}\"] a').click()")
        self.wait(f"document.querySelector('#doc-folder-title')?.textContent === 'services.demo' && document.querySelector('[data-node=\"{demo}\"] > .doc-subtree > ul') !== null", "a folder row opens its scope and expands the tree branch")
        self.check(self.chrome.evaluate("document.querySelectorAll('[data-doc-folder] tbody tr').length") == 3, "the reader lists the scope's children with descriptions")
        self.chrome.evaluate("(() => { const f = document.querySelector('[data-doc-tree-filter]'); f.value = 'stor'; f.dispatchEvent(new Event('input')); })()")
        self.check(self.chrome.evaluate(f"!document.querySelector('.doc-tree li[data-node=\"{storage}\"]').hidden && document.querySelector('.doc-tree li[data-node=\"{workers}\"]').hidden && !document.querySelector('.doc-tree li[data-node=\"{services}\"]').hidden"), "tree filter narrows loaded branches and keeps matching ancestors")
        self.chrome.evaluate("(() => { const f = document.querySelector('[data-doc-tree-filter]'); f.value = ''; f.dispatchEvent(new Event('input')); })()")
        self.chrome.evaluate("history.back()")
        self.wait("document.querySelector('#doc-folder-title')?.textContent === 'services'", "history navigation restores the previous scope")
        self.chrome.evaluate("document.querySelector('.doc-view-toggle a:last-child').click()")
        self.wait("location.search.includes('view=all') && document.querySelectorAll('[data-doc-folder] tr.doc-folder-option').length === 50", "the flattened view swaps in place")
        self.screenshot("folder-view")

        self.navigate(self.base)
        self.chrome.evaluate("(() => { const j = document.querySelector('[data-release-jump]'); j.focus(); j.value = 'sta'; j.dispatchEvent(new Event('input')); })()")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('.release-suggest .fs-item')).map(x => x.textContent)") == ["stable \u2192 1.0.0"], "release jump suggests matching channels first")
        self.chrome.evaluate("window.__beforeJump = true; (() => { const j = document.querySelector('[data-release-jump]'); j.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowDown', bubbles: true})); j.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true})); })()")
        self.wait("window.__beforeJump === undefined && document.querySelector('[data-doc-browser]') !== null && location.search.includes('release=1.0.0')", "release jump resolves the channel to its exact release")

        self.navigate(self.base + "&root=" + backend)
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-option').length") == 1, "reader renders one option panel")
        self.check(self.chrome.evaluate("document.querySelector('.doc-option h2').textContent") == "services.demo.storage.backend", "arbitrary-depth subtree opens the exact option")
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-enum > div').length") == 2, "enum choices have structured visual rows")
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-value').length") == 2, "default and example have separate panels")
        self.screenshot("option-panel")
        self.chrome.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 500, "deviceScaleFactor": 1, "mobile": True})
        self.chrome.evaluate("window.scrollTo(0, window.scrollY + document.querySelector('.doc-search').getBoundingClientRect().top + 100)")
        self.check(abs(self.chrome.evaluate("document.querySelector('.doc-search').getBoundingClientRect().top")) < 2, "search stays visible while reading on mobile")
        self.chrome.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
        legacy = "/demo/cdn/-/docs/config-demo/1.0.0/x86_64-linux#doc:" + "option".encode().hex() + ":" + "services.demo.storage.backend".encode().hex()
        self.navigate(legacy)
        self.wait("document.querySelector('.doc-option h2')?.textContent === 'services.demo.storage.backend'", "historical option anchor")
        self.check(self.chrome.evaluate("location.search.includes('release=1.0.0') && location.search.includes('digest=')"), "historical links pin release and document identity")

        self.chrome.call("Emulation.setScriptExecutionDisabled", {"value": True})
        self.navigate(self.base + "&root=" + workers)
        self.check(self.chrome.evaluate("document.querySelectorAll('.doc-tree-list > li').length") == 50, "no-JavaScript view has a bounded child page")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('[data-doc-expand]')).every(x => x.hidden)"), "no-JavaScript view exposes ordinary subtree links")
        next_page = self.chrome.evaluate("document.querySelector('a.doc-more').getAttribute('href')")
        self.navigate(next_page)
        self.check(self.chrome.evaluate("document.querySelector('.doc-tree-list').textContent.includes('worker050')"), "ordinary next-page link works without JavaScript")
        self.check(self.chrome.evaluate("document.querySelectorAll('[data-doc-folder] tr.doc-folder-branch').length") == 50 and self.chrome.evaluate("document.querySelector('[data-doc-tree-filter]').hidden"), "no-JavaScript reader lists the folder and hides the script-only filter")
        self.navigate(self.base + "&root=" + workers + "&view=all")
        self.check(self.chrome.evaluate("document.querySelectorAll('[data-doc-folder] tr.doc-folder-option').length") == 50, "no-JavaScript flattened view is bounded")
        self.screenshot("no-javascript-tree")
        self.chrome.call("Emulation.setScriptExecutionDisabled", {"value": False})

        self.navigate("/login?next=" + urllib.parse.quote("/demo/private-images/-/docs?release=1.0.0", safe=""), 'form[action="/login/password"]')
        self.chrome.evaluate("(() => { const form = document.querySelector('form[action=\"/login/password\"]'); form.elements.email.value = 'demo@example.com'; form.elements.password.value = 'demo'; form.requestSubmit(); })()")
        self.wait("location.pathname === '/demo/private-images/-/docs' && document.querySelector('[data-doc-browser]') !== null", "private session documentation")
        private = self.chrome.evaluate("fetch('/demo/private-images/-/docs/children?release=1.0.0').then(async r => ({status: r.status, cache: r.headers.get('cache-control'), body: await r.json()}))")
        self.check(private["status"] == 200 and len(private["body"]["items"]) == 1, "authorized browser session can expand a private tree")
        self.check(private["cache"] == "private, no-store", "private-session expansion keeps cache isolation")
        self.chrome.drain_events()
        self.check(not self.chrome.javascript_errors, "browser reports no JavaScript exceptions")
        self.check(not self.chrome.console_errors, "browser reports no script or content-security errors")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    if urllib.parse.urlsplit(args.url).hostname not in ("127.0.0.1", "localhost", "::1"):
        parser.error("this fixture audit requires an isolated loopback Hub")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    chrome = MODULE.ChromePipe(args.browser, args.output_dir, args.timeout)
    audit = BrowserAudit(chrome, args.url.rstrip("/"), args.output_dir, args.timeout)
    failure = None
    try:
        chrome.start()
        audit.run()
    except Exception as error:
        failure = str(error)
        raise
    finally:
        (args.output_dir / "report.json").write_text(json.dumps({"checks": audit.checks, "screenshots": audit.captures, "failure": failure, "javascriptErrors": chrome.javascript_errors, "consoleErrors": chrome.console_errors}, indent=2))
        chrome.close()
    print(f"PASS {len(audit.checks)} native release-browser checks", flush=True)


if __name__ == "__main__":
    main()
