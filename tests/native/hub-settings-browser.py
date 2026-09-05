"""Smoke-tests Hub settings workflows in a real, isolated Chrome process.

The driver speaks the Chrome DevTools Protocol over ``--remote-debugging-pipe``
using only the Python standard library. It creates a temporary browser profile,
signs in through the rendered password form, walks the settings hierarchy, and
writes screenshots plus a machine-readable report to ``--output-dir``.

This is an external native-test helper. It is deliberately not a Nix build or
runtime dependency of the Hub console.
"""

import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse


class DevToolsError(RuntimeError):
    """Reports a failed Chrome DevTools Protocol command."""


class ChromePipe:
    """Owns an isolated Chrome process and a synchronous CDP pipe session."""

    def __init__(self, browser, output_dir, timeout):
        self.browser = str(Path(browser).resolve())
        self.output_dir = output_dir
        self.timeout = timeout
        self.profile = tempfile.mkdtemp(prefix="aos-hub-browser-")
        Path(self.profile).chmod(0o700)
        self.process = None
        self.stderr = None
        self.command = None
        self.events = queue.Queue()
        self.next_id = 1
        self.session_id = None
        self.requests = {}
        self.request_order = []
        self.javascript_errors = []
        self.console_errors = []
        self.network_failures = []
        self.paused_responses = []
        self.expected_cancellation_ids = set()
        self.expected_cancellations = []

    def start(self):
        """Starts Chrome and attaches to its initial page target."""
        saved_descriptors = {}
        for descriptor in (3, 4):
            try:
                saved_descriptors[descriptor] = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 20)
            except OSError:
                saved_descriptors[descriptor] = None

        command_read, command_write = os.pipe()
        event_read, event_write = os.pipe()
        parent_command = fcntl.fcntl(command_write, fcntl.F_DUPFD, 20)
        parent_events = fcntl.fcntl(event_read, fcntl.F_DUPFD, 20)
        child_command = fcntl.fcntl(command_read, fcntl.F_DUPFD, 20)
        child_event = fcntl.fcntl(event_write, fcntl.F_DUPFD, 20)
        for descriptor in (command_read, command_write, event_read, event_write):
            os.close(descriptor)

        # Chromium reserves descriptors 3 and 4 for the command and event
        # halves of its POSIX remote-debugging pipe. Map them before Popen so
        # close_fds preserves the final descriptors rather than intermediates
        # created by a pre-exec callback.
        os.dup2(child_command, 3)
        os.dup2(child_event, 4)

        self.stderr = (self.output_dir / "chrome.stderr.log").open("wb")
        arguments = [
            self.browser,
            "--headless=new",
            "--remote-debugging-pipe",
            f"--user-data-dir={self.profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--no-sandbox",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--metrics-recording-only",
            "--window-size=1440,1000",
            "about:blank",
        ]
        try:
            self.process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self.stderr,
                close_fds=True,
                pass_fds=(3, 4),
            )
        finally:
            os.close(3)
            os.close(4)
            for descriptor, saved in saved_descriptors.items():
                if saved is not None:
                    os.dup2(saved, descriptor)
                    os.close(saved)
            os.close(child_command)
            os.close(child_event)
        self.command = os.fdopen(parent_command, "wb", buffering=0)
        reader = threading.Thread(
            target=self._read_events,
            args=(parent_events,),
            name="chrome-devtools-pipe",
            daemon=True,
        )
        reader.start()

        targets = self.call("Target.getTargets")["targetInfos"]
        pages = [target for target in targets if target["type"] == "page"]
        if not pages:
            raise DevToolsError("Chrome did not create a page target")
        attached = self.call(
            "Target.attachToTarget",
            {"targetId": pages[0]["targetId"], "flatten": True},
        )
        self.session_id = attached["sessionId"]
        for method in ("Page.enable", "Runtime.enable", "Network.enable", "Log.enable"):
            self.call(method)

    def _read_events(self, descriptor):
        """Copies NUL-delimited CDP messages from Chrome into the event queue."""
        pending = bytearray()
        try:
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                pending.extend(chunk)
                while b"\0" in pending:
                    raw, _, remainder = pending.partition(b"\0")
                    pending = bytearray(remainder)
                    if raw:
                        try:
                            self.events.put(json.loads(raw))
                        except json.JSONDecodeError as error:
                            self.events.put({"readerError": str(error)})
        except OSError as error:
            self.events.put({"readerError": str(error)})
        finally:
            os.close(descriptor)
            self.events.put(None)

    def call(self, method, params=None):
        """Runs one CDP command and returns its result."""
        identifier = self.next_id
        self.next_id += 1
        message = {"id": identifier, "method": method}
        if params is not None:
            message["params"] = params
        if self.session_id is not None:
            message["sessionId"] = self.session_id
        encoded = json.dumps(message, separators=(",", ":")).encode() + b"\0"
        try:
            self.command.write(encoded)
        except (BrokenPipeError, OSError) as error:
            raise DevToolsError(f"could not send {method}: {error}") from error

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise DevToolsError(
                    f"Chrome exited with status {self.process.returncode}; "
                    f"inspect {self.output_dir / 'chrome.stderr.log'}"
                )
            try:
                event = self.events.get(timeout=min(0.25, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if event is None:
                raise DevToolsError("Chrome closed the DevTools pipe")
            if "readerError" in event:
                raise DevToolsError(f"invalid DevTools response: {event['readerError']}")
            if event.get("id") == identifier:
                if "error" in event:
                    raise DevToolsError(f"{method}: {event['error']}")
                return event.get("result", {})
            self._record_event(event)
        raise TimeoutError(f"Chrome did not answer {method} within {self.timeout:g}s")

    def drain_events(self, duration=0.05):
        """Records pending browser events without issuing another command."""
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                event = self.events.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                return
            if event is None:
                return
            self._record_event(event)

    def _record_event(self, event):
        method = event.get("method", "")
        params = event.get("params", {})
        if method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails", {})
            self.javascript_errors.append({
                "text": details.get("text", "JavaScript exception"),
                "url": details.get("url", ""),
                "line": details.get("lineNumber"),
                "column": details.get("columnNumber"),
                "exception": self._remote_text(details.get("exception", {})),
            })
        elif method == "Runtime.consoleAPICalled" and params.get("type") in {"error", "assert"}:
            self.console_errors.append({
                "type": params.get("type"),
                "text": " ".join(self._remote_text(item) for item in params.get("args", [])),
            })
        elif (
            method == "Log.entryAdded"
            and params.get("entry", {}).get("level") == "error"
            and params.get("entry", {}).get("source") in {"javascript", "console-api"}
        ):
            entry = params["entry"]
            self.console_errors.append({
                "type": entry.get("source", "log"),
                "text": entry.get("text", ""),
                "url": entry.get("url", ""),
            })
        elif method == "Network.requestWillBeSent":
            request = params.get("request", {})
            url = request.get("url", "")
            if not self._tracks_request(url):
                return
            request_id = params.get("requestId", "")
            self.requests[request_id] = {
                "path": urllib.parse.urlsplit(url).path,
                "method": request.get("method", ""),
                "type": params.get("type", ""),
                "startedAtSeconds": params.get("timestamp"),
                "wallStartedAtSeconds": params.get("wallTime"),
            }
            self.request_order.append(request_id)
        elif method == "Network.responseReceived":
            response = params.get("response", {})
            status = int(response.get("status", 0))
            request = self.requests.get(params.get("requestId", ""))
            if request is None:
                return
            request["status"] = status
            request["responseAtSeconds"] = params.get("timestamp")
            request["headersDurationMs"] = self._duration_ms(
                request.get("startedAtSeconds"), params.get("timestamp"))
            if status >= 400:
                self.network_failures.append(dict(request, status=status))
        elif method == "Network.loadingFinished":
            request = self.requests.get(params.get("requestId", ""))
            if request is None:
                return
            request["finishedAtSeconds"] = params.get("timestamp")
            request["durationMs"] = self._duration_ms(
                request.get("startedAtSeconds"), params.get("timestamp"))
            request["encodedBytes"] = int(params.get("encodedDataLength", 0))
        elif method == "Network.loadingFailed":
            request_id = params.get("requestId", "")
            request = self.requests.get(request_id)
            if request is None:
                return
            request["finishedAtSeconds"] = params.get("timestamp")
            request["durationMs"] = self._duration_ms(
                request.get("startedAtSeconds"), params.get("timestamp"))
            request["error"] = params.get("errorText", "request failed")
            request["canceled"] = params.get("canceled", False)
            failure = dict(request, error=params.get("errorText", "request failed"))
            if params.get("canceled", False) and request_id in self.expected_cancellation_ids:
                self.expected_cancellations.append(failure)
            else:
                self.network_failures.append(failure)
        elif method == "Fetch.requestPaused" and "responseStatusCode" in params:
            self.paused_responses.append({
                "requestId": params.get("requestId", ""),
                "networkId": params.get("networkId", ""),
                "path": urllib.parse.urlsplit(
                    params.get("request", {}).get("url", "")
                ).path,
                "status": params.get("responseStatusCode"),
            })

    @staticmethod
    def _remote_text(value):
        if "value" in value:
            encoded = value["value"]
            return encoded if isinstance(encoded, str) else json.dumps(encoded, sort_keys=True)
        return value.get("description") or value.get("unserializableValue") or value.get("type", "")

    @staticmethod
    def _tracks_request(url):
        return any(marker in url for marker in (
            "/_assets/hub-console",
            "/aos.hub.v1.",
            "/-/auth/session-token",
        ))

    @staticmethod
    def _duration_ms(start, end):
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            return None
        return round((end - start) * 1000, 3)

    def request_timing_report(self):
        """Returns nonsecret asset and RPC timing records in request order."""
        fields = (
            "path",
            "method",
            "type",
            "status",
            "startedAtSeconds",
            "wallStartedAtSeconds",
            "responseAtSeconds",
            "finishedAtSeconds",
            "headersDurationMs",
            "durationMs",
            "encodedBytes",
            "error",
            "canceled",
        )
        return [
            {field: request[field] for field in fields if field in request}
            for request_id in self.request_order
            if (request := self.requests.get(request_id)) is not None
        ]

    def request_timing_summary(self):
        """Aggregates request counts, transfer sizes, and durations by path."""
        groups = {}
        for request in self.request_timing_report():
            key = (request.get("method", ""), request.get("path", ""))
            group = groups.setdefault(key, {
                "method": key[0],
                "path": key[1],
                "count": 0,
                "completed": 0,
                "encodedBytes": 0,
                "durations": [],
            })
            group["count"] += 1
            group["encodedBytes"] += request.get("encodedBytes", 0)
            duration = request.get("durationMs")
            if duration is not None and not request.get("canceled", False):
                group["completed"] += 1
                group["durations"].append(duration)
        result = []
        for group in groups.values():
            durations = group.pop("durations")
            if durations:
                group["totalDurationMs"] = round(sum(durations), 3)
                group["meanDurationMs"] = round(sum(durations) / len(durations), 3)
                group["maxDurationMs"] = round(max(durations), 3)
            result.append(group)
        return result

    def hold_response(self, path):
        """Pauses matching responses so a test can control async completion."""
        self.paused_responses.clear()
        self.call("Fetch.enable", {
            "patterns": [{
                "urlPattern": f"*{path}",
                "requestStage": "Response",
            }],
        })

    def wait_for_held_response(self, path):
        """Waits for and returns one paused response for ``path``."""
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.drain_events(0.05)
            for response in self.paused_responses:
                if response["path"] == path:
                    return response
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting to hold response for {path}")

    def release_response(self, response):
        """Continues a response previously paused by :meth:`hold_response`."""
        try:
            self.call("Fetch.continueResponse", {"requestId": response["requestId"]})
        except DevToolsError:
            self.drain_events()
            network = self.requests.get(response.get("networkId", ""), {})
            if not network.get("canceled", False):
                raise

    def expect_response_cancellation(self, response):
        """Allows cancellation only for one deliberately intercepted response."""
        network_id = response.get("networkId")
        if network_id:
            self.expected_cancellation_ids.add(network_id)

    def stop_holding_responses(self):
        """Disables response interception and clears its transient state."""
        self.call("Fetch.disable")
        self.paused_responses.clear()

    def evaluate(self, expression):
        """Evaluates JavaScript in the page and returns a JSON-compatible value."""
        result = self.call("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True,
            "userGesture": True,
        })
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            raise DevToolsError(
                f"evaluation failed: {details.get('text', '')} "
                f"{self._remote_text(details.get('exception', {}))}"
            )
        return result.get("result", {}).get("value")

    def close(self):
        """Stops Chrome and removes the disposable browser profile."""
        if self.command is not None:
            try:
                self.command.close()
            except OSError:
                pass
            self.command = None
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None
        shutil.rmtree(self.profile, ignore_errors=True)


class HubSettingsSmoke:
    """Exercises the rendered settings hierarchy and records its evidence."""

    def __init__(self, chrome, base_url, email, password, output_dir, timeout):
        self.chrome = chrome
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.output_dir = output_dir
        self.timeout = timeout
        self.checks = []
        self.skips = []
        self.visited = []
        self.screenshots = []
        self.screenshot_number = 0
        self.mobile_navigation_checked = False

    def check(self, condition, description):
        if not condition:
            raise AssertionError(description)
        self.checks.append(description)
        print(f"PASS {description}", flush=True)

    def skip(self, description):
        self.skips.append(description)
        print(f"SKIP {description}", flush=True)

    def wait_for(self, expression, description):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                if self.chrome.evaluate(expression):
                    return
            except DevToolsError as error:
                if not any(fragment in str(error) for fragment in (
                    "Cannot find context",
                    "Execution context was destroyed",
                    "Inspected target navigated",
                )):
                    raise
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for {description}")

    def wait_for_request(self, path, previous_count, description):
        """Waits for one additional successful tracked request to finish."""
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.chrome.drain_events(0.05)
            matching = [
                request
                for request in self.chrome.request_timing_report()
                if request.get("path") == path and "durationMs" in request
            ]
            if len(matching) > previous_count:
                self.check(matching[-1].get("status") == 200, description)
                return
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {description}")

    def navigate(self, path):
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        self.chrome.call("Page.navigate", {"url": url})
        self.wait_for("document.readyState === 'complete'", f"{path} to load")
        self.wait_for(
            "document.querySelector('main#main-content.settings-body, form[action=\"/login/password\"]') !== null",
            f"{path} to render",
        )
        self.chrome.drain_events()
        self.visited.append(self.chrome.evaluate("location.href"))

    def login(self):
        next_path = urllib.parse.quote("/-/instance", safe="/")
        self.navigate(f"/login?next={next_path}")
        self.check(
            self.chrome.evaluate("document.querySelector('form[action=\"/login/password\"]') !== null"),
            "password login form rendered",
        )
        email = json.dumps(self.email)
        password = json.dumps(self.password)
        self.chrome.evaluate(f"""
            (() => {{
                const form = document.querySelector('form[action="/login/password"]');
                const assign = (input, value) => {{
                    const setter = Object.getOwnPropertyDescriptor(
                        HTMLInputElement.prototype, 'value').set;
                    setter.call(input, value);
                    input.dispatchEvent(new Event('input', {{bubbles: true}}));
                    input.dispatchEvent(new Event('change', {{bubbles: true}}));
                }};
                assign(form.elements.email, {email});
                assign(form.elements.password, {password});
                form.requestSubmit();
                return true;
            }})()
        """)
        self.wait_for(
            "location.pathname === '/-/instance' && document.querySelector('main.settings-body') !== null",
            "authenticated instance settings",
        )
        self.wait_for(
            "document.querySelector('.scope-header') !== null && document.querySelector('.workflow-stack') !== null",
            "instance settings application",
        )
        self.chrome.drain_events(0.2)
        self.check(self.chrome.evaluate("location.pathname") == "/-/instance", "browser login completed")

    def assert_settings_page(self, description):
        self.wait_for(
            "document.querySelector('.scope-header') !== null && "
            "document.querySelector('.workflow-stack, .panel, .editor-form') !== null",
            description,
        )
        self.wait_for(
            "document.querySelector('.loading-row') === null",
            f"{description} data",
        )
        self.chrome.drain_events(0.1)
        self.check(
            not self.chrome.evaluate("document.querySelector('.fatal-page, .inline-error') !== null"),
            f"{description} rendered without a fatal or inline error",
        )

    def links(self):
        return self.chrome.evaluate(
            "Array.from(document.querySelectorAll('a[href]'), a => a.href)"
        ) or []

    def screenshot_pair(self, label):
        self.screenshot_number += 1
        prefix = f"{self.screenshot_number:02d}-{label}"
        for suffix, width, height, scale in (
            ("desktop", 1440, 1000, 1),
            ("narrow", 390, 844, 1),
        ):
            self.chrome.call("Emulation.setDeviceMetricsOverride", {
                "width": width,
                "height": height,
                "deviceScaleFactor": scale,
                "mobile": suffix == "narrow",
            })
            if suffix == "narrow" and not self.mobile_navigation_checked:
                self.wait_for(
                    "!document.querySelector('.settings-nav-disclosure').open",
                    "narrow settings navigation to collapse",
                )
                self.check(True, "narrow settings navigation starts collapsed")
                self.check(
                    self.click_details(".settings-nav-disclosure", True),
                    "narrow settings navigation opens from its summary",
                )
                self.check(
                    self.click_details(".settings-nav-disclosure", False),
                    "narrow settings navigation closes from its summary",
                )
                self.mobile_navigation_checked = True
            if suffix == "narrow":
                self.check(
                    self.chrome.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth"
                    ),
                    f"{label} fits the narrow viewport without horizontal overflow",
                )
            time.sleep(0.1)
            capture = self.chrome.call("Page.captureScreenshot", {
                "format": "png",
                "fromSurface": True,
                "captureBeyondViewport": True,
            })
            destination = self.output_dir / f"{prefix}-{suffix}.png"
            destination.write_bytes(base64.b64decode(capture["data"]))
            self.screenshots.append(str(destination))
        self.chrome.call("Emulation.setDeviceMetricsOverride", {
            "width": 1440,
            "height": 1000,
            "deviceScaleFactor": 1,
            "mobile": False,
        })
        self.wait_for(
            "document.querySelector('.settings-nav-disclosure').open",
            "desktop settings navigation to expand",
        )

    def click_details(self, selector, opened):
        """Clicks a details summary when needed and waits for native state."""
        selector_literal = json.dumps(selector)
        details = self.chrome.evaluate(f"document.querySelector({selector_literal}) !== null")
        if not details:
            return False
        current = self.chrome.evaluate(f"document.querySelector({selector_literal}).open")
        if current != opened:
            clicked = self.chrome.evaluate(f"""
                (() => {{
                    const summary = document.querySelector({selector_literal})
                        .querySelector(':scope > summary');
                    if (!summary) return false;
                    summary.click();
                    return true;
                }})()
            """)
            if not clicked:
                return False
            expected = str(opened).lower()
            self.wait_for(
                f"document.querySelector({selector_literal}).open === {expected}",
                f"{selector} state",
            )
        return self.chrome.evaluate(
            f"document.querySelector({selector_literal}).open === {str(opened).lower()}"
        )

    def toggle_details(self, selector, description):
        selector_literal = json.dumps(selector)
        exists = self.chrome.evaluate(f"document.querySelector({selector_literal}) !== null")
        if not exists:
            self.skip(f"{description}: no matching control in this fixture")
            return False
        self.check(
            self.click_details(selector, True),
            f"{description} opens",
        )
        self.check(
            self.click_details(selector, False),
            f"{description} closes",
        )
        return True

    def set_labeled_value(self, label, value):
        """Updates the form control whose visible label has the given text."""
        label_literal = json.dumps(label)
        value_literal = json.dumps(value)
        return self.chrome.evaluate(f"""
            (() => {{
                const label = Array.from(document.querySelectorAll('.workflow-editor label'))
                    .find(item => {{
                        const caption = Array.from(item.children)
                            .find(child => child.tagName === 'SPAN');
                        return caption && caption.textContent.trim() === {label_literal};
                    }});
                if (!label) return false;
                const control = label.querySelector('input, select, textarea');
                if (!control) return false;
                const prototype = control instanceof HTMLSelectElement
                    ? HTMLSelectElement.prototype
                    : control instanceof HTMLTextAreaElement
                        ? HTMLTextAreaElement.prototype
                        : HTMLInputElement.prototype;
                Object.getOwnPropertyDescriptor(prototype, 'value').set.call(
                    control, {value_literal});
                control.dispatchEvent(new Event('input', {{bubbles: true}}));
                control.dispatchEvent(new Event('change', {{bubbles: true}}));
                return control.value === {value_literal};
            }})()
        """)

    def review_delivery_destination(self):
        """Plans a fixture CDN destination and verifies stale-review invalidation."""
        probe = json.dumps({
            "provider": "native_file",
            "signerSecretRef": "fixture-probe-key",
            "publicKey": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }, separators=(",", ":"))
        values = (
            ("Endpoint", "new"),
            ("Public hostname", "cdn.browser.example.test"),
            ("Provider listener", "listener:local-e2e"),
            ("TLS provider", "external"),
            ("TLS certificate", "secret:fixture"),
            ("Provider probe", probe),
            ("CDN URL prefix", "/cdn"),
        )
        for label, value in values:
            self.check(
                self.set_labeled_value(label, value),
                f"guided delivery accepts {label.lower()}",
            )
        submitted = self.chrome.evaluate("""
            (() => {
                const button = Array.from(
                    document.querySelectorAll('.workflow-editor button'))
                    .find(item => item.textContent.trim() === 'Review destination');
                if (!button || button.disabled) return false;
                button.click();
                return true;
            })()
        """)
        self.check(submitted, "guided delivery prerequisites enable review")
        self.wait_for(
            "document.querySelector('.workflow-editor .review-card, "
            ".workflow-editor .inline-error') !== null",
            "delivery destination review",
        )
        self.check(
            self.chrome.evaluate("document.querySelector('.workflow-editor .inline-error') === null"),
            "delivery destination planning succeeds",
        )
        self.check(
            self.chrome.evaluate("document.querySelector('.workflow-editor .review-card') !== null"),
            "delivery destination renders immutable review effects",
        )
        self.screenshot_pair("registry-delivery-review")

        self.check(
            self.set_labeled_value("CDN URL prefix", "/edge"),
            "guided delivery draft remains editable after review",
        )
        self.wait_for(
            "document.querySelector('.workflow-editor .review-card') === null",
            "stale delivery review to clear after editing",
        )
        self.check(True, "editing the delivery draft invalidates its stale review")

    def exercise_saved_delivery_workflow(self):
        """Checks and resumes a persisted blocked workflow when one is present."""
        selector = ".delivery-workflows .workflow-card"
        if not self.chrome.evaluate(f"document.querySelector({json.dumps(selector)}) !== null"):
            self.skip("saved delivery progress: fixture contains no persisted workflow")
            return
        workflow_id = self.chrome.evaluate(
            "document.querySelector('.workflow-card-heading code').textContent.trim()"
        )
        self.check(bool(workflow_id), "saved delivery workflow exposes its stable identity")
        self.check(
            self.chrome.evaluate(
                "document.querySelector('.workflow-card .status-badge').textContent.trim() "
                "=== 'blocked'"
            ),
            "saved unconfigured delivery workflow remains blocked",
        )
        self.check(
            self.chrome.evaluate(
                "document.querySelectorAll('.workflow-card .workflow-steps li').length > 0 && "
                "document.querySelectorAll('.workflow-card .workflow-blockers li').length > 0"
            ),
            "saved delivery workflow renders steps and explicit blockers",
        )
        self.toggle_details(
            ".workflow-card details.advanced-controls",
            "saved workflow resource inspection",
        )
        self.screenshot_pair("registry-delivery-progress")

        resume_path = "/aos.hub.v1.DeliveryService/ResumeDeliveryDestination"
        for attempt in (1, 2):
            resume_count = sum(
                request.get("path") == resume_path and "durationMs" in request
                for request in self.chrome.request_timing_report()
            )
            resumed = self.chrome.evaluate("""
                (() => {
                    const button = Array.from(document.querySelectorAll('.workflow-card button'))
                        .find(item => item.textContent.trim() === 'Check and continue');
                    if (!button || button.disabled) return false;
                    window.__aosSmokeOldWorkflowCard = button.closest('.workflow-card');
                    button.click();
                    return true;
                })()
            """)
            self.check(resumed, f"saved delivery workflow exposes resume action {attempt}")
            self.wait_for_request(
                resume_path,
                resume_count,
                f"delivery workflow resume request {attempt} succeeds",
            )
            self.wait_for(
                "window.__aosSmokeOldWorkflowCard !== null && "
                "!window.__aosSmokeOldWorkflowCard.isConnected && "
                "document.querySelector('.loading-row') === null && "
                "Array.from(document.querySelectorAll('.workflow-card button')).some("
                "button => button.textContent.trim() === 'Check and continue' && !button.disabled)",
                f"delivery workflow SPA refresh {attempt}",
            )
            self.assert_settings_page(f"resumed delivery workflow {attempt}")
            current_id = self.chrome.evaluate(
                "document.querySelector('.workflow-card-heading code').textContent.trim()"
            )
            self.check(
                current_id == workflow_id,
                f"resume {attempt} preserves delivery workflow identity",
            )
        self.check(
            self.chrome.evaluate(
                "document.querySelectorAll('.workflow-card .workflow-blockers li').length > 0"
            ),
            "resumed workflow keeps unmet provider prerequisites explicit",
        )

    def review_identity_and_invalidate(self):
        self.navigate("/-/instance/identity-and-signup")
        self.assert_settings_page("instance identity settings")
        clicked = self.chrome.evaluate("""
            (() => {
                const button = Array.from(document.querySelectorAll('button'))
                    .find(item => item.textContent.trim() === 'Review identity settings');
                if (!button || button.disabled) return false;
                button.click();
                return true;
            })()
        """)
        if not clicked:
            self.skip("identity draft invalidation: review action is unavailable")
            return
        self.wait_for(
            "document.querySelector('.review-card, .inline-error') !== null",
            "identity review response",
        )
        if self.chrome.evaluate("document.querySelector('.review-card') === null"):
            self.skip("identity draft invalidation: fixture rejected planning")
            return
        self.check(True, "identity settings produce a reviewed plan")
        changed = self.chrome.evaluate("""
            (() => {
                const input = document.querySelector('.editor-form input[type="number"]');
                if (!input) return false;
                input.value = String(Number(input.value || '0') + 1);
                input.dispatchEvent(new Event('input', {bubbles: true}));
                return true;
            })()
        """)
        self.check(changed, "identity draft has an editable value")
        self.wait_for(
            "document.querySelector('.review-card') === null",
            "stale identity review to clear after editing",
        )
        self.check(True, "editing the identity draft invalidates its stale review")

    def exercise_inflight_plan_navigation(self):
        """Navigates away while a settings plan response remains in flight."""
        self.navigate("/-/instance/identity-and-signup")
        self.assert_settings_page("instance identity cancellation fixture")
        plan_path = "/aos.hub.v1.InstanceService/PlanSetInstanceSettings"
        errors_before = len(self.chrome.javascript_errors)
        held_response = None
        self.chrome.hold_response(plan_path)
        try:
            clicked = self.chrome.evaluate("""
                (() => {
                    const button = Array.from(document.querySelectorAll('button'))
                        .find(item => item.textContent.trim() === 'Review identity settings');
                    if (!button || button.disabled) return false;
                    button.click();
                    return true;
                })()
            """)
            self.check(clicked, "identity plan starts before SPA navigation")
            held_response = self.chrome.wait_for_held_response(plan_path)
            self.check(
                held_response.get("status") == 200,
                "identity plan response is held after backend completion",
            )
            self.chrome.expect_response_cancellation(held_response)
            navigated = self.chrome.evaluate("""
                (() => {
                    const link = document.querySelector(
                        '.scope-header a[href="/-/instance"]'
                    );
                    if (!link) return false;
                    link.click();
                    return true;
                })()
            """)
            self.check(navigated, "scope overview link works while plan response is held")
            self.wait_for(
                "location.pathname === '/-/instance' && "
                "document.querySelector('.workflow-stack') !== null && "
                "document.querySelector('.loading-row') === null",
                "instance overview after in-flight plan navigation",
            )
            self.chrome.release_response(held_response)
            held_response = None
        finally:
            if held_response is not None:
                self.chrome.release_response(held_response)
            self.chrome.stop_holding_responses()
        self.chrome.drain_events(0.25)
        self.check(
            len(self.chrome.javascript_errors) == errors_before,
            "completed plan does not update its disposed workflow",
        )
        self.assert_settings_page("instance overview after canceled plan continuation")

    def discover_path(self, pattern):
        compiled = re.compile(pattern)
        for link in self.links():
            parsed = urllib.parse.urlparse(link)
            if parsed.netloc == urllib.parse.urlparse(self.base_url).netloc and compiled.fullmatch(parsed.path):
                return parsed.path
        return None

    def exercise(self):
        self.login()
        self.check(
            self.chrome.evaluate("document.querySelector('.scope-header') !== null"),
            "persistent instance scope header rendered",
        )
        self.screenshot_pair("instance-overview")
        self.exercise_inflight_plan_navigation()
        self.review_identity_and_invalidate()

        self.navigate("/-/orgs")
        self.assert_settings_page("organization inventory")
        organization_path = self.discover_path(r"/-/org/[^/]+")
        self.check(organization_path is not None, "organization fixture is discoverable")
        self.navigate(organization_path)
        self.assert_settings_page("organization overview")
        self.toggle_details("details.advanced-controls", "organization advanced settings")
        self.screenshot_pair("organization-overview")

        registries_path = organization_path + "/registries"
        self.navigate(registries_path)
        self.assert_settings_page("organization registry inventory")
        registry_path = self.discover_path(r"/[^/]+/[^/]+/-/settings")
        self.check(registry_path is not None, "registry fixture is discoverable")
        self.navigate(registry_path)
        self.assert_settings_page("registry overview")
        self.check(
            self.chrome.evaluate(
                "Array.from(document.querySelectorAll('.overview-actions a'))"
                ".some(link => link.textContent.trim() === 'View containers')"
            ),
            "registry overview exposes the containers workspace",
        )
        self.toggle_details("details.advanced-controls", "registry advanced settings")

        containers_path = registry_path + "/containers"
        clicked = self.chrome.evaluate(f"""
            (() => {{
                const link = Array.from(document.querySelectorAll('.overview-actions a'))
                    .find(item => new URL(item.href).pathname === {json.dumps(containers_path)});
                if (!link) return false;
                link.click();
                return true;
            }})()
        """)
        self.check(clicked, "registry containers overview action is interactive")
        self.wait_for(
            f"location.pathname === {json.dumps(containers_path)}",
            "registry containers SPA navigation",
        )
        self.visited.append(self.chrome.evaluate("location.href"))
        self.assert_settings_page("registry containers settings")
        self.check(
            self.chrome.evaluate("document.body.textContent.includes('Containers')"),
            "registry containers workspace renders",
        )
        self.chrome.evaluate("history.back()")
        self.wait_for(
            f"location.pathname === {json.dumps(registry_path)}",
            "registry overview browser history navigation",
        )
        self.assert_settings_page("registry overview after browser Back")
        self.check(True, "browser Back preserves SPA settings navigation")

        delivery_path = registry_path + "/delivery"
        self.navigate(delivery_path)
        self.assert_settings_page("registry delivery settings")
        self.wait_for(
            "document.querySelector('.delivery-workflows, details.guided-workflow') !== null",
            "guided delivery workflow",
        )
        self.check(
            self.chrome.evaluate("document.body.textContent.includes('Delivery destinations')"),
            "delivery destination workflow rendered",
        )
        self.exercise_saved_delivery_workflow()
        guided_selector = "details.guided-workflow"
        if self.chrome.evaluate(f"document.querySelector({json.dumps(guided_selector)}) !== null"):
            self.check(
                self.click_details(guided_selector, True),
                "guided delivery workflow opens",
            )
            self.wait_for(
                "document.querySelector('details.guided-workflow .workflow-editor, "
                "details.guided-workflow .inline-error, details.guided-workflow form') !== null",
                "guided delivery editor",
            )
            self.check(True, "guided delivery workflow mounts its editor on demand")
            self.review_delivery_destination()
            self.screenshot_pair("registry-delivery")
            self.check(
                self.click_details(guided_selector, False),
                "guided delivery workflow closes",
            )
        else:
            self.skip("guided delivery editor: current permissions do not expose creation")
            self.screenshot_pair("registry-delivery")

        caches_path = organization_path + "/caches"
        self.navigate(caches_path)
        self.assert_settings_page("organization cache inventory")
        cache_path = self.discover_path(re.escape(caches_path) + r"/(?!new$)[^/]+")
        if cache_path is None:
            self.skip("cache resource pages: native fixture contains no binary cache")
            self.screenshot_pair("cache-inventory")
        else:
            self.navigate(cache_path)
            self.assert_settings_page("cache overview")
            self.toggle_details("details.advanced-controls", "cache advanced settings")
            self.screenshot_pair("cache-overview")
            self.navigate(cache_path + "/integrations")
            self.assert_settings_page("cache integration settings")
            self.check(
                self.chrome.evaluate("document.body.textContent.includes('Connect this cache')"),
                "guided cache integration outcomes rendered",
            )
            self.navigate(cache_path + "/retention")
            self.assert_settings_page("cache retention settings")

        self.chrome.drain_events(0.25)

    def report(self, failure=None):
        return {
            "baseUrl": self.base_url,
            "checks": self.checks,
            "skips": self.skips,
            "visited": self.visited,
            "screenshots": self.screenshots,
            "javascriptErrors": self.chrome.javascript_errors,
            "consoleErrors": self.chrome.console_errors,
            "networkFailures": self.chrome.network_failures,
            "expectedNetworkCancellations": self.chrome.expected_cancellations,
            "requestTimings": self.chrome.request_timing_report(),
            "requestTimingSummary": self.chrome.request_timing_summary(),
            "failure": str(failure) if failure is not None else None,
        }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True, help="Path to Chrome or Chromium")
    parser.add_argument("--url", required=True, help="Root URL of the native Hub fixture")
    parser.add_argument("--email", required=True, help="Fixture user email")
    parser.add_argument("--password-file", required=True, help="Mode-0600 fixture password file")
    parser.add_argument("--output-dir", required=True, help="Directory for screenshots and report.json")
    parser.add_argument("--timeout", type=float, default=30, help="Per-operation timeout in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    parsed_url = urllib.parse.urlparse(args.url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise SystemExit("--url must be an absolute HTTP or HTTPS URL")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    browser = Path(args.browser)
    if not browser.is_file():
        raise SystemExit(f"browser does not exist: {browser}")
    password_file = Path(args.password_file)
    password = password_file.read_text().rstrip("\r\n")
    if not password:
        raise SystemExit("password file is empty")

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    chrome = ChromePipe(browser, output_dir, args.timeout)
    smoke = HubSettingsSmoke(chrome, args.url, args.email, password, output_dir, args.timeout)
    failure = None
    try:
        chrome.start()
        smoke.exercise()
        if chrome.javascript_errors:
            raise AssertionError(f"captured {len(chrome.javascript_errors)} JavaScript exception(s)")
        if chrome.console_errors:
            raise AssertionError(f"captured {len(chrome.console_errors)} browser console error(s)")
        if chrome.network_failures:
            raise AssertionError(f"captured {len(chrome.network_failures)} failed console request(s)")
    except BaseException as error:
        failure = error
    finally:
        chrome.drain_events()
        report = smoke.report(failure)
        (output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        chrome.close()

    if failure is not None:
        print(f"FAIL {failure}; inspect {output_dir / 'report.json'}", flush=True)
        return 1
    print(f"PASS {len(smoke.checks)} browser checks; evidence in {output_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
