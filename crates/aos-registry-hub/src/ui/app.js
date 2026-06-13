// First-party, same-origin progressive-enhancement bundle. Served at
// /_assets/app.js and allowed by the strict `default-src 'self'` CSP — no
// inline script, no nonce, no third-party origin. Every behavior here is an
// enhancement: with JS disabled the underlying forms and textareas work on
// their own (the no-JS tier is the floor).
//
// Two enhancements live here:
//   * live search   — `<form data-live>` filters a `[data-live-list]` table
//                      as you type, updating a `[data-live-count]` element.
//   * config editor  — `.code-editor` wraps a `<textarea>` in a syntax-
//                      highlighted overlay whose palette is the page's own
//                      ink-on-paper CSS variables.
(function () {
  "use strict";

  function escapeHtml(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // --- Live search -------------------------------------------------------
  function initLiveSearch(form) {
    var input = form.querySelector('input[type="search"], input[name="q"]');
    var list = document.querySelector("[data-live-list]");
    if (!input || !list) return;

    // A pager means the list is server-paginated: filtering only the visible
    // page would hide matches on other pages, so leave the form as a plain
    // server `?q=` submit (the count and button stay) and don't enhance.
    if (document.querySelector(".pager")) return;

    var rows = Array.prototype.slice.call(list.querySelectorAll("tbody tr"));
    var count = document.querySelector("[data-live-count]");
    var noun = list.getAttribute("data-live-noun") || "rows";
    var total = rows.length;

    var button = form.querySelector("button");
    if (button) button.style.display = "none"; // filtering is live now
    form.addEventListener("submit", function (e) {
      e.preventDefault(); // stay on the page; the filter already applied
    });

    function apply() {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var match = q === "" || row.textContent.toLowerCase().indexOf(q) !== -1;
        row.style.display = match ? "" : "none";
        if (match) shown += 1;
      });
      if (count) {
        count.textContent =
          q === ""
            ? total + " " + noun
            : shown + " of " + total + " " + noun + ' matching "' + input.value + '"';
      }
    }

    input.addEventListener("input", apply);
    apply();
  }

  // --- TOML syntax highlighting -----------------------------------------
  // Line-oriented and deliberately approximate: it covers the registry.toml
  // schema (tables, dotted keys, strings, numbers, booleans, comments) and
  // lets anything it doesn't recognize fall through as plain ink. The palette
  // comes from CSS classes (t-c/t-h/t-k/t-s/t-n/t-b/t-a) bound to theme vars.
  function highlightTomlLine(line) {
    // Split off a trailing comment, skipping any `#` inside a string literal.
    var inStr = null;
    var cut = -1;
    for (var i = 0; i < line.length; i++) {
      var c = line.charAt(i);
      if (inStr) {
        if (c === inStr) inStr = null;
      } else if (c === '"' || c === "'") {
        inStr = c;
      } else if (c === "#") {
        cut = i;
        break;
      }
    }
    var comment = "";
    var code = line;
    if (cut >= 0) {
      comment = '<span class="t-c">' + escapeHtml(line.slice(cut)) + "</span>";
      code = line.slice(0, cut);
    }

    var trimmed = code.trim();
    var html;
    if (trimmed === "") {
      html = escapeHtml(code);
    } else if (trimmed.charAt(0) === "[") {
      html = '<span class="t-h">' + escapeHtml(code) + "</span>";
    } else {
      var eq = code.indexOf("=");
      if (eq >= 0) {
        html =
          '<span class="t-k">' +
          escapeHtml(code.slice(0, eq)) +
          "</span>=" +
          highlightTomlValue(code.slice(eq + 1));
      } else {
        html = escapeHtml(code);
      }
    }
    return html + comment;
  }

  function highlightTomlValue(v) {
    var core = v.trim();
    if (core === "") return escapeHtml(v);
    var lead = v.slice(0, v.length - v.replace(/^\s+/, "").length);
    var trail = v.slice(v.replace(/\s+$/, "").length);
    var cls = null;
    if (/^".*"$|^'.*'$/.test(core)) cls = "t-s";
    else if (/^(true|false)$/.test(core)) cls = "t-b";
    else if (/^[-+]?[0-9][0-9_.:eE+-]*$/.test(core)) cls = "t-n";
    else if (core.charAt(0) === "[" || core.charAt(0) === "{") cls = "t-a";
    if (!cls) return escapeHtml(v);
    return (
      escapeHtml(lead) +
      '<span class="' + cls + '">' + escapeHtml(core) + "</span>" +
      escapeHtml(trail)
    );
  }

  function highlightToml(src) {
    return src.split("\n").map(highlightTomlLine).join("\n");
  }

  function initCodeEditor(editor) {
    var textarea = editor.querySelector("textarea");
    var codeEl = editor.querySelector("pre.code-highlight code");
    if (!textarea || !codeEl) return;

    function render() {
      // The trailing newline keeps the final line's height in the overlay.
      codeEl.innerHTML = highlightToml(textarea.value) + "\n";
    }
    function syncScroll() {
      var pre = codeEl.parentNode;
      pre.scrollTop = textarea.scrollTop;
      pre.scrollLeft = textarea.scrollLeft;
    }

    textarea.addEventListener("input", function () {
      render();
      syncScroll();
    });
    textarea.addEventListener("scroll", syncScroll);
    textarea.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      e.preventDefault(); // insert two spaces, don't move focus
      var start = textarea.selectionStart;
      var end = textarea.selectionEnd;
      textarea.value =
        textarea.value.slice(0, start) + "  " + textarea.value.slice(end);
      textarea.selectionStart = textarea.selectionEnd = start + 2;
      render();
    });

    editor.classList.add("enhanced");
    render();
  }

  document.querySelectorAll("form[data-live]").forEach(initLiveSearch);
  document.querySelectorAll(".code-editor").forEach(initCodeEditor);
})();
