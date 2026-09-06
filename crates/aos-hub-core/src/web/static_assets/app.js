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
    if (/^\x22.*\x22$|^\x27.*\x27$/.test(core)) cls = "t-s";
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

  // --- Package filter box (Wireshark-style) ------------------------------
  // Enhances a `[data-filter-widget]` filter input with grey-shade syntax
  // highlighting and a custom, theme-styled autocomplete dropdown (field
  // names, operators, connectives, and the registry's distinct per-field
  // values from the `#filter-meta` JSON island). The plain <input> remains a
  // working server `?filter=` submit when this does not run.
  var FILTER_OPS_2 = ["&&", "||", "==", "!=", ">=", "<="];
  var FILTER_BOUNDARY = /[\s()\x22\x27&|!=<>~]/;

  function initFilterBox(widget) {
    var input = widget.querySelector("input.filter-box");
    var codeEl = widget.querySelector("pre.filter-highlight code");
    var suggest = widget.querySelector(".filter-suggest");
    if (!input || !codeEl || !suggest) return;

    var meta = { fields: [], operators: [], connectives: [], values: {} };
    var metaEl = document.getElementById("filter-meta");
    if (metaEl) {
      try {
        meta = JSON.parse(metaEl.textContent);
      } catch (e) {
        /* leave defaults */
      }
    }

    // Tokenize, mirroring the server grammar, for both highlighting and
    // autocomplete context. Each token carries its type and source span.
    function tokenize(text) {
      var tokens = [];
      var i = 0;
      while (i < text.length) {
        var ch = text.charAt(i);
        if (/\s/.test(ch)) {
          var ws = i;
          while (i < text.length && /\s/.test(text.charAt(i))) i += 1;
          tokens.push({ t: "ws", v: text.slice(ws, i), s: ws, e: i });
          continue;
        }
        if (ch === "(" || ch === ")") {
          tokens.push({ t: "paren", v: ch, s: i, e: i + 1 });
          i += 1;
          continue;
        }
        var two = text.substr(i, 2);
        if (FILTER_OPS_2.indexOf(two) !== -1) {
          tokens.push({ t: two === "&&" || two === "||" ? "bool" : "op", v: two, s: i, e: i + 2 });
          i += 2;
          continue;
        }
        if (ch === ">" || ch === "<" || ch === "~") {
          tokens.push({ t: "op", v: ch, s: i, e: i + 1 });
          i += 1;
          continue;
        }
        if (ch === "!") {
          tokens.push({ t: "bool", v: ch, s: i, e: i + 1 });
          i += 1;
          continue;
        }
        if (ch === '"' || ch === "'") {
          var q = ch;
          var sq = i;
          i += 1;
          while (i < text.length && text.charAt(i) !== q) i += 1;
          if (i < text.length) i += 1;
          tokens.push({ t: "string", v: text.slice(sq, i), s: sq, e: i });
          continue;
        }
        var sw = i;
        while (i < text.length && !FILTER_BOUNDARY.test(text.charAt(i))) i += 1;
        if (i === sw) {
          i += 1; // stray boundary char (e.g. a lone `=`); skip
          continue;
        }
        var word = text.slice(sw, i);
        var lower = word.toLowerCase();
        var type = "value";
        if (meta.fields.indexOf(lower) !== -1) type = "field";
        else if (meta.connectives.indexOf(lower) !== -1) type = "bool";
        else if (lower === "contains") type = "op";
        tokens.push({ t: type, v: word, s: sw, e: i });
      }
      return tokens;
    }

    function renderHighlight() {
      var toks = tokenize(input.value);
      var html = "";
      toks.forEach(function (tk) {
        if (tk.t === "ws") {
          html += escapeHtml(tk.v);
        } else {
          html += '<span class="ftok-' + tk.t + '">' + escapeHtml(tk.v) + "</span>";
        }
      });
      codeEl.innerHTML = html;
      codeEl.parentNode.scrollLeft = input.scrollLeft;
    }

    // Decide what to suggest given the caret: a field at the start of a clause,
    // an operator after a field, a value after an operator, or a connective
    // after a completed comparison.
    function contextAt(caret) {
      var left = input.value.slice(0, caret);
      var toks = tokenize(left).filter(function (t) {
        return t.t !== "ws";
      });
      var partial = "";
      var partialStart = caret;
      var endsOpen = left === "" || FILTER_BOUNDARY.test(left.charAt(left.length - 1));
      var prevIdx = toks.length - 1;
      if (!endsOpen && toks.length) {
        var last = toks[toks.length - 1];
        partial = last.v;
        partialStart = last.s;
        prevIdx = toks.length - 2;
      }
      var prev = prevIdx >= 0 ? toks[prevIdx] : null;

      var category;
      var field = null;
      if (!prev || prev.t === "bool" || prev.v === "(") category = "field";
      else if (prev.t === "field") category = "op";
      else if (prev.t === "op") {
        category = "value";
        field = prevIdx > 0 ? toks[prevIdx - 1].v.toLowerCase() : null;
      } else category = "conn";

      var pool;
      if (category === "field") pool = meta.fields.concat(["not", "("]);
      else if (category === "op") pool = meta.operators;
      else if (category === "value") pool = (field && meta.values[field]) || [];
      else pool = meta.connectives.filter(function (c) { return c !== "not"; });

      var p = partial.toLowerCase();
      var items = pool.filter(function (x) {
        return x.toLowerCase().indexOf(p) === 0 && x.toLowerCase() !== p;
      });
      return { items: items.slice(0, 12), start: partialStart, end: caret, category: category };
    }

    var current = null;
    var activeIndex = -1;

    function showSuggest() {
      current = contextAt(input.selectionStart);
      if (!current.items.length) {
        hideSuggest();
        return;
      }
      suggest.innerHTML = "";
      current.items.forEach(function (item, idx) {
        var el = document.createElement("div");
        el.className = "fs-item";
        el.textContent = item;
        el.addEventListener("mousedown", function (e) {
          e.preventDefault();
          accept(idx);
        });
        suggest.appendChild(el);
      });
      activeIndex = -1;
      suggest.hidden = false;
    }

    function hideSuggest() {
      suggest.hidden = true;
      activeIndex = -1;
    }

    function setActive(idx) {
      var items = suggest.children;
      for (var i = 0; i < items.length; i += 1) {
        items[i].classList.toggle("active", i === idx);
      }
      activeIndex = idx;
      if (items[idx] && items[idx].scrollIntoView) {
        items[idx].scrollIntoView({ block: "nearest" });
      }
    }

    function accept(idx) {
      if (!current || !current.items[idx]) return;
      var val = current.items[idx];
      if (current.category === "value" && /\s/.test(val)) val = '"' + val + '"';
      var before = input.value.slice(0, current.start);
      var after = input.value.slice(current.end);
      var insert = val === "(" ? val : val + " ";
      input.value = before + insert + after;
      var pos = (before + insert).length;
      input.setSelectionRange(pos, pos);
      renderHighlight();
      showSuggest();
    }

    input.addEventListener("keydown", function (e) {
      if (suggest.hidden) return;
      var n = suggest.children.length;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive((activeIndex + 1) % n);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive((activeIndex - 1 + n) % n);
      } else if (e.key === "Enter") {
        // Accept the highlighted suggestion; otherwise let the form submit.
        if (activeIndex >= 0) {
          e.preventDefault();
          accept(activeIndex);
        }
      } else if (e.key === "Tab") {
        if (n > 0) {
          e.preventDefault();
          accept(activeIndex >= 0 ? activeIndex : 0);
        }
      } else if (e.key === "Escape") {
        hideSuggest();
      }
    });
    input.addEventListener("input", function () {
      renderHighlight();
      showSuggest();
    });
    input.addEventListener("scroll", function () {
      codeEl.parentNode.scrollLeft = input.scrollLeft;
    });
    input.addEventListener("focus", showSuggest);
    input.addEventListener("blur", function () {
      // Delay so a mousedown on an item is handled before the box hides.
      setTimeout(hideSuggest, 120);
    });

    widget.classList.add("enhanced");
    renderHighlight();
  }

  // Storage-binding create form: show the S3/R2 origin fields only when an
  // object-store kind is selected. Without JS every field is visible (the
  // server ignores origin fields for local_fs), so this is pure enhancement.
  function initBindingForm(form) {
    var kindSel = form.querySelector("select[name=kind]");
    var accessSel = form.querySelector("select[name=access]");
    if (!kindSel) return;
    function sync() {
      var isObjectStore = kindSel.value === "s3" || kindSel.value === "r2";
      form.querySelectorAll(".s3-only").forEach(function (el) {
        el.style.display = isObjectStore ? "" : "none";
      });
      form.querySelectorAll(".local-only").forEach(function (el) {
        el.style.display = isObjectStore ? "none" : "";
      });
      if (isObjectStore && accessSel) {
        var isPrivate = accessSel.value !== "public";
        form.querySelectorAll(".private-only").forEach(function (el) {
          el.style.display = isPrivate ? "" : "none";
        });
      }
    }
    kindSel.addEventListener("change", sync);
    if (accessSel) accessSel.addEventListener("change", sync);
    sync();
  }

  // The ordered [caches] editor in the structured config form. Row order is
  // preference (priority is derived from order). Clones the last row to add
  // another, and removes a row on its × button. No-JS fallback: the server
  // renders the existing rows plus one blank, all editable.
  function initCacheRows(form) {
    var container = form.querySelector("[data-cache-rows]");
    var addBtn = form.querySelector("[data-add-cache]");
    if (!container) return;
    function bindDel(row) {
      var del = row.querySelector(".row-del");
      if (!del) return;
      del.addEventListener("click", function () {
        // Never remove the final row — keep one for adding/cloning.
        if (container.querySelectorAll(".cache-row").length > 1) {
          row.parentNode.removeChild(row);
        } else {
          row.querySelectorAll("input").forEach(function (i) {
            i.value = "";
          });
        }
      });
    }
    container.querySelectorAll(".cache-row").forEach(bindDel);
    // Add a row, optionally pre-filled with `value`. Reuses the trailing blank
    // row when empty; otherwise clones it. Returns the row's URL input.
    function addRow(value) {
      var rows = container.querySelectorAll(".cache-row");
      var last = rows[rows.length - 1];
      var lastUrl = last.querySelector("input[name=cache_url]");
      var target;
      if (lastUrl && !lastUrl.value) {
        target = last; // fill the existing blank row
      } else {
        target = last.cloneNode(true);
        target.querySelectorAll("input").forEach(function (i) {
          i.value = "";
        });
        bindDel(target);
        container.appendChild(target);
      }
      var url = target.querySelector("input[name=cache_url]");
      if (url && value != null) url.value = value;
      return url;
    }
    if (addBtn) {
      addBtn.addEventListener("click", function () {
        var url = addRow(null);
        if (url) url.focus();
      });
    }
    // Autofill: a linked cache's "add" button inserts its consumer URL, marks
    // itself done, and flips a present indicator so the panel stays live.
    form.querySelectorAll("[data-add-cache-url]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        addRow(btn.getAttribute("data-add-cache-url"));
        var item = btn.closest("li");
        if (item) {
          var chip = item.querySelector(".chip");
          if (chip) {
            chip.textContent = "in config";
            chip.classList.remove("warn");
          }
        }
        btn.parentNode.removeChild(btn);
      });
    });
  }

  // Attached help (web/help.rs): turn a `?` marker's hidden segmented card into
  // a positioned popover. Hover + focus open it; click pins it; Esc / click-away
  // close. Position is fixed coords measured from the marker, flipped/clamped to
  // stay on-screen, so a card never clips inside a table or off the edge. The
  // no-JS floor is the marker's native `title` tooltip.
  function initHelp() {
    var open = null; // currently-open .help-card
    var openMark = null;
    var pinned = false;

    function close() {
      if (open) {
        open.classList.remove("open");
        if (openMark) openMark.setAttribute("aria-expanded", "false");
        open = null;
        openMark = null;
        pinned = false;
      }
    }
    function place(mark, card) {
      if (open && open !== card) close();
      open = card;
      openMark = mark;
      mark.setAttribute("aria-expanded", "true");
      card.classList.add("open"); // make it measurable
      var r = mark.getBoundingClientRect();
      var cw = card.offsetWidth;
      var ch = card.offsetHeight;
      var pad = 8;
      var left = r.left;
      if (left + cw > window.innerWidth - pad) left = window.innerWidth - pad - cw;
      if (left < pad) left = pad;
      var top = r.bottom + 6;
      if (top + ch > window.innerHeight - pad) {
        var above = r.top - ch - 6; // flip above when it would overflow the bottom
        top = above >= pad ? above : pad;
      }
      card.style.left = Math.round(left) + "px";
      card.style.top = Math.round(top) + "px";
    }

    function parts(target) {
      var mark = target.closest && target.closest(".help-mark");
      var help = mark && mark.closest(".help");
      var card = help && help.querySelector(".help-card");
      return mark && card ? { mark: mark, help: help, card: card } : null;
    }

    document.addEventListener("pointerover", function (e) {
      var found = parts(e.target);
      if (found && !pinned) place(found.mark, found.card);
    });
    document.addEventListener("pointerout", function (e) {
      var help = e.target.closest && e.target.closest(".help");
      if (help && !help.contains(e.relatedTarget) && !pinned) close();
    });
    document.addEventListener("focusin", function (e) {
      var found = parts(e.target);
      if (found && !pinned) place(found.mark, found.card);
    });
    document.addEventListener("focusout", function (e) {
      var help = e.target.closest && e.target.closest(".help");
      if (help && !help.contains(e.relatedTarget) && !pinned) close();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") close();
    });
    document.addEventListener("click", function (e) {
      var found = parts(e.target);
      if (!found) {
        if (open) close();
        return;
      }
      e.preventDefault();
      if (pinned && open === found.card) {
        close();
      } else {
        place(found.mark, found.card);
        pinned = true;
        found.mark.setAttribute("aria-expanded", "true");
      }
    });
  }

  // --- Copy-to-clipboard buttons ----------------------------------------
  // A `[data-copy-target="<id>"]` button (rendered `hidden`) copies the text
  // content of the element with that id — used for the `apr change merge`
  // command on the change-request page. With no JS (or no Clipboard API) the
  // button stays hidden and the command text is selectable as the floor.
  function initCopyButton(btn) {
    var target = document.getElementById(btn.getAttribute("data-copy-target"));
    if (!target || !navigator.clipboard) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent.trim()).then(function () {
        var prev = btn.textContent;
        btn.textContent = "copied";
        setTimeout(function () {
          btn.textContent = prev;
        }, 1200);
      });
    });
  }

  // --- Compact hash controls -------------------------------------------
  // Hash controls can be created after this bundle runs by the Leptos shell,
  // so hover/focus/copy behavior is delegated from `document` instead of
  // initialized from a one-time element query.
  function initHashControls() {
    var open = null;

    function close() {
      if (!open) return;
      open.classList.remove("open");
      open = null;
    }

    function place(control) {
      var tooltip = control.querySelector(".hash-tooltip");
      if (!tooltip) return;
      if (open && open !== tooltip) close();
      open = tooltip;
      tooltip.classList.add("open");

      var rect = control.getBoundingClientRect();
      var pad = 8;
      var left = rect.left;
      if (left + tooltip.offsetWidth > window.innerWidth - pad) {
        left = window.innerWidth - pad - tooltip.offsetWidth;
      }
      left = Math.max(pad, left);
      var top = rect.bottom + 6;
      if (top + tooltip.offsetHeight > window.innerHeight - pad) {
        top = Math.max(pad, rect.top - tooltip.offsetHeight - 6);
      }
      tooltip.style.left = Math.round(left) + "px";
      tooltip.style.top = Math.round(top) + "px";
    }

    document.addEventListener("pointerover", function (event) {
      var control = event.target.closest && event.target.closest(".hash-value");
      if (control) place(control);
    });
    document.addEventListener("pointerout", function (event) {
      var control = event.target.closest && event.target.closest(".hash-value");
      if (control && !control.contains(event.relatedTarget)) close();
    });
    document.addEventListener("focusin", function (event) {
      var control = event.target.closest && event.target.closest(".hash-value");
      if (control) place(control);
    });
    document.addEventListener("focusout", function (event) {
      var control = event.target.closest && event.target.closest(".hash-value");
      if (control && !control.contains(event.relatedTarget)) close();
    });
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);

    if (!navigator.clipboard) return;
    document.documentElement.classList.add("hash-controls-ready");
    document.addEventListener("click", function (event) {
      var button = event.target.closest && event.target.closest("[data-copy-value]");
      if (!button) return;
      navigator.clipboard.writeText(button.getAttribute("data-copy-value")).then(function () {
        button.classList.add("copied");
        button.setAttribute("aria-label", "Copied");
        setTimeout(function () {
          button.classList.remove("copied");
          button.setAttribute("aria-label", "Copy full hash");
        }, 1200);
      });
    });
  }

  document.querySelectorAll("form[data-live]").forEach(initLiveSearch);
  document.querySelectorAll(".code-editor").forEach(initCodeEditor);
  document.querySelectorAll("[data-copy-target]").forEach(initCopyButton);
  document.querySelectorAll("[data-filter-widget]").forEach(initFilterBox);
  document.querySelectorAll("form[data-binding-kind]").forEach(initBindingForm);
  document.querySelectorAll("form[data-config-form]").forEach(initCacheRows);
  initHelp();
  initHashControls();
})();

// The release jump is a plain text submit; with scripts it gains a typeahead
// over the page's compact release index (versions and channel names only), so
// hundreds of releases stay reachable without a hundred-entry dropdown.
(function () {
  "use strict";
  document.querySelectorAll("[data-release-picker]").forEach(function (picker) {
    var input = picker.querySelector("[data-release-jump]");
    var suggest = picker.querySelector(".release-suggest");
    var indexEl = picker.querySelector("[data-release-index]");
    var form = input && input.form;
    if (!input || !suggest || !indexEl || !form) return;
    var index;
    try { index = JSON.parse(indexEl.textContent); } catch (_) { return; }
    var entries = [];
    (index.channels || []).forEach(function (channel) {
      entries.push({value: channel.name, label: channel.name + " \u2192 " + channel.release, kind: "channel"});
    });
    (index.releases || []).forEach(function (release) {
      var notes = [];
      if (release.prerelease) notes.push("prerelease");
      if (!release.verified) notes.push("unverified");
      entries.push({value: release.version, label: release.version + (notes.length ? " \u00b7 " + notes.join(", ") : ""), kind: "release"});
    });
    var active = -1;
    var shown = [];
    function close() { suggest.hidden = true; suggest.innerHTML = ""; active = -1; shown = []; }
    function choose(entry) { input.value = entry.value; close(); form.requestSubmit(); }
    function render() {
      var term = input.value.trim().toLowerCase();
      shown = entries.filter(function (entry) { return !term || entry.value.toLowerCase().indexOf(term) !== -1; }).slice(0, 12);
      suggest.innerHTML = "";
      active = -1;
      if (!shown.length) { suggest.hidden = true; return; }
      shown.forEach(function (entry, position) {
        var item = document.createElement("div");
        item.className = "fs-item release-suggest-" + entry.kind;
        item.setAttribute("role", "option");
        item.textContent = entry.label;
        item.addEventListener("mousedown", function (event) { event.preventDefault(); choose(entry); });
        item.addEventListener("mouseenter", function () { highlight(position); });
        suggest.appendChild(item);
      });
      suggest.hidden = false;
    }
    function highlight(position) {
      active = position;
      Array.from(suggest.children).forEach(function (item, at) { item.classList.toggle("active", at === active); });
      if (active >= 0) suggest.children[active].scrollIntoView({block: "nearest"});
    }
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-autocomplete", "list");
    suggest.setAttribute("role", "listbox");
    input.addEventListener("input", render);
    input.addEventListener("focus", render);
    input.addEventListener("blur", function () { setTimeout(close, 120); });
    input.addEventListener("keydown", function (event) {
      if (suggest.hidden) { if (event.key === "ArrowDown") { render(); event.preventDefault(); } return; }
      if (event.key === "ArrowDown") { highlight(Math.min(active + 1, shown.length - 1)); event.preventDefault(); }
      else if (event.key === "ArrowUp") { highlight(Math.max(active - 1, 0)); event.preventDefault(); }
      else if (event.key === "Escape") { close(); event.preventDefault(); }
      else if (event.key === "Enter" && active >= 0) { event.preventDefault(); choose(shown[active]); }
    });
    new MutationObserver(function () { input.setAttribute("aria-expanded", suggest.hidden ? "false" : "true"); }).observe(suggest, {attributes: true, attributeFilter: ["hidden"]});
  });
})();

// Configuration folders fetch only one page on explicit expansion. No subtree
// is prefetched. Docs links swap the reader in place while the tree keeps its
// expanded state; ordinary links remain the navigation and no-JS fallback.
(function () {
  "use strict";
  var browser = document.querySelector("[data-doc-browser]");
  if (!browser || !window.fetch) return;
  var base = browser.getAttribute("data-doc-base");
  var release = browser.getAttribute("data-doc-release");
  function nodeUrl(key, children, cursor) {
    var url = new URL(base + (children ? "/children" : ""), location.origin);
    url.searchParams.set("release", release);
    url.searchParams.set("root", key);
    if (cursor) url.searchParams.set("cursor", cursor);
    return url;
  }
  function expansion(node) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "doc-expand";
    button.textContent = "+";
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-label", "Expand " + node.label);
    button.setAttribute("data-doc-expand", node.key);
    return button;
  }
  function appendPage(container, data, key) {
    if (!Array.isArray(data.items) || data.items.length > 50) throw new Error("Invalid child page");
    var list = document.createElement("ul");
    list.className = "doc-tree-list";
    data.items.forEach(function (node) {
      var row = document.createElement("li");
      row.setAttribute("data-node", node.key);
      if (node.child_count > 0) row.appendChild(expansion(node));
      else {
        var spacer = document.createElement("span");
        spacer.className = "doc-tree-spacer";
        row.appendChild(spacer);
      }
      var link = document.createElement("a");
      link.href = nodeUrl(node.key, false);
      link.textContent = node.label;
      row.appendChild(link);
      list.appendChild(row);
    });
    container.appendChild(list);
    if (data.next_cursor) {
      var more = document.createElement("button");
      more.type = "button";
      more.className = "doc-more";
      more.textContent = "Load more children";
      more.addEventListener("click", function () {
        load(container, key, data.next_cursor, more).then(function (ok) { if (ok) more.remove(); });
      });
      container.appendChild(more);
    }
  }
  function load(container, key, cursor, button) {
    button.disabled = true;
    container.setAttribute("aria-busy", "true");
    return fetch(nodeUrl(key, true, cursor), {credentials: "same-origin", headers: {Accept: "application/json"}})
      .then(function (response) {
        if (!response.ok) throw new Error("Could not load children");
        return response.json();
      })
      .then(function (data) { appendPage(container, data, key); return true; })
      .catch(function () {
        var error = document.createElement("p");
        error.setAttribute("role", "status");
        error.textContent = "Could not load children. Open the subtree link or try again.";
        container.appendChild(error);
        return false;
      })
      .finally(function () { button.disabled = false; container.removeAttribute("aria-busy"); });
  }
  browser.querySelectorAll("[data-doc-expand]").forEach(function (button) { button.hidden = false; });

  // The tree is the scope selector and the reader is the destination. A docs
  // link swaps only the reader, breadcrumbs, and scope inputs from the fetched
  // page, so expanded branches survive navigation. Anything unexpected falls
  // back to an ordinary load of the same URL.
  var reader = browser.querySelector("[data-doc-reader]");
  var crumbs = browser.querySelector(".doc-breadcrumbs");
  function isDocPage(url) {
    return url.origin === location.origin && url.pathname === base;
  }
  function markCurrent(key) {
    browser.querySelectorAll(".doc-tree [aria-current]").forEach(function (row) { row.removeAttribute("aria-current"); });
    var row = key && browser.querySelector('.doc-tree li[data-node="' + key + '"]');
    if (row) row.setAttribute("aria-current", "location");
    var expand = row && row.querySelector(":scope > [data-doc-expand]");
    if (expand && expand.getAttribute("aria-expanded") !== "true") expand.click();
  }
  function swap(url, push) {
    browser.setAttribute("aria-busy", "true");
    return fetch(url, {credentials: "same-origin", headers: {Accept: "text/html"}})
      .then(function (response) {
        if (!response.ok) throw new Error("Could not load documentation");
        return response.text();
      })
      .then(function (text) {
        var page = new DOMParser().parseFromString(text, "text/html");
        var next = page.querySelector("[data-doc-reader]");
        var nextCrumbs = page.querySelector(".doc-breadcrumbs");
        var nextBrowser = page.querySelector("[data-doc-browser]");
        if (!next || !nextCrumbs || !nextBrowser) throw new Error("Unexpected page");
        reader.innerHTML = next.innerHTML;
        crumbs.innerHTML = nextCrumbs.innerHTML;
        var root = nextBrowser.getAttribute("data-doc-root");
        browser.setAttribute("data-doc-root", root);
        document.querySelectorAll('.doc-search input[name="root"], .release-selector input[name="root"]').forEach(function (input) { input.value = root; });
        var query = page.querySelector("#doc-query");
        var current = document.getElementById("doc-query");
        if (query && current) current.value = query.value;
        if (push) history.pushState({docs: true}, "", url.href);
        document.title = page.title || document.title;
        markCurrent(root);
        reader.setAttribute("tabindex", "-1");
        reader.focus({preventScroll: true});
        if (window.matchMedia("(max-width: 720px)").matches) reader.scrollIntoView({block: "start"});
        return true;
      })
      .catch(function () { location.assign(url.href); return false; })
      .finally(function () { browser.removeAttribute("aria-busy"); });
  }
  browser.addEventListener("click", function (event) {
    var link = event.target.closest("a[href]");
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.target) return;
    var url = new URL(link.href, location.href);
    if (!isDocPage(url) || url.searchParams.get("release") !== release) return;
    event.preventDefault();
    swap(url, true);
  });
  var search = browser.querySelector("form.doc-search");
  if (search) search.addEventListener("submit", function (event) {
    var url = new URL(search.action, location.href);
    new FormData(search).forEach(function (value, key) { url.searchParams.set(key, String(value)); });
    if (!isDocPage(url)) return;
    event.preventDefault();
    swap(url, true);
  });
  window.addEventListener("popstate", function () {
    var url = new URL(location.href);
    if (isDocPage(url) && url.searchParams.get("release") === release) swap(url, false);
  });
  history.replaceState({docs: true}, "", location.href);

  // The filter narrows labels already in the tree; Enter escalates it to the
  // release's own subtree search so unseen branches are still reachable.
  var filter = browser.querySelector("[data-doc-tree-filter]");
  if (filter) {
    filter.hidden = false;
    function applyFilter() {
      var term = filter.value.trim().toLowerCase();
      var rows = Array.from(browser.querySelectorAll(".doc-tree li"));
      rows.forEach(function (row) { row.hidden = false; });
      if (!term) return;
      rows.reverse().forEach(function (row) {
        var label = row.querySelector(":scope > a");
        var own = label && label.textContent.toLowerCase().indexOf(term) !== -1;
        var visibleChild = Array.from(row.querySelectorAll("li")).some(function (child) { return !child.hidden; });
        row.hidden = !(own || visibleChild);
      });
    }
    filter.addEventListener("input", applyFilter);
    filter.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" || !search) return;
      event.preventDefault();
      var query = document.getElementById("doc-query");
      var scope = search.querySelector('select[name="scope"]');
      if (query) query.value = filter.value.trim();
      if (scope) scope.value = "subtree";
      search.requestSubmit();
    });
  }

  browser.addEventListener("click", function (event) {
    var button = event.target.closest("[data-doc-expand]");
    if (!button) return;
    var row = button.parentElement;
    var subtree = Array.from(row.children).find(function (child) { return child.classList.contains("doc-subtree"); });
    var expanded = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", expanded ? "false" : "true");
    button.textContent = expanded ? "+" : "−";
    if (subtree) { subtree.hidden = expanded; return; }
    subtree = document.createElement("div");
    subtree.className = "doc-subtree";
    row.appendChild(subtree);
    load(subtree, button.getAttribute("data-doc-expand"), null, button).then(function (ok) {
      if (!ok) {
        button.setAttribute("aria-expanded", "false");
        button.textContent = "+";
        subtree.classList.remove("doc-subtree");
      }
    });
  });
})();

// Historical doc:kind:key fragments select one panel, with no full anchor map.
(function () {
  "use strict";
  if (!document.querySelector("[data-doc-legacy]")) return;
  function selectAnchor() {
    var match = /^#doc:([0-9a-f]+):([0-9a-f]+)$/.exec(location.hash);
    if (!match || match[0].length > 8192) return;
    function decode(hex) {
      if (hex.length % 2) throw new Error("Invalid anchor");
      return new TextDecoder("utf-8", {fatal: true}).decode(Uint8Array.from(hex.match(/../g), function (byte) { return parseInt(byte, 16); }));
    }
    try {
      var url = new URL(location.href);
      var kind = decode(match[1]);
      var key = decode(match[2]);
      if (url.searchParams.get("kind") === kind && url.searchParams.get("doc_key") === key) return;
      url.searchParams.set("kind", kind);
      url.searchParams.set("doc_key", key);
      location.replace(url);
    } catch (_) { /* An invalid old anchor leaves the package guide available. */ }
  }
  window.addEventListener("hashchange", selectAnchor);
  selectAnchor();
})();
