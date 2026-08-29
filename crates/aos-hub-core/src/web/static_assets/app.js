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
