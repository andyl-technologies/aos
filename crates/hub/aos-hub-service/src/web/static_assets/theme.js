// Apply the saved appearance before the stylesheet paints. This small,
// same-origin script also handles controls mounted later by the console.
(function () {
  "use strict";

  var storageKey = "aos-hub-theme";
  var modes = ["system", "light", "dark"];
  var root = document.documentElement;

  function apply(mode) {
    if (modes.indexOf(mode) === -1) mode = "system";

    root.setAttribute("data-theme-mode", mode);
    if (mode === "system") {
      // CSS continues following OS changes, including when JavaScript is off.
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", mode);
    }
  }

  try {
    apply(localStorage.getItem(storageKey));
  } catch (_) {
    // Private browsing or storage policy must not prevent page rendering.
    apply("system");
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof Element) || !target.closest("[data-theme-toggle]")) return;

    var index = modes.indexOf(root.getAttribute("data-theme-mode"));
    var mode = modes[(index + 1) % modes.length];
    apply(mode);

    try {
      if (mode === "system") {
        localStorage.removeItem(storageKey);
      } else {
        localStorage.setItem(storageKey, mode);
      }
    } catch (_) {
      // The selection still works for this document without persistent storage.
    }
  });

  window.addEventListener("storage", function (event) {
    if (event.key === storageKey || event.key === null) apply(event.newValue);
  });
})();
