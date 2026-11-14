// Runs before first paint (loaded synchronously in <head>) so the page never flashes the wrong theme.
(function () {
  var t = null;
  try { t = localStorage.getItem("nw_theme"); } catch (e) {}
  if (t !== "light" && t !== "dark") t = window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
})();
