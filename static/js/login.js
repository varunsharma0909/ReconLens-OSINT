"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const field = document.getElementById("password");
  const toggle = document.getElementById("toggle-password");
  if (!field || !toggle) return;
  toggle.addEventListener("click", () => {
    const visible = field.type === "password";
    field.type = visible ? "text" : "password";
    toggle.textContent = visible ? "Hide" : "Show";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
  });
});
