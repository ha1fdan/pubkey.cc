// Minimal client-side router. Handles /u/<key_or_handle> share links so
// visiting one triggers a contact lookup instead of a raw 404.

const listeners = [];

function dispatch() {
  const path = window.location.pathname;
  for (const listener of listeners) listener(path);
}

export function onRouteChange(listener) {
  listeners.push(listener);
}

export function navigate(path) {
  if (window.location.pathname === path) {
    dispatch();
    return;
  }
  window.history.pushState({}, "", path);
  dispatch();
}

export function initRouter() {
  window.addEventListener("popstate", dispatch);
  document.addEventListener("click", (event) => {
    const link = event.target.closest("[data-link]");
    if (!link) return;
    event.preventDefault();
    navigate(link.getAttribute("href"));
  });
  dispatch();
}

export function parseUserRoute(path) {
  const match = path.match(/^\/u\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}
