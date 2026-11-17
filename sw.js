// Kairos のサービスワーカー：通知と、電波がないときのための保存（ネット優先、つながらなければ前回の保存分）
const CACHE = "kx-offline-v1";
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && res.type === "basic") {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(url.origin + url.pathname, copy)).catch(() => {});
        }
        return res;
      })
      .catch(async () => {
        const c = await caches.open(CACHE);
        let hit = await c.match(url.origin + url.pathname);
        if (!hit && req.mode === "navigate") {
          hit = (await c.match(self.registration.scope + "index.html")) || (await c.match(self.registration.scope));
        }
        return hit || Response.error();
      }),
  );
});

self.addEventListener("push", (e) => {
  let d = {};
  try {
    d = e.data ? e.data.json() : {};
  } catch (_) {
    d = { body: e.data ? e.data.text() : "" };
  }
  e.waitUntil(
    self.registration.showNotification(d.title || "Kairos", {
      body: d.body || "新しい情報が追加されました",
      icon: "img/icon-192.png",
      badge: "img/icon-192.png",
      tag: "kairos-update",
      data: { url: self.registration.scope },
    }),
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = self.registration.scope;
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.indexOf(url) === 0 && "focus" in c) return c.focus();
      }
      return self.clients.openWindow(url);
    }),
  );
});
