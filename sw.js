// Kairos の通知だけを扱うサービスワーカー（ページのキャッシュはしない）
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

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
