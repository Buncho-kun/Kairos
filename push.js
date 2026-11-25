// 設定タブの「通知」。購読情報は Firebase（Firestore の kairos_subs）に保存し、
// 送信は GitHub Actions（.github/workflows/notify.yml）が行う。
(function () {
  var C = window.KAIROS_PUSH || {};
  var LS = "kx-push-ep";
  var configured = !!(C.vapidPublicKey && C.firebaseProjectId && C.firebaseApiKey);
  var ua = navigator.userAgent || "";
  var isIOS = /iP(hone|od|ad)/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  var standalone =
    window.navigator.standalone === true ||
    (window.matchMedia && matchMedia("(display-mode: standalone)").matches);
  var supported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  var busy = "";
  var lastErr = "";

  function lsGet() {
    try {
      return localStorage.getItem(LS);
    } catch (e) {
      return null;
    }
  }
  function lsSet(v) {
    try {
      if (v) localStorage.setItem(LS, v);
      else localStorage.removeItem(LS);
    } catch (e) {}
  }
  function b64u(s) {
    var p = "=".repeat((4 - (s.length % 4)) % 4);
    var raw = atob((s + p).replace(/-/g, "+").replace(/_/g, "/"));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function device() {
    if (isIOS) return "iPhone/iPad";
    if (/Android/.test(ua)) return "Android";
    return "PC";
  }
  async function sha(s) {
    var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf))
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("")
      .slice(0, 40);
  }
  async function save(sub) {
    var j = sub.toJSON();
    var id = await sha(j.endpoint);
    var url =
      "https://firestore.googleapis.com/v1/projects/" +
      encodeURIComponent(C.firebaseProjectId) +
      "/databases/(default)/documents/kairos_subs?documentId=" +
      id +
      "&key=" +
      encodeURIComponent(C.firebaseApiKey);
    var body = {
      fields: {
        endpoint: { stringValue: j.endpoint },
        p256dh: { stringValue: j.keys.p256dh },
        auth: { stringValue: j.keys.auth },
        ua: { stringValue: device() },
        created: { timestampValue: new Date().toISOString() },
      },
    };
    var r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok && r.status !== 409) throw new Error("保存に失敗しました（" + r.status + "）");
    lsSet(j.endpoint);
    // 管理者の端末は、点検の失敗や報告の到着も受け取る
    try {
      if (localStorage.getItem("kx-mode") === "owner") {
        await fetch(url.replace("/kairos_subs?", "/kairos_owner_subs?"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        localStorage.setItem("kx-push-own", j.endpoint);
      }
    } catch (e) {}
  }
  async function reg() {
    return navigator.serviceWorker.register("sw.js", { scope: "./" });
  }
  async function current() {
    var r = await navigator.serviceWorker.getRegistration("./");
    return r ? r.pushManager.getSubscription() : null;
  }

  // いまの状態：off / on / denied / ios-home / unsupported
  async function state() {
    if (!supported) return isIOS && !standalone ? "ios-home" : "unsupported";
    if (Notification.permission === "denied") return "denied";
    if (Notification.permission !== "granted") return "off";
    var s = await current();
    return s ? "on" : "off";
  }

  function bodyHTML(st) {
    if (busy) return '<p class="note">' + busy + "</p>";
    var err = lastErr ? '<p class="note" style="color:#c44">' + lastErr + "</p>" : "";
    if (st === "ios-home")
      return (
        '<p class="note">iPhone・iPad では、Safari の共有ボタンから「ホーム画面に追加」したKairosで設定できます。ホーム画面のアイコンから開いて、もう一度この画面を見てください。</p>'
      );
    if (st === "unsupported") return '<p class="note">このブラウザは通知に対応していません。</p>';
    if (st === "denied")
      return '<p class="note">通知がオフになっています。端末の設定で、Kairos（またはブラウザ）の通知を許可してください。</p>';
    if (st === "on")
      return (
        '<p class="note">オンです。新しい情報が入った朝に1回お知らせします。</p>' +
        err +
        '<div class="pills"><button type="button" id="kx-push-off">通知を止める</button></div>'
      );
    return (
      '<p class="note">新しい情報が入った朝に1回お知らせします。</p>' +
      err +
      '<div class="pills"><button type="button" id="kx-push-on">通知を受け取る</button></div>'
    );
  }
  function paint(st) {
    var el = document.getElementById("kx-push-b");
    if (!el) return;
    el.innerHTML = bodyHTML(st);
    var on = document.getElementById("kx-push-on");
    var off = document.getElementById("kx-push-off");
    if (on) on.addEventListener("click", turnOn);
    if (off) off.addEventListener("click", turnOff);
  }
  async function refresh() {
    try {
      paint(await state());
    } catch (e) {
      paint("unsupported");
    }
  }

  function withTimeout(p, ms) {
    return Promise.race([
      p,
      new Promise(function (_, rej) {
        setTimeout(function () {
          rej(new Error("timeout"));
        }, ms);
      }),
    ]);
  }
  async function subscribeAndSave() {
    var r = await reg();
    await navigator.serviceWorker.ready;
    var key = b64u(C.vapidPublicKey);
    var sub = await r.pushManager.getSubscription();
    if (!sub) {
      try {
        sub = await r.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      } catch (e) {
        var old = await r.pushManager.getSubscription();
        if (old) await old.unsubscribe();
        sub = await r.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      }
    }
    await save(sub);
  }
  async function turnOn() {
    lastErr = "";
    var perm;
    try {
      perm = await Notification.requestPermission();
    } catch (e) {
      perm = Notification.permission;
    }
    if (perm !== "granted") return refresh();
    busy = "設定しています…";
    paint();
    try {
      await withTimeout(subscribeAndSave(), 30000);
    } catch (e) {
      lastErr = "うまく設定できませんでした。時間をおいてもう一度お試しください。";
    }
    busy = "";
    refresh();
  }
  async function turnOff() {
    lastErr = "";
    busy = "止めています…";
    paint();
    try {
      var s = await current();
      if (s) await s.unsubscribe();
    } catch (e) {}
    lsSet("");
    busy = "";
    refresh();
  }

  // 端末側で購読が入れ替わっていたら、新しいものを保存し直す
  async function resync() {
    try {
      if (!supported || Notification.permission !== "granted") return;
      var s = await current();
      var own = false;
      try {
        own = localStorage.getItem("kx-mode") === "owner" && localStorage.getItem("kx-push-own") !== (s && s.endpoint);
      } catch (e) {}
      if (s && (s.endpoint !== lsGet() || own)) await save(s);
    } catch (e) {}
  }

  if (configured && supported) {
    window.addEventListener("load", function () {
      reg()
        .then(resync)
        .catch(function () {});
    });
  }

  window.KairosPush = {
    html: function () {
      if (!configured) return "";
      return '<section class="panel" id="kx-push"><h2>通知</h2><div class="pb" id="kx-push-b"></div></section>';
    },
    bind: function () {
      if (configured) refresh();
    },
  };
})();
