/* Kairos: encrypted data loader for the GitHub Pages version. */
(function () {
  const ENC = new TextEncoder();
  const LS_KEY = "kx-kek";
  const LS_SALT = "kx-salt";
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (u) => {
    let s = "";
    u.forEach((b) => (s += String.fromCharCode(b)));
    return btoa(s);
  };
  let metaP = null;
  let keyP = null;
  const getMeta = () =>
    (metaP =
      metaP ||
      fetch("k.json", { cache: "no-cache" }).then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      }));
  async function derive(pass, meta) {
    const base = await crypto.subtle.importKey("raw", ENC.encode(pass), "PBKDF2", false, [
      "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: b64d(meta.salt), iterations: meta.iter },
      base,
      256,
    );
    return new Uint8Array(bits);
  }
  const imp = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  async function decBuf(key, buf) {
    const u = new Uint8Array(buf);
    if (u[0] !== 75 || u[1] !== 88 || u[2] !== 49) throw new Error("bad file");
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(3, 15) }, key, u.slice(15));
    const s = new Blob([pt]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(s).text();
  }
  const impWrap = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  /* kek: raw bytes derived from a person's code; returns the data key or throws */
  async function openWith(kekRaw, meta) {
    const kk = await impWrap(kekRaw);
    for (const w of meta.wraps || []) {
      try {
        const b = b64d(w.w);
        const dk = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, kk, b.slice(12));
        const k = await imp(new Uint8Array(dk));
        await decBuf(k, b64d(meta.check).buffer);
        return k;
      } catch (x) {}
    }
    throw new Error("no match");
  }
  const normCode = (c) => c.toUpperCase().replace(/[^A-Z0-9]/g, "");
  const LS_MODE = "kx-mode"; // "owner" | "code:<cid>"
  const LS_AUTH = "kx-auth";
  const LS_W = "kx-w"; // wrapped key kept for offline use
  const LS_SYNC = "kx-sync"; // id of the shared record for marks
  const lsGet = (k) => {
    try {
      return localStorage.getItem(k);
    } catch (x) {
      return null;
    }
  };
  const lsSet = (k, v) => {
    try {
      if (v == null) localStorage.removeItem(k);
      else localStorage.setItem(k, v);
    } catch (x) {}
  };
  const hex = (buf) =>
    Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  const codeId = async (code) =>
    hex(await crypto.subtle.digest("SHA-256", ENC.encode("kairos-code:" + normCode(code)))).slice(0, 40);

  /* ---- Firebase (anonymous sign-in + Firestore REST) for the 3-device limit ---- */
  const FB = () => window.KAIROS_PUSH || {};
  let tok = null;
  async function idToken() {
    if (tok && tok.exp > Date.now() + 60e3) return tok;
    const key = FB().firebaseApiKey;
    if (!key) throw new Error("設定が読み込めません");
    let a = null;
    try {
      a = JSON.parse(lsGet(LS_AUTH) || "null");
    } catch (x) {}
    let r, j;
    if (a && a.refresh) {
      r = await fetch("https://securetoken.googleapis.com/v1/token?key=" + key, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "grant_type=refresh_token&refresh_token=" + encodeURIComponent(a.refresh),
      });
      j = await r.json().catch(() => ({}));
      if (!r.ok) lsSet(LS_AUTH, null);
      if (r.ok) {
        tok = { id: j.id_token, uid: j.user_id, exp: Date.now() + (+j.expires_in || 3600) * 1000 };
        lsSet(LS_AUTH, JSON.stringify({ uid: j.user_id, refresh: j.refresh_token }));
        return tok;
      }
    }
    r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + key, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ returnSecureToken: true }),
    });
    j = await r.json().catch(() => ({}));
    if (!r.ok) {
      const m = String((j.error && j.error.message) || "");
      const why = /ADMIN_ONLY_OPERATION|OPERATION_NOT_ALLOWED/.test(m)
        ? "サーバー側で端末の登録が止まっています。管理者に連絡してください"
        : /TOO_MANY_ATTEMPTS/.test(m)
          ? "短時間に試行が多すぎます。1時間ほどおいて試してください"
          : /API_KEY|API key/i.test(m)
            ? "アプリの設定に問題があります。管理者に連絡してください"
            : "時間をおいて試してください";
      throw new Error("端末の確認に失敗しました（" + r.status + (m ? " " + m.split(" ")[0] : "") + "）。" + why);
    }
    tok = { id: j.idToken, uid: j.localId, exp: Date.now() + (+j.expiresIn || 3600) * 1000 };
    lsSet(LS_AUTH, JSON.stringify({ uid: j.localId, refresh: j.refreshToken }));
    return tok;
  }
  const fsBase = () =>
    "https://firestore.googleapis.com/v1/projects/" + FB().firebaseProjectId + "/databases/(default)/documents";
  const docName = (path) =>
    "projects/" + FB().firebaseProjectId + "/databases/(default)/documents/" + path;
  async function fsGet(path) {
    const t = await idToken();
    const r = await fetch(fsBase() + "/" + path, { headers: { Authorization: "Bearer " + t.id }, cache: "no-store" });
    if (r.status === 403 || r.status === 404) return { status: r.status };
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      const m = String((j.error && (j.error.status || j.error.message)) || "");
      throw new Error("通信に失敗しました（" + r.status + (m ? " " + m.split(" ")[0] : "") + "）");
    }
    return { status: 200, doc: await r.json() };
  }
  async function fsWrite(path, mask, transforms) {
    const t = await idToken();
    const r = await fetch(fsBase() + ":commit", {
      method: "POST",
      headers: { Authorization: "Bearer " + t.id, "Content-Type": "application/json" },
      body: JSON.stringify({
        writes: [
          {
            update: { name: docName(path), fields: {} },
            updateMask: { fieldPaths: mask },
            updateTransforms: transforms.map((f) => ({ fieldPath: f, setToServerValue: "REQUEST_TIME" })),
            currentDocument: { exists: true },
          },
        ],
      }),
    });
    return r.ok;
  }
  const dev = (uid) => "devices.`" + uid + "`";
  function slotInfo(doc) {
    const f = (doc && doc.fields) || {};
    const m = (f.devices && f.devices.mapValue && f.devices.mapValue.fields) || {};
    const devices = Object.keys(m).map((u) => ({ uid: u, at: Date.parse(m[u].timestampValue || 0) || 0 }));
    const swapAt = Date.parse((f.swapAt && f.swapAt.timestampValue) || 0) || 0;
    return { devices, swapAt };
  }
  class GateError extends Error {}
  /* returns the AES key for a code, registering this device if there is room */
  async function keyForCode(code, meta, allowJoin) {
    const kek = await derive(normCode(code), meta);
    const cid = await codeId(code);
    const read = async () => {
      const r = await fsGet("kx_keys/" + cid);
      if (r.status !== 200) return null;
      const w = r.doc.fields.w.stringValue;
      const k = await openWith(kek, { wraps: [{ w }], check: meta.check });
      lsSet(LS_W, w);
      return k;
    };
    let k = await read();
    if (k) return { k, cid };
    if (!allowJoin) throw new GateError("この端末の登録が外れています。コードを入れ直してください。");
    const s = await fsGet("kx_slots/" + cid);
    if (s.status !== 200) throw new GateError("コードが違うか、無効になっています");
    const info = slotInfo(s.doc);
    const me = (await idToken()).uid;
    let ok = false;
    if (info.devices.some((d) => d.uid === me)) ok = true;
    else if (info.devices.length < 3) ok = await fsWrite("kx_slots/" + cid, [], [dev(me)]);
    else {
      const next = info.swapAt + 30 * 864e5;
      if (Date.now() < next) {
        const d = new Date(next);
        throw new GateError(
          "このコードはすでに3台で使われています。入れ替えは " +
            (d.getMonth() + 1) + "月" + d.getDate() + "日以降にできます。急ぐときは管理者に連絡してください。",
        );
      }
      const old = info.devices.slice().sort((a, b) => a.at - b.at)[0];
      if (!window.confirm("このコードはすでに3台で使われています。いちばん長く使われていない端末の登録を外して、この端末を登録しますか？（入れ替えは30日に1回まで）"))
        throw new GateError("登録をやめました");
      ok = await fsWrite("kx_slots/" + cid, [dev(old.uid)], [dev(me), "swapAt"]);
    }
    if (!ok) throw new GateError("端末を登録できませんでした。時間をおいて試してください。");
    k = await read();
    if (!k) throw new GateError("コードが違うか、無効になっています");
    return { k, cid };
  }
  const ownerId = async (kekRaw) =>
    hex(await crypto.subtle.digest("SHA-256", ENC.encode("kairos-owner:" + b64e(kekRaw)))).slice(0, 40);
  /* register this device under the owner's record so marks can sync (best effort, never blocks) */
  async function ownerJoin(kekRaw) {
    const cid = await ownerId(kekRaw);
    lsSet(LS_SYNC, cid);
    const me = (await idToken()).uid;
    const s = await fsGet("kx_slots/" + cid);
    if (s.status !== 200) return;
    const info = slotInfo(s.doc);
    if (info.devices.some((d) => d.uid === me)) await fsWrite("kx_slots/" + cid, [], [dev(me)]);
    else if (info.devices.length < 3) await fsWrite("kx_slots/" + cid, [], [dev(me)]);
  }
  /* owner passphrase: wraps in k.json */
  async function keyForOwner(pass, meta) {
    const kek = await derive(pass, meta);
    return { k: await openWith(kek, meta), kek };
  }

  function gate(meta, resolve, note) {
    const w = document.createElement("div");
    w.id = "kx-gate";
    w.innerHTML =
      '<form><p class="kx-t">アクセスコードを入力してください</p>' +
      '<input type="password" autocomplete="current-password" autocapitalize="off" spellcheck="false">' +
      '<button type="submit">開く</button><p class="kx-e" role="alert"></p></form>';
    document.body.appendChild(w);
    const f = w.querySelector("form");
    const inp = w.querySelector("input");
    const err = w.querySelector(".kx-e");
    const btn = w.querySelector("button");
    if (note) err.textContent = note;
    setTimeout(() => inp.focus(), 50);
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const v = inp.value.trim();
      if (!v) return;
      btn.disabled = true;
      err.textContent = "確認しています…";
      try {
        let k = null;
        try {
          const o = await keyForOwner(v, meta);
          k = o.k;
          lsSet(LS_MODE, "owner");
          lsSet(LS_KEY, b64e(o.kek));
          ownerJoin(o.kek).catch(() => {});
        } catch (x) {}
        if (!k) {
          const c = await keyForCode(v, meta, true);
          k = c.k;
          lsSet(LS_MODE, "code:" + c.cid);
          lsSet(LS_SYNC, c.cid);
          lsSet(LS_KEY, b64e(await derive(normCode(v), meta)));
        }
        lsSet(LS_SALT, meta.salt);
        w.remove();
        resolve(k);
      } catch (x) {
        err.textContent = x instanceof GateError ? x.message : "確認できませんでした（" + (x && x.message) + "）";
        btn.disabled = false;
        inp.select();
      }
    });
  }
  async function reopen(meta) {
    const mode = lsGet(LS_MODE) || "";
    const raw = lsGet(LS_KEY);
    if (!raw || lsGet(LS_SALT) !== meta.salt) return null;
    const kek = b64d(raw);
    if (mode === "owner" || !mode) {
      const k = await openWith(kek, meta);
      ownerJoin(kek).catch(() => {});
      return k;
    }
    const cid = mode.slice(5);
    let r = null;
    try {
      r = await fsGet("kx_keys/" + cid);
    } catch (x) {
      r = null; // offline: use the key saved on this device
    }
    if (r && r.status !== 200) throw new GateError("この端末の登録が外れました。コードを入れ直してください。");
    const w = r ? r.doc.fields.w.stringValue : lsGet(LS_W);
    if (!w) throw new Error("offline");
    const k = await openWith(kek, { wraps: [{ w }], check: meta.check });
    if (r) {
      lsSet(LS_W, w);
      idToken()
        .then((t) => fsWrite("kx_slots/" + cid, [], [dev(t.uid)]))
        .catch(() => {});
    }
    return k;
  }
  function getKey() {
    return (keyP =
      keyP ||
      getMeta().then(async (meta) => {
        let note = "";
        try {
          const k = await reopen(meta);
          if (k) return k;
        } catch (x) {
          if (x instanceof GateError) {
            note = x.message;
            lsSet(LS_MODE, null);
            lsSet(LS_KEY, null);
            lsSet(LS_W, null);
          } else note = "通信できないため開けませんでした。電波のある場所で一度開くと、次からは電波がなくても開けます。";
        }
        return new Promise((res) => gate(meta, res, note));
      }));
  }

  /* settings panel: this device's registration */
  window.KairosDevice = {
    html() {
      const mode = lsGet(LS_MODE) || "";
      if (!mode.startsWith("code:")) return "";
      return (
        '<section class="panel" id="kx-dev"><h2>この端末</h2><div class="pb">' +
        '<p class="note">1つのコードで使える端末は3台までです。機種変更などで使わなくなる端末は、ここで登録を外してください。</p>' +
        '<div class="pills"><button type="button" id="kx-dev-leave">この端末の登録を外す</button></div>' +
        '<p class="note" id="kx-dev-msg"></p></div></section>'
      );
    },
    bind() {
      const b = document.getElementById("kx-dev-leave");
      if (!b) return;
      b.onclick = async () => {
        if (!window.confirm("この端末の登録を外します。次に開くときはコードの入力が必要です。よろしいですか？")) return;
        b.disabled = true;
        const msg = document.getElementById("kx-dev-msg");
        try {
          const cid = (lsGet(LS_MODE) || "").slice(5);
          const me = (await idToken()).uid;
          const ok = await fsWrite("kx_slots/" + cid, [dev(me)], []);
          if (!ok) throw new Error("x");
          lsSet(LS_MODE, null);
          lsSet(LS_KEY, null);
          lsSet(LS_W, null);
          lsSet(LS_SYNC, null);
          location.reload();
        } catch (x) {
          if (msg) msg.textContent = "外せませんでした。通信状況を確認してください。";
          b.disabled = false;
        }
      };
    },
  };
  async function fetchDec(path) {
    const k = await getKey();
    const r = await fetch(path, { cache: "no-cache" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return JSON.parse(await decBuf(k, await r.arrayBuffer()));
  }
  /* ---- ★保存・メモの同期（コードごと、暗号化して Firestore に保存） ---- */
  const AT_LS = "kx-marks-at";
  async function syncKey() {
    const raw = lsGet(LS_KEY);
    if (!raw) return null;
    return crypto.subtle.importKey("raw", b64d(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  async function pullMarks() {
    const cid = lsGet(LS_SYNC);
    const key = await syncKey();
    if (!cid || !key) return null;
    const r = await fsGet("kx_marks/" + cid);
    if (r.status !== 200) return null;
    const b = b64d(r.doc.fields.b.stringValue);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, key, b.slice(12));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  let pushTimer = null;
  async function pushMarks(marks) {
    const cid = lsGet(LS_SYNC);
    const key = await syncKey();
    if (!cid || !key) return;
    const at = +(lsGet(AT_LS) || Date.now());
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ENC.encode(JSON.stringify({ at, marks }))),
    );
    const all = new Uint8Array(12 + ct.length);
    all.set(iv);
    all.set(ct, 12);
    const t = await idToken();
    await fetch(fsBase() + ":commit", {
      method: "POST",
      headers: { Authorization: "Bearer " + t.id, "Content-Type": "application/json" },
      body: JSON.stringify({
        writes: [
          {
            update: {
              name: docName("kx_marks/" + cid),
              fields: { b: { stringValue: b64e(all) }, at: { integerValue: String(at) } },
            },
          },
        ],
      }),
    });
  }
  const startAt = +(lsGet(AT_LS) || 0); // last local change before this session
  let pulled = false;
  let pending = null;
  window.KairosSync = {
    /* resolves to the newer marks from the cloud, or null to keep the local ones */
    async pull(local) {
      let out = null;
      try {
        const remote = await pullMarks();
        if (remote && remote.at > startAt) {
          lsSet(AT_LS, String(remote.at));
          out = remote.marks || {};
          pending = null;
        } else if (local && Object.keys(local).length) {
          lsSet(AT_LS, String(Math.max(startAt, Date.now())));
          pending = local;
        }
      } catch (x) {}
      pulled = true;
      if (pending) {
        const m = pending;
        pending = null;
        pushMarks(m).catch(() => {});
      }
      return out;
    },
    push(marks) {
      if (!pulled) {
        pending = marks;
        return;
      }
      lsSet(AT_LS, String(Date.now()));
      clearTimeout(pushTimer);
      pushTimer = setTimeout(() => pushMarks(marks).catch(() => {}), 1500);
    },
  };
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));
  }

  /* fetch() replacement for the bundled reference files */
  window.kxFetch = (src) =>
    fetchDec("data/" + src + ".enc").then(
      (d) => ({ ok: true, status: 200, json: async () => d }),
      (e) => ({ ok: false, status: 0, json: async () => { throw e; } }),
    );
  /* read-only query interface over the decrypted collections */
  function mkDb(cols) {
    const docObj = (id, d) => ({ id, exists: d !== undefined, data: () => d });
    const snapOf = (a) => ({ docs: a, size: a.length, metadata: { fromCache: false } });
    const later = (fn) => Promise.resolve().then(fn);
    function Q(name, f, o, l) {
      const run = () => {
        let a = Object.entries(cols[name] || {}).map(([id, d]) => docObj(id, d));
        f.forEach(([k, op, v]) => {
          a = a.filter((x) => {
            const z = x.data()[k];
            if (z == null) return false;
            if (op === ">=") return String(z) >= String(v);
            if (op === "<=") return String(z) <= String(v);
            if (op === ">") return String(z) > String(v);
            if (op === "<") return String(z) < String(v);
            if (op === "==") return z === v;
            return true;
          });
        });
        if (o) {
          const [k, dir] = o;
          const s = dir === "desc" ? -1 : 1;
          a.sort((p, q) => {
            const A = String(p.data()[k] ?? ""),
              B = String(q.data()[k] ?? "");
            return (A < B ? -1 : A > B ? 1 : 0) * s;
          });
        }
        if (l != null) a = a.slice(0, l);
        return snapOf(a);
      };
      const denied = async () => {
        throw new Error("permission denied");
      };
      return {
        where: (k, op, v) => Q(name, f.concat([[k, op, v]]), o, l),
        orderBy: (k, dir) => Q(name, f, [k, dir || "asc"], l),
        limit: (n) => Q(name, f, o, n),
        get: async () => run(),
        onSnapshot: (cb, eb) => {
          later(() => cb(run())).catch((e) => eb && eb(e));
          return () => {};
        },
        doc: (id) => ({
          get: async () => docObj(id, (cols[name] || {})[id]),
          set: denied,
          update: denied,
          onSnapshot: (cb, eb) => {
            later(() => cb(docObj(id, (cols[name] || {})[id]))).catch((e) => eb && eb(e));
            return () => {};
          },
        }),
        add: denied,
      };
    }
    return {
      collection: (n) => Q(n, [], null, null),
      doc: (p) => {
        const i = p.lastIndexOf("/");
        return Q(p.slice(0, i), [], null, null).doc(p.slice(i + 1));
      },
    };
  }
  const COLLS = ["items", "branches", "journals", "manuals", "watch", "tools", "meta"];
  window.kxOpenDb = async () => {
    const parts = await Promise.all(COLLS.map((c) => fetchDec("data/" + c + ".enc").catch(() => ({}))));
    const cols = {};
    COLLS.forEach((c, i) => (cols[c] = parts[i] || {}));
    return mkDb(cols);
  };
})();
