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
  const imp = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt", "encrypt"]);
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

  const iosBrowser = () => {
    const ua = navigator.userAgent || "";
    const ios = /iP(hone|od|ad)/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const alone = navigator.standalone === true || (window.matchMedia && matchMedia("(display-mode: standalone)").matches);
    return ios && !alone;
  };
  function gate(meta, resolve, note) {
    const w = document.createElement("div");
    w.id = "kx-gate";
    w.innerHTML =
      '<form><p class="kx-t">アクセスコードを入力してください</p>' +
      (iosBrowser()
        ? '<p class="kx-h">iPhone・iPadの方へ：先に、共有ボタン（四角から矢印が出ている印）→「ホーム画面に追加」を行い、ホーム画面のアイコンから開いてコードを入れてください。ここで入れると、登録できる3台のうち1台分を余計に使います。</p>'
        : "") +
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
      }).then(agree));
  }
  /* first use on this device: show the terms once */
  const LS_AGREE = "kx-agree";
  function agree(k) {
    if (lsGet(LS_AGREE) === "1") return k;
    return new Promise((res) => {
      const w = document.createElement("div");
      w.id = "kx-agree";
      w.innerHTML =
        '<form><p class="kx-t">使う前に確認してください</p><ol>' +
        "<li>内容は診療の参考情報です。処方や判断の前に、電子添文や原典を確かめてください。最終的な判断は担当医が行います。</li>" +
        "<li>メモ欄や報告欄に、患者さんの氏名・IDなど個人が分かる情報を書かないでください。</li>" +
        "<li>アクセスコードは本人専用です。ほかの人に渡さないでください。</li>" +
        "<li>誤りや古い記載に気づいたら、設定の「誤り・要望の報告」から知らせてください。</li>" +
        '</ol><button type="submit">同意して使う</button></form>';
      document.body.appendChild(w);
      w.querySelector("form").addEventListener("submit", (e) => {
        e.preventDefault();
        lsSet(LS_AGREE, "1");
        w.remove();
        res(k);
      });
    });
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
  /* ---- 誤り・要望の報告（データ鍵で暗号化して送る。読めるのは管理者の端末だけ） ---- */
  async function seal(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ENC.encode(JSON.stringify(obj))));
    const all = new Uint8Array(12 + ct.length);
    all.set(iv);
    all.set(ct, 12);
    return b64e(all);
  }
  async function unseal(key, b64) {
    const b = b64d(b64);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, key, b.slice(12));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  const isOwner = () => lsGet(LS_MODE) === "owner";
  const fmtAt = (ms) => {
    if (!ms) return "未使用";
    const d = new Date(ms);
    return d.getFullYear() + "/" + (d.getMonth() + 1) + "/" + d.getDate() + " " + String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  };
  const escH = (t) => String(t == null ? "" : t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  window.KairosReport = {
    html() {
      if (!lsGet(LS_SYNC)) return "";
      return (
        '<section class="panel" id="kx-rep"><h2>誤り・要望の報告</h2><div class="pb">' +
        '<p class="note">内容の誤り、古い記載、使いにくい点を管理者に送れます。患者さんの個人情報は書かないでください。</p>' +
        '<label class="sr" for="kx-rep-t">報告の内容</label>' +
        '<textarea id="kx-rep-t" rows="4" maxlength="2000" placeholder="例：ツール「相互作用」の○○と△△の組み合わせ。添付文書では併用注意になっている。"></textarea>' +
        '<label class="sr" for="kx-rep-n">名前（任意）</label>' +
        '<input id="kx-rep-n" type="text" maxlength="40" placeholder="名前（任意）" autocomplete="off">' +
        '<div class="pills"><button type="button" id="kx-rep-send">送信</button></div>' +
        '<p class="note" id="kx-rep-msg" role="status"></p></div></section>'
      );
    },
    bind(ctx) {
      const b = document.getElementById("kx-rep-send");
      if (!b) return;
      const nm = document.getElementById("kx-rep-n");
      nm.value = lsGet("kx-rep-name") || "";
      b.onclick = async () => {
        const ta = document.getElementById("kx-rep-t");
        const msg = document.getElementById("kx-rep-msg");
        const text = ta.value.trim();
        if (!text) return (msg.textContent = "内容を入力してください。");
        b.disabled = true;
        msg.textContent = "送信しています…";
        try {
          const k = await getKey();
          const cid = lsGet(LS_SYNC);
          lsSet("kx-rep-name", nm.value.trim() || null);
          const blob = await seal(k, {
            text,
            name: nm.value.trim(),
            where: typeof ctx === "function" ? ctx() : "",
            ua: /iP(hone|ad)/.test(navigator.userAgent) ? "iPhone/iPad" : /Android/.test(navigator.userAgent) ? "Android" : "PC",
          });
          const t = await idToken();
          const id = hex(crypto.getRandomValues(new Uint8Array(10)));
          const r = await fetch(fsBase() + ":commit", {
            method: "POST",
            headers: { Authorization: "Bearer " + t.id, "Content-Type": "application/json" },
            body: JSON.stringify({
              writes: [
                {
                  update: { name: docName("kx_feedback/" + id), fields: { b: { stringValue: blob }, cid: { stringValue: cid } } },
                  updateTransforms: [{ fieldPath: "at", setToServerValue: "REQUEST_TIME" }],
                  currentDocument: { exists: false },
                },
              ],
            }),
          });
          if (!r.ok) throw new Error(String(r.status));
          ta.value = "";
          msg.textContent = "送信しました。ありがとうございます。";
        } catch (x) {
          msg.textContent = "送信できませんでした（" + (x && x.message) + "）。通信状況を確かめて、もう一度お試しください。";
        }
        b.disabled = false;
      };
    },
  };
  /* ---- 管理者用：コードの利用状況と、届いた報告 ---- */
  async function ownerCodes() {
    const kek = b64d(lsGet(LS_KEY));
    const r = await fetch("data/codes.enc", { cache: "no-cache" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const lst = JSON.parse(await decBuf(await imp(kek), await r.arrayBuffer()));
    const out = [];
    for (const c of lst) {
      if (!c.n || !c.code) continue;
      const cid = await codeId(c.code);
      let devices = [];
      try {
        const s = await fsGet("kx_slots/" + cid);
        if (s.status === 200) devices = slotInfo(s.doc).devices;
        else devices = null;
      } catch (x) {
        devices = undefined; // 通信できず
      }
      out.push({ n: c.n, label: c.label || "", code: c.code, cid, devices });
    }
    return out;
  }
  async function ownerFeedback(codes) {
    const t = await idToken();
    const r = await fetch(fsBase() + "/kx_feedback?pageSize=300", {
      headers: { Authorization: "Bearer " + t.id },
      cache: "no-store",
    });
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    const k = await getKey();
    const out = [];
    for (const d of j.documents || []) {
      const f = d.fields || {};
      const cid = (f.cid && f.cid.stringValue) || "";
      const c = codes.find((x) => x.cid === cid);
      let body = null;
      try {
        body = await unseal(k, f.b.stringValue);
      } catch (x) {}
      out.push({
        id: d.name.split("/").pop(),
        at: Date.parse((f.at && f.at.timestampValue) || 0) || 0,
        from: c ? c.n + "番" + (c.label ? " " + c.label : "") : cid === lsGet(LS_SYNC) ? "管理者" : "不明なコード",
        body,
      });
    }
    return out.sort((a, b) => b.at - a.at);
  }
  window.KairosAdmin = {
    html() {
      if (!isOwner()) return "";
      return '<section class="panel" id="kx-adm"><h2>管理</h2><div class="pb" id="kx-adm-b"><p class="note">読み込んでいます…</p></div></section>';
    },
    async bind() {
      const el = document.getElementById("kx-adm-b");
      if (!el) return;
      let codes = [];
      let h = "";
      try {
        codes = await ownerCodes();
        h +=
          '<p class="lbl">コードの利用状況</p><table class="kx-tbl"><thead><tr><th>番号</th><th>名前</th><th>台数</th><th>最後に使った日時</th></tr></thead><tbody>' +
          codes
            .map((c) => {
              const last = c.devices && c.devices.length ? Math.max.apply(null, c.devices.map((d) => d.at)) : 0;
              return (
                "<tr><td>" + c.n + "</td><td>" + (escH(c.label) || "—") + "</td><td>" +
                (c.devices ? c.devices.length + "/3" : c.devices === null ? "未反映" : "確認できず") + "</td><td>" + (c.devices ? fmtAt(last) : "—") + "</td></tr>"
              );
            })
            .join("") +
          '</tbody></table><p class="note">名前の変更・コードの追加と停止はClaudeに頼んでください。「未反映」はサーバーにまだ登録されていないコードです。</p>';
      } catch (x) {
        h += '<p class="note">コードの一覧を読めませんでした（' + escH(x && x.message) + "）。</p>";
      }
      try {
        const fb = await ownerFeedback(codes);
        h +=
          '<p class="lbl">届いた報告（' + fb.length + "件）</p>" +
          (fb.length
            ? fb
                .map(
                  (f) =>
                    '<div class="kx-fb"><div class="note">' + fmtAt(f.at) + "　" + escH(f.from) +
                    (f.body && f.body.name ? "（" + escH(f.body.name) + "）" : "") +
                    (f.body && f.body.where ? "　" + escH(f.body.where) : "") +
                    (f.body && f.body.ua ? "　" + escH(f.body.ua) : "") +
                    "</div><p>" + (f.body ? escH(f.body.text) : "（読めませんでした）") +
                    '</p><button type="button" class="kx-fb-del" data-fbdel="' + f.id + '">対応済みにして消す</button></div>',
                )
                .join("")
            : '<p class="note">まだありません。</p>');
      } catch (x) {
        h += '<p class="note">報告を読めませんでした（' + escH(x && x.message) + "）。この端末が管理者として登録されていない可能性があります。</p>";
      }
      el.innerHTML = h;
      el.querySelectorAll("[data-fbdel]").forEach((b) => {
        b.onclick = async () => {
          if (!window.confirm("この報告を消します。よろしいですか？")) return;
          b.disabled = true;
          const t = await idToken();
          const r = await fetch(fsBase() + "/kx_feedback/" + b.dataset.fbdel, { method: "DELETE", headers: { Authorization: "Bearer " + t.id } });
          if (r.ok) b.closest(".kx-fb").remove();
          else b.disabled = false;
        };
      });
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
