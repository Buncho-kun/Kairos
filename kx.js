/* Kairos: encrypted data loader for the GitHub Pages version. */
(function () {
  const ENC = new TextEncoder();
  const LS_KEY = "kx-key";
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
  async function tryRaw(raw, meta) {
    const k = await imp(raw);
    await decBuf(k, b64d(meta.check).buffer);
    return k;
  }
  function gate(meta, resolve) {
    const w = document.createElement("div");
    w.id = "kx-gate";
    w.innerHTML =
      '<form><p class="kx-t">合言葉を入力してください</p>' +
      '<input type="password" autocomplete="current-password" autocapitalize="off" spellcheck="false">' +
      '<button type="submit">開く</button><p class="kx-e" role="alert"></p></form>';
    document.body.appendChild(w);
    const f = w.querySelector("form");
    const inp = w.querySelector("input");
    const err = w.querySelector(".kx-e");
    const btn = w.querySelector("button");
    setTimeout(() => inp.focus(), 50);
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!inp.value) return;
      btn.disabled = true;
      err.textContent = "確認しています…";
      try {
        const raw = await derive(inp.value, meta);
        const k = await tryRaw(raw, meta);
        try {
          localStorage.setItem(LS_KEY, b64e(raw));
          localStorage.setItem(LS_SALT, meta.salt);
        } catch (x) {}
        w.remove();
        resolve(k);
      } catch (x) {
        err.textContent = "合言葉が違います";
        btn.disabled = false;
        inp.select();
      }
    });
  }
  function getKey() {
    return (keyP =
      keyP ||
      getMeta().then(async (meta) => {
        try {
          const raw = localStorage.getItem(LS_KEY);
          if (raw && localStorage.getItem(LS_SALT) === meta.salt) return await tryRaw(b64d(raw), meta);
        } catch (x) {}
        return new Promise((res) => gate(meta, res));
      }));
  }
  async function fetchDec(path) {
    const k = await getKey();
    const r = await fetch(path, { cache: "no-cache" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return JSON.parse(await decBuf(k, await r.arrayBuffer()));
  }
  /* fetch() replacement for the bundled reference files */
  window.kxFetch = (src) =>
    fetchDec("data/" + src + ".enc").then(
      (d) => ({ ok: true, status: 200, json: async () => d }),
      (e) => ({ ok: false, status: 0, json: async () => { throw e; } }),
    );
  /* minimal read-only stand-in for the artifact database */
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
