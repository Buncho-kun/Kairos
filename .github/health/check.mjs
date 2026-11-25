// 毎朝の点検。利用者と同じ道筋（端末の登録→コードの確認）と、データの更新・復号を確かめる。
// 失敗したら管理者の端末に通知し、ジョブを失敗させる（GitHub からもメールが届く）。
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
const require = createRequire(new URL("../codes/package.json", import.meta.url));
const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const env = process.env;
const cfg = fs.readFileSync("push-config.js", "utf8");
const pick = (k) => (cfg.match(new RegExp(k + '\\s*:\\s*"([^"]*)"')) || [])[1] || "";
const API = pick("firebaseApiKey");
const PROJECT = pick("firebaseProjectId");
const SITE = "https://buncho-kun.github.io/Kairos/";
const REF = { Referer: SITE, Origin: "https://buncho-kun.github.io" };
const fails = [];
const notes = [];
const fail = (m) => (fails.push(m), console.log("NG  " + m));
const ok = (m) => console.log("ok  " + m);

const account = JSON.parse(String(env.FIREBASE_SERVICE_ACCOUNT || "{}").trim() || "{}");
const app = account.private_key ? initializeApp({ credential: cert(account) }) : null;
const db = app ? getFirestore(app) : null;

async function signUp() {
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + API, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...REF },
    body: JSON.stringify({ returnSecureToken: true }),
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, msg: (j.error && j.error.message) || "", id: j.idToken };
}

// 1. 端末の登録（匿名ログイン）。止まっていたら有効に戻して、もう一度試す
let me = await signUp();
if (!me.ok && app && /ADMIN_ONLY_OPERATION|OPERATION_NOT_ALLOWED/.test(me.msg)) {
  const tok = await app.options.credential.getAccessToken();
  const r = await fetch(
    `https://identitytoolkit.googleapis.com/admin/v2/projects/${account.project_id}/config?updateMask=signIn.anonymous.enabled`,
    {
      method: "PATCH",
      headers: { Authorization: "Bearer " + tok.access_token, "Content-Type": "application/json" },
      body: JSON.stringify({ signIn: { anonymous: { enabled: true } } }),
    },
  );
  notes.push("匿名ログインが止まっていたので" + (r.ok ? "有効に戻しました" : "戻そうとしましたが失敗しました（" + r.status + "）"));
  me = await signUp();
}
if (me.ok) ok("端末の登録（匿名ログイン）");
else fail(`端末の登録に失敗（${me.status} ${me.msg}）。利用者はコードを入れても開けません`);

// 2. コードの確認（枠は読める・鍵は未登録の端末には渡さない）
let codes = [];
try {
  codes = JSON.parse(execFileSync("python3", ["tools/kdb.py", "slots"], { encoding: "utf8", env: { ...env } }));
  ok("コードの一覧を開けた（" + codes.length + "件）");
} catch (e) {
  fail("コードの一覧を開けません（KAIROS_PASS か data/codes.enc を確認）");
}
if (me.ok && codes.length) {
  const c = codes.find((x) => x.n !== 0) || codes[0];
  const base = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/`;
  const h = { Authorization: "Bearer " + me.id, ...REF };
  const s = await fetch(base + "kx_slots/" + c.cid, { headers: h });
  if (s.status === 200) ok("コードの枠を読めた");
  else fail(`コードの枠を読めません（${s.status}）。codes.yml の反映を確認`);
  const k = await fetch(base + "kx_keys/" + c.cid, { headers: h });
  if (k.status === 403) ok("未登録の端末には鍵を渡していない");
  else fail(`未登録の端末が鍵を読めた、またはルールが外れています（${k.status}）`);
  const f = await fetch(base + "kx_feedback?pageSize=1", { headers: h });
  if (f.status === 403) ok("未登録の端末は報告を読めない");
  else fail(`報告の保護が外れています（${f.status}）`);
}
if (me.ok)
  await fetch("https://identitytoolkit.googleapis.com/v1/accounts:delete?key=" + API, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...REF },
    body: JSON.stringify({ idToken: me.id }),
  }).catch(() => {});

// 3. サーバー側の登録が、手元のコード一覧とそろっているか
if (db && codes.length) {
  const snap = await db.collection("kx_keys").get();
  const have = new Set(snap.docs.map((d) => d.id));
  const miss = codes.filter((c) => !have.has(c.cid)).map((c) => c.n + "番");
  if (miss.length) fail("サーバーに未反映のコード：" + miss.join("・"));
  else ok("全コードがサーバーに反映済み");
}

// 4. データを全部開けるか、毎朝の収集が止まっていないか
try {
  execFileSync("python3", ["tools/kdb.py", "open"], { encoding: "utf8", env: { ...env }, stdio: "pipe" });
  let n = 0;
  for (const f of fs.readdirSync(".plain")) {
    if (!f.endsWith(".json")) continue;
    JSON.parse(fs.readFileSync(".plain/" + f, "utf8"));
    n++;
  }
  ok("データを開けた（" + n + "ファイル）");
  const meta = JSON.parse(fs.readFileSync(".plain/meta.json", "utf8"));
  const last = Date.parse((meta.status || {}).lastRun || 0) || 0;
  const hours = (Date.now() - last) / 36e5;
  if (hours > 30) fail(`毎朝の収集が止まっています（最後は${Math.round(hours)}時間前）`);
  else ok(`最後の収集は${Math.round(hours)}時間前`);
} catch (e) {
  fail("データを開けません：" + String(e.message || e).slice(0, 200));
}

// 5. 公開されているサイトが、リポジトリの中身と同じか
try {
  const r = await fetch(SITE + "k.json?" + Date.now());
  const live = JSON.stringify(await r.json());
  const local = JSON.stringify(JSON.parse(fs.readFileSync("k.json", "utf8")));
  if (r.ok && live === local) ok("公開サイトは最新");
  else fail("公開サイトの鍵情報がリポジトリと違います（GitHub Pages の反映待ちか失敗）");
  const p = await fetch(SITE);
  if (!p.ok) fail("公開サイトが開けません（" + p.status + "）");
} catch (e) {
  fail("公開サイトに届きません：" + e.message);
}

// 管理者の端末に知らせる（問題なしで報告もなければ送らない）
const lines = [...fails.map((f) => "点検NG：" + f), ...notes];
if (lines.length && db && env.VAPID_PRIVATE_KEY) {
  try {
    const req2 = createRequire(new URL("../notify/package.json", import.meta.url));
    const webpush = req2("web-push");
    webpush.setVapidDetails("https://github.com/Buncho-kun", pick("vapidPublicKey"), String(env.VAPID_PRIVATE_KEY).replace(/[\s"'`]/g, ""));
    const subs = await db.collection("kairos_owner_subs").get();
    let sent = 0;
    for (const d of subs.docs) {
      const s = d.data();
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
          JSON.stringify({ title: fails.length ? "Kairos 点検で問題" : "Kairos", body: lines.join("\n").slice(0, 300) }),
          { TTL: 86400, urgency: fails.length ? "high" : "normal", topic: "kairos-admin" },
        );
        sent++;
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) await d.ref.delete();
      }
    }
    console.log(`管理者の端末 ${sent} 台に通知`);
  } catch (e) {
    console.log("通知を送れませんでした：" + e.message);
  }
}
for (const n of notes) console.log("・" + n);
console.log(fails.length ? `\n問題 ${fails.length} 件` : "\nすべて問題なし");
process.exit(fails.length ? 1 : 0);
