// データ更新のあと、通知を受け取る設定にした端末へ Web Push を送る。
// 設定（Secrets）がまだないとき・中身の更新がないときは、何もせずに終わる。
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import webpush from "web-push";
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

const env = process.env;
const cfg = fs.readFileSync("push-config.js", "utf8");
const pub = (cfg.match(/vapidPublicKey\s*:\s*"([^"]*)"/) || [])[1] || "";

if (!pub || !env.VAPID_PRIVATE_KEY || !env.FIREBASE_SERVICE_ACCOUNT) {
  console.log("通知の設定（Secrets）がまだないので送りません。");
  process.exit(0);
}

// 貼り付け時に混ざりやすい空白・改行・引用符を取り除き、公開鍵と対になっているか確かめる
const priv = String(env.VAPID_PRIVATE_KEY).replace(/[\s"'`]/g, "");
try {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(priv, "base64url"));
  if (ecdh.getPublicKey().toString("base64url") !== pub) {
    console.log("VAPID_PRIVATE_KEY が push-config.js の公開鍵と対になっていません。Secrets の値を貼り直してください。");
    process.exit(1);
  }
} catch {
  console.log(`VAPID_PRIVATE_KEY の形式が正しくありません（${priv.length}文字。正しくは43文字）。Secrets の値を貼り直してください。`);
  process.exit(1);
}
let account;
try {
  account = JSON.parse(String(env.FIREBASE_SERVICE_ACCOUNT).trim());
} catch {
  const s = String(env.FIREBASE_SERVICE_ACCOUNT).trim();
  const hint = [
    `${s.length}文字`,
    `先頭が { ${s.startsWith("{") ? "○" : "×"}`,
    `末尾が } ${s.endsWith("}") ? "○" : "×"}`,
    `private_key を含む ${s.includes("private_key") ? "○" : "×"}`,
    s.includes("apiKey") ? "Web用の設定（apiKey）が貼られているようです" : "",
  ]
    .filter(Boolean)
    .join("・");
  console.log(`FIREBASE_SERVICE_ACCOUNT が JSON として読めません（${hint}）。サービスアカウントの JSON ファイルの中身を { から } まで全部貼り直してください。`);
  process.exit(1);
}
if (account.type !== "service_account" || !account.private_key) {
  console.log("FIREBASE_SERVICE_ACCOUNT がサービスアカウントの鍵ではありません。「プロジェクトの設定」→「サービスアカウント」→「新しい秘密鍵の生成」で出るファイルの中身を貼ってください。");
  process.exit(1);
}

const git = (...a) => execFileSync("git", a, { encoding: "utf8" }).trim();
const IGNORE = new Set(["data/meta.enc", "data/codes.enc", "data/collector.md.enc"]);

function todayJST() {
  const d = new Date(Date.now() + 9 * 3600e3);
  return d.getUTCMonth() + 1 + "/" + d.getUTCDate();
}

function makeBody() {
  if (env.EVENT === "workflow_dispatch") return env.MANUAL_BODY || "テスト通知です";
  let files;
  try {
    files = git("diff", "--name-only", env.BEFORE, "HEAD", "--", "data");
  } catch {
    files = git("diff", "--name-only", "HEAD~1", "HEAD", "--", "data");
  }
  const changed = files.split("\n").filter((f) => f && !IGNORE.has(f));
  if (!changed.length) return null;
  const msg = git("log", "-1", "--format=%s");
  if (/新着なし/.test(msg)) return null;
  const m = msg.match(/新着\s*(\d+)\s*件/);
  return todayJST() + (m ? " 新着" + m[1] + "件" : " 内容が更新されました");
}

const body = makeBody();
if (!body) {
  console.log("中身の更新がないので送りません。");
  process.exit(0);
}

webpush.setVapidDetails("https://github.com/Buncho-kun", pub, priv);
initializeApp({ credential: cert(account) });
const db = getFirestore();
const snap = await db.collection("kairos_subs").get();
const payload = JSON.stringify({ title: "Kairos", body });

let ok = 0;
let gone = 0;
let ng = 0;
await Promise.all(
  snap.docs.map(async (doc) => {
    const s = doc.data();
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        payload,
        { TTL: 86400, urgency: "normal", topic: "kairos" },
      );
      ok++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await doc.ref.delete();
        gone++;
      } else {
        ng++;
        console.log("送信失敗:", e.statusCode || "", String(e.body || e.message || "").slice(0, 200));
      }
    }
  }),
);
console.log(`本文「${body}」：送信 ${ok} 件／解除済みを削除 ${gone} 件／失敗 ${ng} 件`);
