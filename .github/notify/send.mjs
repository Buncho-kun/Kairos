// データ更新のあと、通知を受け取る設定にした端末へ Web Push を送る。
// 設定（Secrets）がまだないとき・中身の更新がないときは、何もせずに終わる。
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

webpush.setVapidDetails("https://github.com/Buncho-kun", pub, env.VAPID_PRIVATE_KEY);
initializeApp({ credential: cert(JSON.parse(env.FIREBASE_SERVICE_ACCOUNT)) });
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
