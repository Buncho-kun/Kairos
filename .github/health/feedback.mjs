// 新しく届いた「誤り・要望の報告」を、管理者の端末にだけ通知する。
// 通知済みの報告には印（nt）を付け、同じ報告を二度知らせない。
import fs from "node:fs";
import { createRequire } from "node:module";
const req1 = createRequire(new URL("../codes/package.json", import.meta.url));
const req2 = createRequire(new URL("../notify/package.json", import.meta.url));
const { initializeApp, cert } = req1("firebase-admin/app");
const { getFirestore } = req1("firebase-admin/firestore");
const webpush = req2("web-push");

const env = process.env;
if (!env.FIREBASE_SERVICE_ACCOUNT || !env.VAPID_PRIVATE_KEY) {
  console.log("Secrets がそろっていないので何もしません。");
  process.exit(0);
}
const cfg = fs.readFileSync("push-config.js", "utf8");
const pub = (cfg.match(/vapidPublicKey\s*:\s*"([^"]*)"/) || [])[1] || "";
initializeApp({ credential: cert(JSON.parse(String(env.FIREBASE_SERVICE_ACCOUNT).trim())) });
const db = getFirestore();

const all = await db.collection("kx_feedback").get();
const fresh = all.docs.filter((d) => !d.get("nt"));
if (!fresh.length) {
  console.log("新しい報告はありません。");
  process.exit(0);
}
webpush.setVapidDetails("https://github.com/Buncho-kun", pub, String(env.VAPID_PRIVATE_KEY).replace(/[\s"'`]/g, ""));
const subs = await db.collection("kairos_owner_subs").get();
let sent = 0;
for (const d of subs.docs) {
  const s = d.data();
  try {
    await webpush.sendNotification(
      { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
      JSON.stringify({ title: "Kairos", body: `誤り・要望の報告が${fresh.length}件届きました（設定→管理）` }),
      { TTL: 86400, urgency: "normal", topic: "kairos-report" },
    );
    sent++;
  } catch (e) {
    if (e.statusCode === 404 || e.statusCode === 410) await d.ref.delete();
    else console.log("送信失敗:", e.statusCode || "", String(e.body || e.message || "").slice(0, 200));
  }
}
console.log(`新しい報告 ${fresh.length} 件／管理者の端末 ${sent} 台に通知（登録 ${subs.size} 台）`);
// 1台にも届かなかったときは印を付けず、次回もう一度試す
if (sent) for (const d of fresh) await d.ref.update({ nt: true });
