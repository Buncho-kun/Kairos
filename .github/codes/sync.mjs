// アクセスコードの鍵と登録端末の枠を Firestore に反映し、セキュリティルールを更新する。
// 必要な Secrets：KAIROS_PASS（管理者の合言葉）、FIREBASE_SERVICE_ACCOUNT
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore, Timestamp } from "firebase-admin/firestore";
import { getSecurityRules } from "firebase-admin/security-rules";

const env = process.env;
if (!env.KAIROS_PASS || !env.FIREBASE_SERVICE_ACCOUNT) {
  console.log("Secrets（KAIROS_PASS と FIREBASE_SERVICE_ACCOUNT）がそろっていないので何もしません。");
  process.exit(1);
}
const account = JSON.parse(String(env.FIREBASE_SERVICE_ACCOUNT).trim());
const app = initializeApp({ credential: cert(account) });
const db = getFirestore(app);

// 1. セキュリティルール
await getSecurityRules(app).releaseFirestoreRulesetFromSource(fs.readFileSync("firestore.rules", "utf8"));
console.log("ルールを更新しました");

// 2. 匿名ログインを有効にする（端末ごとの識別に使う）
try {
  const tok = await app.options.credential.getAccessToken();
  const r = await fetch(
    `https://identitytoolkit.googleapis.com/admin/v2/projects/${account.project_id}/config?updateMask=signIn.anonymous.enabled`,
    {
      method: "PATCH",
      headers: { Authorization: "Bearer " + tok.access_token, "Content-Type": "application/json" },
      body: JSON.stringify({ signIn: { anonymous: { enabled: true } } }),
    },
  );
  console.log(r.ok ? "匿名ログインを有効にしました" : "匿名ログインの設定に失敗：" + r.status + " " + (await r.text()).slice(0, 300));
} catch (e) {
  console.log("匿名ログインの設定に失敗：" + e.message);
}

// 3. コードごとの鍵と枠
const codes = JSON.parse(
  execFileSync("python3", ["tools/kdb.py", "slots"], { encoding: "utf8", env: { ...env } }),
);
const keep = new Set(codes.map((c) => c.cid));
for (const c of codes) {
  await db.collection("kx_keys").doc(c.cid).set({ w: c.w });
  const ref = db.collection("kx_slots").doc(c.cid);
  const cur = await ref.get();
  if (!cur.exists) {
    await ref.set({ devices: {}, swapAt: Timestamp.fromMillis(0), resetAt: c.resetAt || "" });
  } else if ((c.resetAt || "") > (cur.get("resetAt") || "")) {
    await ref.update({ devices: {}, resetAt: c.resetAt });
    console.log(`${c.n}番の登録端末をリセットしました`);
  }
}
for (const name of ["kx_keys", "kx_slots"]) {
  const snap = await db.collection(name).get();
  for (const d of snap.docs) if (!keep.has(d.id)) await d.ref.delete();
}
const slots = await db.collection("kx_slots").get();
console.log("コード " + codes.length + " 件を反映");
for (const c of codes) {
  const d = slots.docs.find((x) => x.id === c.cid);
  console.log(`  ${c.n}番：${d ? Object.keys(d.get("devices") || {}).length : 0}台`);
}
