#!/usr/bin/env python3
"""Kairos data tool: encrypted JSON collections in data/*.enc.

The passphrase is read from the environment variable KAIROS_PASS.
Plain files live in .plain/ (ignored by git) and are never committed.

  python3 tools/kdb.py open                 decrypt data/*.enc into .plain/
  python3 tools/kdb.py seal                 encrypt changed .plain/*.json back into data/
  python3 tools/kdb.py ids COLL             list document ids
  python3 tools/kdb.py list COLL [F1,F2..]  print id and the given top-level fields
  python3 tools/kdb.py get COLL ID          print one document
  python3 tools/kdb.py put COLL ID [--replace] < doc.json
                                            merge (default) or replace one document
  python3 tools/kdb.py del COLL ID          delete one document
  python3 tools/kdb.py enc SRC DST          encrypt any JSON file (e.g. static data)
  python3 tools/kdb.py dec SRC              decrypt any .enc file to stdout
  python3 tools/kdb.py init                 create k.json (only once)

Access codes (one per person). KAIROS_PASS must be the owner passphrase:
  python3 tools/kdb.py codes                list codes (number, label, code)
  python3 tools/kdb.py addcode LABEL        issue a new code for LABEL
  python3 tools/kdb.py rmcode N             revoke code N and re-encrypt everything
  python3 tools/kdb.py rotate               re-encrypt everything with a new data key
  python3 tools/kdb.py resetcode N          clear the devices registered for code N
  python3 tools/kdb.py label N TEXT         set the private label of code N
  python3 tools/kdb.py slots                JSON used by the device-limit sync job

Each code works on at most 3 devices. The keys for codes live in Firestore
(kx_keys / kx_slots), synced by .github/workflows/codes.yml; only the owner
entry is kept in k.json.

Collections: items, branches, journals, manuals, watch, tools, meta.
"""
import base64, gzip, hashlib, json, os, secrets, sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
PLAIN = os.path.join(ROOT, ".plain")
KFILE = os.path.join(ROOT, "k.json")
COLLS = ["items", "branches", "journals", "manuals", "watch", "tools", "meta"]
MAGIC = b"KX1"
CODES = os.path.join(DATA, "codes.enc")
ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ITER = 310000


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def passphrase():
    p = os.environ.get("KAIROS_PASS")
    if not p:
        die("KAIROS_PASS is not set")
    return p


def derive(meta, secret=None):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(meta["salt"]),
        iterations=meta["iter"],
    )
    return kdf.derive((secret if secret is not None else passphrase()).encode("utf-8"))


def norm_code(c):
    return "".join(ch for ch in c.upper() if ch.isalnum())


def wrap(kek, dk):
    iv = os.urandom(12)
    return base64.b64encode(iv + AESGCM(kek).encrypt(iv, dk, None)).decode()


def unwrap(kek, w):
    b = base64.b64decode(w)
    return AESGCM(kek).decrypt(b[:12], b[12:], None)


def read_meta():
    if not os.path.exists(KFILE):
        die("k.json not found; run init")
    return json.load(open(KFILE))


_key = None
_kek = None


def kek():
    global _kek
    if _kek is None:
        _kek = derive(read_meta())
    return _kek


def key():
    global _key
    if _key is None:
        meta = read_meta()
        global _kek
        cands = [kek()]
        if norm_code(passphrase()) != passphrase():
            cands.append(derive(meta, norm_code(passphrase())))
        for k in cands:
            for w in meta["wraps"]:
                try:
                    dk = unwrap(k, w["w"])
                    dec_bytes(base64.b64decode(meta["check"]), dk)
                    _key, _kek = dk, k
                    break
                except Exception:
                    continue
            if _key is not None:
                break
        if _key is None:
            die("wrong passphrase")
    return _key


def owner_codes():
    key()
    if not os.path.exists(CODES):
        return []
    try:
        return json.loads(dec_bytes(open(CODES, "rb").read(), kek()))
    except Exception:
        die("the code list opens only with the owner passphrase")


def save_codes(lst):
    open(CODES, "wb").write(enc_bytes(dumps(lst), kek()))


def write_meta(meta):
    json.dump(meta, open(KFILE, "w"), indent=1)


def enc_bytes(raw, k=None):
    iv = os.urandom(12)
    return MAGIC + iv + AESGCM(k or key()).encrypt(iv, gzip.compress(raw, 9, mtime=0), None)


def dec_bytes(blob, k=None):
    if blob[:3] != MAGIC:
        raise ValueError("not a Kairos file")
    return gzip.decompress(AESGCM(k or key()).decrypt(blob[3:15], blob[15:], None))


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def plain_path(c):
    return os.path.join(PLAIN, c + ".json")


def load(c):
    p = plain_path(c)
    if not os.path.exists(p):
        die(c + ": not opened (run open first)")
    return json.load(open(p, encoding="utf-8"))


def save(c, obj):
    with open(plain_path(c), "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)


def cmd_init():
    if os.path.exists(KFILE):
        die("k.json already exists")
    meta = {"v": 2, "iter": ITER, "salt": base64.b64encode(os.urandom(16)).decode()}
    dk = os.urandom(32)
    meta["check"] = base64.b64encode(enc_bytes(b'"ok"', dk)).decode()
    meta["wraps"] = [{"n": 0, "w": wrap(derive(meta), dk)}]
    write_meta(meta)
    os.makedirs(DATA, exist_ok=True)
    global _key
    _key = dk
    save_codes([{"n": 0, "label": "owner", "code": None}])
    print("k.json created")


def new_code():
    raw = "".join(secrets.choice(ALPH) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def cmd_codes():
    for c in owner_codes():
        print("%3d  %-20s %s" % (c["n"], c.get("label", ""), c.get("code") or "(owner passphrase)"))


def cmd_addcode(label="", count="1"):
    lst = owner_codes()
    meta = read_meta()
    for _ in range(int(count)):
        n = max([c["n"] for c in lst] + [meta.get("next", 1) - 1]) + 1
        meta["next"] = n + 1
        code = new_code()
        lst.append({"n": n, "label": label, "code": code,
                    "w": wrap(derive(meta, norm_code(code)), key())})
        print("%d  %s  %s" % (n, label, code))
    save_codes(lst)
    write_meta(meta)


def code_id(code):
    return hashlib.sha256(("kairos-code:" + norm_code(code)).encode()).hexdigest()[:40]


def cmd_resetcode(n):
    import datetime
    n = int(n)
    lst = owner_codes()
    hit = [c for c in lst if c["n"] == n and n != 0]
    if not hit:
        die("no such code: %d" % n)
    hit[0]["resetAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_codes(lst)
    print("reset requested for", n)


def cmd_label(n, label):
    lst = owner_codes()
    for c in lst:
        if c["n"] == int(n):
            c["label"] = label
    save_codes(lst)


def cmd_slots():
    """JSON for the device-limit sync job: one entry per access code."""
    out = []
    for c in owner_codes():
        if c["n"] == 0 or not c.get("w"):
            continue
        out.append({"n": c["n"], "cid": code_id(c["code"]), "w": c["w"], "resetAt": c.get("resetAt", "")})
    print(json.dumps(out))


def all_enc_files():
    return sorted(
        os.path.join(DATA, f) for f in os.listdir(DATA) if f.endswith(".enc") and f != "codes.enc"
    )


def cmd_rotate():
    lst = owner_codes()
    old = key()
    meta = read_meta()
    dk = os.urandom(32)
    for f in all_enc_files():
        raw = dec_bytes(open(f, "rb").read(), old)
        open(f, "wb").write(enc_bytes(raw, dk))
    meta["check"] = base64.b64encode(enc_bytes(b'"ok"', dk)).decode()
    meta["wraps"] = [{"n": 0, "w": wrap(kek(), dk)}]
    for c in lst:
        if c["n"] != 0:
            c["w"] = wrap(derive(meta, norm_code(c["code"])), dk)
    write_meta(meta)
    save_codes(lst)
    global _key
    _key = dk
    print("rotated: %d files, %d codes" % (len(all_enc_files()), len(lst)))


def cmd_rmcode(n):
    n = int(n)
    if n == 0:
        die("the owner entry cannot be removed")
    lst = [c for c in owner_codes() if c["n"] != n]
    save_codes(lst)
    cmd_rotate()
    print("revoked", n)


def cmd_open():
    os.makedirs(PLAIN, exist_ok=True)
    hashes_ = {}
    for c in COLLS:
        src = os.path.join(DATA, c + ".enc")
        obj = json.loads(dec_bytes(open(src, "rb").read())) if os.path.exists(src) else {}
        save(c, obj)
        hashes_[c] = hashlib.sha256(dumps(obj)).hexdigest()
    json.dump(hashes_, open(os.path.join(PLAIN, ".hash"), "w"))
    print("opened:", ", ".join("%s(%d)" % (c, len(load(c))) for c in COLLS))


def cmd_seal():
    hp = os.path.join(PLAIN, ".hash")
    old = json.load(open(hp)) if os.path.exists(hp) else {}
    changed = []
    for c in COLLS:
        if not os.path.exists(plain_path(c)):
            continue
        raw = dumps(load(c))
        h = hashlib.sha256(raw).hexdigest()
        if old.get(c) == h and os.path.exists(os.path.join(DATA, c + ".enc")):
            continue
        os.makedirs(DATA, exist_ok=True)
        open(os.path.join(DATA, c + ".enc"), "wb").write(enc_bytes(raw))
        old[c] = h
        changed.append(c)
    json.dump(old, open(hp, "w"))
    print("sealed:", ", ".join(changed) if changed else "(no changes)")


def cmd_ids(c):
    print("\n".join(sorted(load(c).keys())))


def cmd_list(c, fields=""):
    fs = [f for f in fields.split(",") if f]
    for i, d in sorted(load(c).items()):
        print(json.dumps({"id": i, **{f: d.get(f) for f in fs}}, ensure_ascii=False))


def cmd_get(c, i):
    d = load(c).get(i)
    if d is None:
        die("not found: %s/%s" % (c, i))
    print(json.dumps(d, ensure_ascii=False, indent=1))


def cmd_put(c, i, *flags):
    new = json.load(sys.stdin)
    if not isinstance(new, dict):
        die("document must be a JSON object")
    obj = load(c)
    if "--replace" in flags or i not in obj:
        obj[i] = new
    else:
        obj[i].update(new)
    save(c, obj)
    print("put %s/%s" % (c, i))


def cmd_del(c, i):
    obj = load(c)
    obj.pop(i, None)
    save(c, obj)
    print("deleted %s/%s" % (c, i))


def cmd_enc(src, dst):
    open(dst, "wb").write(enc_bytes(open(src, "rb").read()))
    print("encrypted", src, "->", dst)


def cmd_dec(src):
    sys.stdout.buffer.write(dec_bytes(open(src, "rb").read()))


def main(argv):
    if not argv:
        die(__doc__)
    cmd, args = argv[0], argv[1:]
    fn = {
        "init": cmd_init, "open": cmd_open, "seal": cmd_seal, "ids": cmd_ids,
        "list": cmd_list, "get": cmd_get, "put": cmd_put, "del": cmd_del,
        "enc": cmd_enc, "dec": cmd_dec, "codes": cmd_codes, "addcode": cmd_addcode,
        "rmcode": cmd_rmcode, "rotate": cmd_rotate, "resetcode": cmd_resetcode,
        "label": cmd_label, "slots": cmd_slots,
    }.get(cmd)
    if not fn:
        die(__doc__)
    if args and cmd in ("ids", "list", "get", "put", "del") and args[0] not in COLLS:
        die("unknown collection: " + args[0])
    fn(*args)


if __name__ == "__main__":
    main(sys.argv[1:])
