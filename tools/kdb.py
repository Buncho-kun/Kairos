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

Collections: items, branches, journals, manuals, watch, tools, meta.
"""
import base64, gzip, hashlib, json, os, sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
PLAIN = os.path.join(ROOT, ".plain")
KFILE = os.path.join(ROOT, "k.json")
COLLS = ["items", "branches", "journals", "manuals", "watch", "tools", "meta"]
MAGIC = b"KX1"
ITER = 310000


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def passphrase():
    p = os.environ.get("KAIROS_PASS")
    if not p:
        die("KAIROS_PASS is not set")
    return p


def derive(meta):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(meta["salt"]),
        iterations=meta["iter"],
    )
    return kdf.derive(passphrase().encode("utf-8"))


_key = None


def key():
    global _key
    if _key is None:
        if not os.path.exists(KFILE):
            die("k.json not found; run init")
        meta = json.load(open(KFILE))
        k = derive(meta)
        try:
            dec_bytes(base64.b64decode(meta["check"]), k)
        except Exception:
            die("wrong passphrase")
        _key = k
    return _key


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
    meta = {"v": 1, "iter": ITER, "salt": base64.b64encode(os.urandom(16)).decode()}
    k = derive(meta)
    meta["check"] = base64.b64encode(enc_bytes(b'"ok"', k)).decode()
    json.dump(meta, open(KFILE, "w"), indent=1)
    print("k.json created")


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
        "enc": cmd_enc, "dec": cmd_dec,
    }.get(cmd)
    if not fn:
        die(__doc__)
    if args and cmd in ("ids", "list", "get", "put", "del") and args[0] not in COLLS:
        die("unknown collection: " + args[0])
    fn(*args)


if __name__ == "__main__":
    main(sys.argv[1:])
