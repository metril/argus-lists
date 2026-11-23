#!/usr/bin/env python3
"""Generate roots/roots.json: Mozilla roots with the Websites trust bit, from CCADB cross-checked
against NSS certdata.txt (set intersection by SHA-256). See SOURCES.md.

    python generator/rootstore.py generate [--out roots/roots.json] [--max-diff 3]
    python generator/rootstore.py classify OLD NEW   # prints auto|review|none, writes PR body to --body
"""
import argparse, base64, binascii, csv, datetime as dt, hashlib, io, json, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import ROOT, http_get  # noqa: E402

CCADB_URL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"
# Mozilla moved mozilla-central to git (mozilla-firefox/firefox); hg.mozilla.org no longer serves the file.
CERTDATA_URL = ("https://raw.githubusercontent.com/mozilla-firefox/firefox/main/"
                "security/nss/lib/ckfw/builtins/certdata.txt")
CHROME_URL = ("https://chromium.googlesource.com/chromium/src/+/main/"
              "net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT")  # base64
CT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
CT_LOG_LIST_SIG_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.sig"
# Google's published CT log list public key (https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem),
# pinned here; log_list.sig is RSA PKCS#1 v1.5 / SHA-256 over the raw log_list.json bytes.
CT_LOG_LIST_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----"""
MIN_USABLE_LOGS = 3
LOG_STATES = ("usable", "qualified", "readonly", "retired")
OUT = ROOT / "roots" / "roots.json"
MIN_ROOTS = 100        # floor for Mozilla/CCADB/certdata before the Chrome restriction
MIN_FINAL_ROOTS = 80   # floor for the published (Chrome-restricted) set
DEFAULT_MAX_DIFF = 3


class RootError(Exception):
    pass


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# ---- CCADB ---------------------------------------------------------------------------------

def parse_ccadb(csv_text):
    """{sha256: {"der", "distrust_after", "name"}} for rows with the Websites trust bit."""
    out = {}
    for row in csv.DictReader(io.StringIO(csv_text)):
        bits = {b.strip() for b in row["Trust Bits"].split(";")}
        if "Websites" not in bits:
            continue
        pem = row["PEM Info"].strip().strip("'\"")
        body = "".join(l for l in pem.splitlines() if "-----" not in l)
        der = base64.b64decode(body)
        fp = row["SHA-256 Fingerprint"].strip().lower()
        if sha256_hex(der) != fp:
            raise RootError(f"CCADB PEM does not match its fingerprint: {row['Common Name or Certificate Name']}")
        if fp in out:
            raise RootError(f"duplicate CCADB fingerprint {fp}")
        out[fp] = {"der": der, "distrust_after": parse_distrust(row["Distrust for TLS After Date"]),
                   "name": row["Common Name or Certificate Name"]}
    return out


def parse_distrust(s):
    s = s.strip()
    if not s:
        return None
    m = re.fullmatch(r"(\d{4})[.\-/](\d{2})[.\-/](\d{2})", s)
    if not m:
        raise RootError(f"unparseable distrust date {s!r}")
    return f"{m[1]}-{m[2]}-{m[3]}T00:00:00Z"


# ---- NSS certdata.txt ----------------------------------------------------------------------

def _octal(lines):
    return bytes(int(x, 8) for l in lines for x in re.findall(r"\\(\d{3})", l))


def parse_certdata(text):
    """SHA-256 set of certificates NSS trusts as delegators for server auth."""
    objs, cur, lines, i = [], None, text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith("CKA_CLASS "):
            cur = {"class": line.split()[-1]}
            objs.append(cur)
        elif cur is not None and line.startswith("CKA_"):
            parts = line.split(None, 2)
            if parts[1] == "MULTILINE_OCTAL":
                buf = []
                while lines[i].strip() != "END":
                    buf.append(lines[i])
                    i += 1
                i += 1
                cur[parts[0]] = _octal(buf)
            else:
                cur[parts[0]] = parts[2] if len(parts) > 2 else ""
    sha1_to_sha256 = {}
    for o in objs:
        if o["class"] == "CKO_CERTIFICATE" and "CKA_VALUE" in o:
            sha1_to_sha256[hashlib.sha1(o["CKA_VALUE"]).hexdigest()] = sha256_hex(o["CKA_VALUE"])
    trusted = set()
    for o in objs:
        if o["class"] == "CKO_NSS_TRUST" and o.get("CKA_TRUST_SERVER_AUTH") == "CKT_NSS_TRUSTED_DELEGATOR":
            h = o["CKA_CERT_SHA1_HASH"].hex()
            if h not in sha1_to_sha256:
                raise RootError(f"certdata trust object without certificate: {h}")
            trusted.add(sha1_to_sha256[h])
    return trusted


# ---- build ---------------------------------------------------------------------------------

def subject_of(der):
    from cryptography import x509
    return x509.load_der_x509_certificate(der).subject.rfc4514_string()


# ---- Chrome Root Store ---------------------------------------------------------------------

def rfc3339(sec):
    return dt.datetime.fromtimestamp(int(sec), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_chrome(text):
    """{sha256: {"sct_not_after": RFC3339|None, "permitted_dns_names": [..]}} from root_store.textproto
    (trust_anchors only; min_version/max_version_exclusive are ignored; the strictest value wins when
    several constraints are present). An sct_all_after constraint cannot be represented: fail loudly."""
    out, cur, depth = {}, None, 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if depth == 0:
            if re.match(r"trust_anchors\s*:?\s*\{", line):
                cur = {"sha256": None, "sct": [], "dns": set()}
            elif "{" in line:
                cur = None
        elif cur is not None:
            m = re.match(r'(\w+)\s*:\s*"?([^"]*)"?$', line)
            if m:
                k, v = m.groups()
                if k == "sha256_hex" and depth == 1:
                    cur["sha256"] = v.lower()
                elif k == "sct_not_after_sec":
                    cur["sct"].append(int(v))
                elif k == "sct_all_after_sec":
                    raise RootError(f"Chrome sct_all_after constraint on {cur['sha256']} is not representable; extend the schema")
                elif k == "permitted_dns_names":
                    cur["dns"].add(v.lower())
        depth += line.count("{") - line.count("}")
        if depth == 0 and cur is not None and "}" in line:
            if not cur["sha256"] or not re.fullmatch(r"[0-9a-f]{64}", cur["sha256"]):
                raise RootError("Chrome trust anchor without a valid sha256_hex")
            if cur["sha256"] in out:
                raise RootError(f"duplicate Chrome trust anchor {cur['sha256']}")
            out[cur["sha256"]] = {"sct_not_after": rfc3339(min(cur["sct"])) if cur["sct"] else None,
                                  "permitted_dns_names": sorted(cur["dns"])}
            cur = None
    if depth != 0 or not out:
        raise RootError("could not parse the Chrome Root Store")
    return out


# ---- CT log list ---------------------------------------------------------------------------

def verify_log_list(data, sig, pubkey_pem=CT_LOG_LIST_PUBKEY):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_public_key(pubkey_pem.encode())
    try:
        key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise RootError("CT log list signature does not verify against the pinned key")


def parse_log_list(data):
    """Logs that are usable, qualified, readonly or retired, sorted by log_id."""
    logs = []
    for op in json.loads(data)["operators"]:
        for l in op["logs"]:
            state = next((k for k in LOG_STATES if k in l["state"]), None)
            if state is None:
                continue
            key = base64.b64decode(l["key"], validate=True)
            if base64.b64encode(hashlib.sha256(key).digest()).decode() != l["log_id"]:
                raise RootError(f"CT log_id does not match its key: {l.get('name')}")
            ti = l.get("temporal_interval")
            logs.append({"log_id": l["log_id"], "key": l["key"], "operator": op["name"], "state": state,
                         "state_since": l["state"][state]["timestamp"],
                         "temporal_interval": {"start": ti["start_inclusive"], "end": ti["end_exclusive"]} if ti else None})
    logs.sort(key=lambda x: x["log_id"])
    if sum(1 for l in logs if l["state"] == "usable") < MIN_USABLE_LOGS:
        raise RootError(f"fewer than {MIN_USABLE_LOGS} usable CT logs")
    return logs


def build(ccadb, nss, chrome, max_diff=DEFAULT_MAX_DIFF):
    """(roots, dropped_by_chrome). Mozilla/CCADB intersection, minus roots absent from the Chrome Root
    Store; Chrome-only roots are never added. Raise RootError when CCADB and certdata disagree by more
    than max_diff roots."""
    only_ccadb, only_nss = sorted(set(ccadb) - nss), sorted(nss - set(ccadb))
    for h in only_ccadb:
        print(f"disagreement: only in CCADB: {h} {ccadb[h]['name']}", file=sys.stderr)
    for h in only_nss:
        print(f"disagreement: only in certdata: {h}", file=sys.stderr)
    if len(only_ccadb) + len(only_nss) > max_diff:
        raise RootError(f"CCADB and certdata disagree on {len(only_ccadb) + len(only_nss)} roots (max {max_diff})")
    both = sorted(set(ccadb) & nss)
    dropped = [h for h in both if h not in chrome]
    for h in dropped:
        print(f"dropped (absent from the Chrome Root Store): {h} {ccadb[h]['name']}", file=sys.stderr)
    roots = [{"sha256": h, "subject": subject_of(ccadb[h]["der"]),
              "der": base64.b64encode(ccadb[h]["der"]).decode(), "distrust_after": ccadb[h]["distrust_after"],
              "sct_not_after": chrome[h]["sct_not_after"], "permitted_dns_names": chrome[h]["permitted_dns_names"]}
             for h in both if h in chrome]
    return roots, dropped


def next_serial(prev, now):
    s = int(now.strftime("%Y%m%d")) * 100
    while s <= prev:
        s += 1
    if s % 100 > 99 or s // 100 != int(now.strftime("%Y%m%d")):
        raise RootError("more than 100 serials in one day")
    return s


def render(doc):
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def generate(out=OUT, max_diff=DEFAULT_MAX_DIFF, now=None, ccadb_text=None, certdata_text=None,
             chrome_text=None, loglist=None, loglist_sig=None, pubkey_pem=CT_LOG_LIST_PUBKEY):
    now = now or dt.datetime.now(dt.timezone.utc)
    if ccadb_text is None:
        ccadb_text = http_get(CCADB_URL).decode("utf-8")
    if certdata_text is None:
        certdata_text = http_get(CERTDATA_URL).decode("utf-8")
    if chrome_text is None:
        chrome_text = base64.b64decode(http_get(CHROME_URL)).decode("utf-8")
    if loglist is None:
        loglist, loglist_sig = http_get(CT_LOG_LIST_URL), http_get(CT_LOG_LIST_SIG_URL)
    verify_log_list(loglist, loglist_sig, pubkey_pem)
    ct_logs = parse_log_list(loglist)
    ccadb, nss = parse_ccadb(ccadb_text), parse_certdata(certdata_text)
    if len(set(ccadb) & nss) < MIN_ROOTS:
        raise RootError(f"only {len(set(ccadb) & nss)} Mozilla roots (floor {MIN_ROOTS})")
    roots, dropped = build(ccadb, nss, parse_chrome(chrome_text), max_diff)
    print(f"{len(dropped)} Mozilla roots dropped for being absent from the Chrome Root Store")
    if len(roots) < MIN_FINAL_ROOTS:
        raise RootError(f"only {len(roots)} roots (floor {MIN_FINAL_ROOTS})")
    old = json.loads(out.read_text()) if out.exists() else None
    if old and old["roots"] == roots and old.get("ct_logs") == ct_logs:
        print("roots unchanged")
        return False
    doc = {"schema": 1, "serial": next_serial(old["serial"] if old else 0, now),
           "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sources": {"ccadb_sha256": sha256_hex(ccadb_text.encode()),
                       "certdata_rev": sha256_hex(certdata_text.encode())},
           "ct_logs": ct_logs, "roots": roots}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(doc))
    print(f"wrote {out}: serial {doc['serial']}, {len(roots)} roots, {len(ct_logs)} CT logs")
    return True


# ---- approval policy -----------------------------------------------------------------------

STATE_RANK = {"usable": 0, "qualified": 0, "readonly": 1, "retired": 2}


def _later(new, old):
    """True if the (RFC3339 UTC) date new is later than old; None (no date) counts as latest."""
    return old is not None and (new is None or new > old)


def _root_loosened(a, b):
    if a["distrust_after"] != b["distrust_after"] and _later(b["distrust_after"], a["distrust_after"]):
        return True
    if _later(b.get("sct_not_after"), a.get("sct_not_after")):
        return True
    da, db = a.get("permitted_dns_names") or [], b.get("permitted_dns_names") or []
    # unconstrained (empty) is the loosest; a constrained set may only shrink
    return bool(da) and (not db or not set(db) <= set(da))


def _log_loosened(a, b):
    if a["key"] != b["key"] or a["temporal_interval"] != b["temporal_interval"] or a["operator"] != b["operator"]:
        return True
    if STATE_RANK[b["state"]] < STATE_RANK[a["state"]]:
        return True
    return a["state"] == b["state"] == "retired" and b["state_since"] > a["state_since"]


def classify(old, new):
    """('none'|'auto'|'review', added_roots). Review: anything that loosens trust (an added root or log,
    a removed or later distrust/SCT date, a widened DNS constraint); stricter changes are 'auto'."""
    o = {r["sha256"]: r for r in old["roots"]}
    n = {r["sha256"]: r for r in new["roots"]}
    added = [n[h] for h in sorted(set(n) - set(o))]
    review = bool(added)
    changed = bool(set(o) - set(n))
    for h in set(o) & set(n):
        if o[h] != n[h]:
            changed = True
            review = review or _root_loosened(o[h], n[h])
    ol = {l["log_id"]: l for l in old.get("ct_logs", [])}
    nl = {l["log_id"]: l for l in new.get("ct_logs", [])}
    if set(nl) - set(ol):
        review = True
    for h in set(ol) & set(nl):
        if ol[h] != nl[h]:
            changed = True
            review = review or _log_loosened(ol[h], nl[h])
    changed = changed or set(ol) - set(nl) or bool(set(nl) - set(ol))
    return ("review" if review else "auto" if changed else "none"), added


def pr_body(added):
    lines = ["Root store changes that loosen trust, awaiting review (never auto-merged). Listed below: added roots; "
             "see the diff for CT log and constraint changes.", "",
             f"Source report: {CCADB_URL}", "", "| Subject | SHA-256 | Links |", "|---|---|---|"]
    for r in added:
        subj = r["subject"].replace("|", "\\|")
        lines.append(f"| {subj} | `{r['sha256']}` | [CCADB report]({CCADB_URL}) / [crt.sh](https://crt.sh/?q={r['sha256']}) |")
    return "\n".join(lines) + "\n"


# ---- validation (used by scripts/validate_roots.py) ----------------------------------------

def validate_logs(logs):
    """Structure of ct_logs (the signature itself is verified when the list is fetched)."""
    from cryptography.hazmat.primitives import serialization
    if not isinstance(logs, list):
        raise RootError("ct_logs must be a list")
    ids = [l.get("log_id") for l in logs]
    if ids != sorted(set(ids)):
        raise RootError("ct_logs not sorted by log_id or duplicated")
    for l in logs:
        if set(l) != {"log_id", "key", "operator", "state", "state_since", "temporal_interval"}:
            raise RootError(f"bad ct_log keys: {l.get('log_id')}")
        if l["state"] not in LOG_STATES:
            raise RootError(f"bad ct_log state: {l['log_id']}")
        try:
            key = base64.b64decode(l["key"], validate=True)
            serialization.load_der_public_key(key)
        except (binascii.Error, ValueError):
            raise RootError(f"bad ct_log key: {l['log_id']}")
        if base64.b64encode(hashlib.sha256(key).digest()).decode() != l["log_id"]:
            raise RootError(f"ct_log log_id does not match its key: {l['log_id']}")
        ti = l["temporal_interval"]
        if ti is not None and (not isinstance(ti, dict) or set(ti) != {"start", "end"}):
            raise RootError(f"bad ct_log temporal_interval: {l['log_id']}")
    if sum(1 for l in logs if l["state"] == "usable") < MIN_USABLE_LOGS:
        raise RootError(f"fewer than {MIN_USABLE_LOGS} usable CT logs")


def validate(doc, prev_serial=None, min_roots=MIN_FINAL_ROOTS):
    """Raise RootError on any problem."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519, ed448
    if not isinstance(doc, dict) or set(doc) != {"schema", "serial", "generated_at", "sources", "ct_logs", "roots"}:
        raise RootError("bad top-level keys")
    if doc["schema"] != 1:
        raise RootError("schema must be 1")
    if type(doc["serial"]) is not int or not 0 < doc["serial"] < 2**64:
        raise RootError("serial must be a u64")
    try:
        dt.datetime.fromisoformat(doc["generated_at"].replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise RootError("generated_at is not RFC3339")
    src = doc["sources"]
    if not isinstance(src, dict) or set(src) != {"ccadb_sha256", "certdata_rev"} or not all(isinstance(v, str) and v for v in src.values()):
        raise RootError("bad sources")
    if prev_serial is not None and doc["serial"] <= prev_serial:
        raise RootError(f"serial {doc['serial']} is not greater than published {prev_serial}")
    validate_logs(doc["ct_logs"])
    roots = doc["roots"]
    if len(roots) < min_roots:
        raise RootError(f"{len(roots)} roots, below the floor of {min_roots}")
    if [r.get("sha256") for r in roots] != sorted({r.get("sha256") for r in roots}):
        raise RootError("roots not sorted by sha256 or duplicated")
    for r in roots:
        if set(r) != {"sha256", "subject", "der", "distrust_after", "sct_not_after", "permitted_dns_names"}:
            raise RootError(f"bad root keys: {r.get('sha256')}")
        der = base64.b64decode(r["der"], validate=True)
        if sha256_hex(der) != r["sha256"]:
            raise RootError(f"sha256 mismatch: {r['sha256']}")
        c = x509.load_der_x509_certificate(der)
        if c.subject != c.issuer:
            raise RootError(f"not self-issued: {r['sha256']}")
        if c.subject.rfc4514_string() != r["subject"]:
            raise RootError(f"subject mismatch: {r['sha256']}")
        k = c.public_key()
        try:
            if isinstance(k, rsa.RSAPublicKey):
                if c.signature_algorithm_oid._name.endswith("PSS") or c.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.10":
                    padd = c.signature_algorithm_parameters
                else:
                    padd = padding.PKCS1v15()
                k.verify(c.signature, c.tbs_certificate_bytes, padd, c.signature_hash_algorithm)
            elif isinstance(k, ec.EllipticCurvePublicKey):
                k.verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
            elif isinstance(k, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                k.verify(c.signature, c.tbs_certificate_bytes)
            else:
                raise RootError(f"unsupported key type: {r['sha256']}")
        except RootError:
            raise
        except Exception as e:
            raise RootError(f"invalid self-signature for {r['sha256']}: {e!r}")
        for f in ("distrust_after", "sct_not_after"):
            if r[f] is not None:
                try:
                    dt.datetime.fromisoformat(r[f].replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    raise RootError(f"bad {f}: {r['sha256']}")
        names = r["permitted_dns_names"]
        if not isinstance(names, list) or not all(isinstance(x, str) and x for x in names):
            raise RootError(f"bad permitted_dns_names: {r['sha256']}")
    return doc


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", type=pathlib.Path, default=OUT)
    g.add_argument("--max-diff", type=int, default=DEFAULT_MAX_DIFF)
    c = sub.add_parser("classify")
    c.add_argument("old", type=pathlib.Path)
    c.add_argument("new", type=pathlib.Path)
    c.add_argument("--body", type=pathlib.Path)
    a = ap.parse_args()
    try:
        if a.cmd == "generate":
            generate(a.out, a.max_diff)
        else:
            status, added = classify(json.loads(a.old.read_text()), json.loads(a.new.read_text()))
            if a.body:
                a.body.write_text(pr_body(added))
            print(status)
    except RootError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
