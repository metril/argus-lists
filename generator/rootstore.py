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
    """SHA-256 set of certificates NSS trusts as delegators for server auth. Raises RootError on a
    truncated or malformed file."""
    objs, cur, lines, i = [], None, text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith("CKA_CLASS "):
            cur = {"class": line.split()[-1]}
            objs.append(cur)
        elif cur is not None and line.startswith("CKA_"):
            parts = line.split(None, 2)
            if len(parts) < 2:
                raise RootError(f"certdata: malformed line {i}")
            if parts[1] == "MULTILINE_OCTAL":
                buf = []
                while True:
                    if i >= len(lines):
                        raise RootError("certdata truncated inside a MULTILINE_OCTAL value")
                    if lines[i].strip() == "END":
                        break
                    buf.append(lines[i])
                    i += 1
                i += 1
                cur[parts[0]] = _octal(buf)
            else:
                cur[parts[0]] = parts[2] if len(parts) > 2 else ""
    certs = [o for o in objs if o["class"] == "CKO_CERTIFICATE"]
    trusts = [o for o in objs if o["class"] == "CKO_NSS_TRUST"]
    if not certs or not trusts:
        raise RootError("certdata has no certificate or trust objects (truncated?)")
    sha1_to_sha256 = {}
    for o in certs:
        if not o.get("CKA_VALUE"):
            raise RootError("certdata: certificate object without CKA_VALUE (truncated?)")
        sha1_to_sha256[hashlib.sha1(o["CKA_VALUE"]).hexdigest()] = sha256_hex(o["CKA_VALUE"])
    trusted = set()
    for o in trusts:
        if "CKA_CERT_SHA1_HASH" not in o or "CKA_TRUST_SERVER_AUTH" not in o:
            raise RootError("certdata: trust object missing its hash or server-auth bit (truncated?)")
        if o["CKA_TRUST_SERVER_AUTH"] == "CKT_NSS_TRUSTED_DELEGATOR":
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


ANCHOR_KEYS = {"sha256_hex", "crs_root_id", "ev_policy_oids", "eutl", "trust_anchor_id", "enforce_anchor_constraints",
               "enforce_anchor_expiry", "tls_trust_anchor", "constraints"}
CONSTRAINT_KEYS = {"min_version", "max_version_exclusive", "sct_not_after_sec", "sct_all_after_sec", "permitted_dns_names"}
_TOKEN = re.compile(r'\s+|#[^\n]*|(?P<str>"(?:\\.|[^"\\])*")|(?P<id>[A-Za-z_][\w.]*)|(?P<num>-?\d[\w.+-]*)|(?P<p>[:{}<>;,\[\]])')


def _textproto(text):
    """Minimal text-proto reader: list of (key, value) where value is str/int-ish or a nested list."""
    toks, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise RootError(f"Chrome Root Store: cannot tokenise at offset {pos}")
        pos = m.end()
        for k in ("str", "id", "num", "p"):
            if m.group(k) is not None:
                toks.append((k, m.group(k)))
    i = 0

    def message(end_on_brace):
        nonlocal i
        out = []
        while i < len(toks):
            kind, v = toks[i]
            if kind == "p" and v == "}":
                if not end_on_brace:
                    raise RootError("Chrome Root Store: unbalanced braces")
                i += 1
                return out
            if kind == "p" and v in ";,":
                i += 1
                continue
            if kind != "id":
                raise RootError(f"Chrome Root Store: unexpected token {v!r}")
            i += 1
            if i < len(toks) and toks[i] == ("p", ":"):
                i += 1
            if i >= len(toks):
                raise RootError("Chrome Root Store truncated")
            kind2, v2 = toks[i]
            i += 1
            if kind2 == "p" and v2 == "{":
                out.append((v, message(True)))
            elif kind2 == "str":
                out.append((v, bytes(v2[1:-1], "utf-8").decode("unicode_escape")))
                while i < len(toks) and toks[i][0] == "str":  # adjacent string literals concatenate
                    out[-1] = (v, out[-1][1] + toks[i][1][1:-1]); i += 1
            elif kind2 in ("id", "num"):
                out.append((v, v2))
            else:
                raise RootError(f"Chrome Root Store: unexpected token {v2!r}")
        if end_on_brace:
            raise RootError("Chrome Root Store truncated (missing closing brace)")
        return out

    return message(False)


def parse_chrome(text):
    """{sha256: {"sct_not_after": RFC3339|None, "permitted_dns_names": [..]}} from root_store.textproto.

    Only trust_anchors are read; any field not on the whitelist raises RootError (an unknown constraint
    must never be silently dropped). A constraint block with max_version_exclusive does not apply to
    current Chrome; an anchor whose constraints are all of that kind is removed in current Chrome and is
    left out. sct_all_after cannot be represented in schema 1: fail loudly. The strictest value wins when
    several current constraints are present."""
    out = {}
    anchors = [v for k, v in _textproto(text) if k == "trust_anchors"]
    for a in anchors:
        for k, _ in a:
            if k not in ANCHOR_KEYS:
                raise RootError(f"Chrome Root Store: unknown trust anchor field {k!r}")
        sha = [v for k, v in a if k == "sha256_hex"]
        if len(sha) != 1 or not re.fullmatch(r"[0-9a-f]{64}", sha[0].lower()):
            raise RootError("Chrome trust anchor without a valid sha256_hex")
        sha = sha[0].lower()
        if sha in out:
            raise RootError(f"duplicate Chrome trust anchor {sha}")
        blocks = []
        for k, v in a:
            if k == "constraints":
                if not isinstance(v, list):
                    raise RootError("Chrome Root Store: malformed constraints")
                for ck, _ in v:
                    if ck not in CONSTRAINT_KEYS:
                        raise RootError(f"Chrome Root Store: unknown constraint field {ck!r} on {sha}")
                blocks.append(v)
        current = [b for b in blocks if not any(k == "max_version_exclusive" for k, _ in b)]
        if blocks and not current:
            print(f"Chrome removed {sha} (only max_version_exclusive constraints)", file=sys.stderr)
            continue
        sct, dns = [], set()
        for b in current:
            for k, v in b:
                if k == "sct_all_after_sec":
                    raise RootError(f"Chrome sct_all_after constraint on {sha} is not representable; extend the schema")
                if k == "sct_not_after_sec":
                    sct.append(int(v))
                elif k == "permitted_dns_names":
                    dns.add(v.lower())
        out[sha] = {"sct_not_after": rfc3339(min(sct)) if sct else None, "permitted_dns_names": sorted(dns)}
    if not out:
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
    """Logs (RFC 6962 and tiled/static) that are usable, qualified, readonly or retired, sorted by log_id."""
    logs = []
    for op in json.loads(data)["operators"]:
        for typ, group in (("rfc6962", "logs"), ("static", "tiled_logs")):
            for l in op.get(group, []):
                state = next((k for k in LOG_STATES if k in l["state"]), None)
                if state is None:
                    continue
                key = base64.b64decode(l["key"], validate=True)
                if base64.b64encode(hashlib.sha256(key).digest()).decode() != l["log_id"]:
                    raise RootError(f"CT log_id does not match its key: {l.get('name')}")
                ti = l.get("temporal_interval")
                logs.append({"log_id": l["log_id"], "key": l["key"], "operator": op["name"], "state": state,
                             "type": typ, "state_since": l["state"][state]["timestamp"],
                             "temporal_interval": {"start": ti["start_inclusive"], "end": ti["end_exclusive"]} if ti else None})
    ids = [l["log_id"] for l in logs]
    if len(ids) != len(set(ids)):
        raise RootError("duplicate CT log_id in the log list")
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


def _content(doc):
    return doc["roots"], doc.get("ct_logs", [])


def same_content(a, b):
    return _content(a) == _content(b)


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
    changed = changed or bool(set(ol) - set(nl))
    return ("review" if review else "auto" if changed else "none"), added


def stricter_only(old, new, now=None):
    """Old document plus only the stricter parts of new: removals, new or earlier dates, narrowed DNS
    lists, logs removed or moved to a more restricted state. Additions and loosenings are left out.
    Returns old itself when nothing stricter changed; otherwise a new document with a bumped serial."""
    n = {r["sha256"]: r for r in new["roots"]}
    roots = []
    for o in old["roots"]:
        r = n.get(o["sha256"])
        if r is None:
            continue
        m = dict(o)
        if not _later(r["distrust_after"], o["distrust_after"]) and r["distrust_after"] != o["distrust_after"]:
            m["distrust_after"] = r["distrust_after"]
        if not _later(r.get("sct_not_after"), o.get("sct_not_after")) and r.get("sct_not_after") != o.get("sct_not_after"):
            m["sct_not_after"] = r["sct_not_after"]
        dn, do = r.get("permitted_dns_names") or [], o.get("permitted_dns_names") or []
        if dn and (not do or set(dn) <= set(do)):
            m["permitted_dns_names"] = dn
        roots.append(m)
    nl = {l["log_id"]: l for l in new.get("ct_logs", [])}
    logs = []
    for o in old.get("ct_logs", []):
        l = nl.get(o["log_id"])
        if l is not None:
            logs.append(o if _log_loosened(o, l) else l)
    if (roots, logs) == _content(old):
        return old
    now = now or dt.datetime.now(dt.timezone.utc)
    return {**old, "serial": next_serial(old["serial"], now), "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sources": new["sources"], "ct_logs": logs, "roots": roots}


def rebase_serial(base, new, now=None):
    """new with its serial moved above base's (new is applied on top of base)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    return {**new, "serial": next_serial(base["serial"], now)} if new["serial"] <= base["serial"] else new


def merged_pr_ok(pulls):
    """True if the commit-associated PR list (GitHub API) holds a merged PR into main."""
    return any(p.get("merged_at") and p.get("base", {}).get("ref") == "main" for p in pulls)


def _clean(s):
    return re.sub(r"[^\x20-\x7e\u00a0-\U0010ffff]", "", s).replace("`", "'").replace("|", "/")


def pr_body(added):
    lines = ["Root store changes that loosen trust, awaiting review (never auto-merged). Listed below: added roots; "
             "see the diff for CT log and constraint changes.", "",
             f"Source report: {CCADB_URL}", "", "| Subject | SHA-256 | Links |", "|---|---|---|"]
    for r in added:
        lines.append(f"| `{_clean(r['subject'])}` | `{r['sha256']}` | [CCADB report]({CCADB_URL}) / "
                     f"[crt.sh](https://crt.sh/?q={r['sha256']}) |")
    return "\n".join(lines) + "\n"


# ---- validation (used by scripts/validate_roots.py) ----------------------------------------

RFC3339Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
DNS_NAME = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _check_time(v, what):
    if not isinstance(v, str) or not RFC3339Z.fullmatch(v):
        raise RootError(f"{what} is not an RFC3339 UTC time ending in Z")
    try:
        dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise RootError(f"{what} is not a valid time")


def validate_logs(logs):
    """Structure of ct_logs (the signature itself is verified when the list is fetched)."""
    from cryptography.hazmat.primitives import serialization
    if not isinstance(logs, list):
        raise RootError("ct_logs must be a list")
    ids = [l.get("log_id") for l in logs]
    if ids != sorted(set(ids)):
        raise RootError("ct_logs not sorted by log_id or duplicated")
    for l in logs:
        if set(l) != {"log_id", "key", "operator", "state", "state_since", "temporal_interval", "type"}:
            raise RootError(f"bad ct_log keys: {l.get('log_id')}")
        if l["state"] not in LOG_STATES:
            raise RootError(f"bad ct_log state: {l['log_id']}")
        if l["type"] not in ("rfc6962", "static"):
            raise RootError(f"bad ct_log type: {l['log_id']}")
        if not isinstance(l["operator"], str) or not l["operator"]:
            raise RootError(f"bad ct_log operator: {l['log_id']}")
        _check_time(l["state_since"], f"ct_log state_since {l['log_id']}")
        try:
            key = base64.b64decode(l["key"], validate=True)
            serialization.load_der_public_key(key)
        except (binascii.Error, ValueError):
            raise RootError(f"bad ct_log key: {l['log_id']}")
        if base64.b64encode(hashlib.sha256(key).digest()).decode() != l["log_id"]:
            raise RootError(f"ct_log log_id does not match its key: {l['log_id']}")
        ti = l["temporal_interval"]
        if ti is not None:
            if not isinstance(ti, dict) or set(ti) != {"start", "end"}:
                raise RootError(f"bad ct_log temporal_interval: {l['log_id']}")
            _check_time(ti["start"], f"ct_log interval start {l['log_id']}")
            _check_time(ti["end"], f"ct_log interval end {l['log_id']}")
            if ti["start"] >= ti["end"]:
                raise RootError(f"ct_log temporal_interval is empty: {l['log_id']}")
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
    _check_time(doc["generated_at"], "generated_at")
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
                _check_time(r[f], f"{f} of {r['sha256']}")
        names = r["permitted_dns_names"]
        if not isinstance(names, list) or not all(isinstance(x, str) and len(x) <= 253 and DNS_NAME.fullmatch(x) for x in names):
            raise RootError(f"bad permitted_dns_names: {r['sha256']}")
    return doc


def _load(p):
    return json.loads(p.read_text())


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
    sp = sub.add_parser("split", help="split old->new into a stricter-only document and the remaining review document")
    sp.add_argument("old", type=pathlib.Path)
    sp.add_argument("new", type=pathlib.Path)
    sp.add_argument("--outdir", type=pathlib.Path, required=True)
    sp.add_argument("--branch", type=pathlib.Path, help="roots.json currently on the rolling branch (optional)")
    a = ap.parse_args()
    try:
        if a.cmd == "generate":
            generate(a.out, a.max_diff)
        elif a.cmd == "classify":
            status, added = classify(_load(a.old), _load(a.new))
            if a.body:
                a.body.write_text(pr_body(added))
            print(status)
        else:
            old, new = _load(a.old), _load(a.new)
            a.outdir.mkdir(parents=True, exist_ok=True)
            strict = stricter_only(old, new)
            has_strict = strict is not old
            base = strict if has_strict else old
            review = not same_content(base, new)
            if has_strict:
                validate(strict)  # a stricter doc that fails validation fails the job loudly
                (a.outdir / "stricter.json").write_text(render(strict))
            if review:
                doc = rebase_serial(base, new)
                validate(doc)
                (a.outdir / "review.json").write_text(render(doc))
                (a.outdir / "body.md").write_text(pr_body(classify(base, new)[1]))
            fresh = bool(a.branch and a.branch.exists() and review and not has_strict
                         and same_content(_load(a.branch), new))
            print(f"stricter={'yes' if has_strict else 'no'}")
            print(f"review={'yes' if review else 'no'}")
            print(f"branch_fresh={'yes' if fresh else 'no'}")
    except RootError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
