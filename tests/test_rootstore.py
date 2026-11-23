import base64, datetime as dt, hashlib, json, pathlib, sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "generator"))
import rootstore as rs  # noqa: E402

NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.timezone.utc)
_cache = {}


def make_cert(cn, kind="ec", self_signed=True):
    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    other = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=1))
         .not_valid_after(NOW + dt.timedelta(days=3650)).sign(key if self_signed else other, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def der_of(cn, kind="ec"):
    return _cache.setdefault((cn, kind), make_cert(cn, kind))


def sha(d):
    return hashlib.sha256(d).hexdigest()


def pem(d):
    return "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(d).decode() + "\n-----END CERTIFICATE-----"


def ccadb_csv(rows):
    import csv, io
    b = io.StringIO()
    w = csv.writer(b)
    w.writerow(["Common Name or Certificate Name", "SHA-256 Fingerprint", "Trust Bits", "Distrust for TLS After Date", "PEM Info"])
    for d, bits, dist in rows:
        w.writerow(["x", sha(d).upper(), bits, dist, "'" + pem(d) + "'"])
    return b.getvalue()


def octal(b):
    s = "".join(f"\\{x:03o}" for x in b)
    return "\n".join(s[i:i + 64] for i in range(0, len(s), 64))


def certdata(items):
    out = []
    for d, trust in items:
        out.append(f'CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_LABEL UTF8 "x"\nCKA_VALUE MULTILINE_OCTAL\n{octal(d)}\nEND\n')
        out.append(f"CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\nCKA_CERT_SHA1_HASH MULTILINE_OCTAL\n"
                   f"{octal(hashlib.sha1(d).digest())}\nEND\nCKA_TRUST_SERVER_AUTH CK_TRUST {trust}\n")
    return "\n".join(out)


TD = "CKT_NSS_TRUSTED_DELEGATOR"


def chrome_txt(entries):
    out = "version_major: 1\n"
    for h, sct, dns in entries:
        out += f'# CN=x\ntrust_anchors {{\n  sha256_hex: "{h}"\n  crs_root_id: 3\n  ev_policy_oids: "2.23.140.1.1"\n'
        if sct:
            out += f'  constraints: {{\n    sct_not_after_sec: {sct}\n    min_version: "153.0.1.0"\n    permitted_dns_names: "{dns}"\n  }}\n' if dns else \
                   f'  constraints: {{\n    sct_not_after_sec: {sct}\n    min_version: "153.0.1.0"\n  }}\n  constraints: {{\n    max_version_exclusive: "153.0.1.0"\n  }}\n'
        out += "}\n\n"
    out += 'additional_certs {\n  sha256_hex: "' + "ab" * 32 + '"\n  crs_root_id: 9\n}\n'
    return out


def test_parse_chrome():
    c = rs.parse_chrome(chrome_txt([("a" * 64, 1820966399, None), ("b" * 64, None, None), ("c" * 64, 1790812799, "example.com")]))
    assert set(c) == {"a" * 64, "b" * 64, "c" * 64}  # additional_certs ignored
    assert c["a" * 64] == {"sct_not_after": "2027-09-14T23:59:59Z", "permitted_dns_names": []}
    assert c["b" * 64] == {"sct_not_after": None, "permitted_dns_names": []}
    assert c["c" * 64]["permitted_dns_names"] == ["example.com"]
    with pytest.raises(rs.RootError):
        rs.parse_chrome("trust_anchors {\n sha256_hex: \"" + "a" * 64 + "\"\n constraints: {\n sct_all_after_sec: 5\n }\n}\n")


def test_parse_ccadb_filters_websites_and_distrust():
    a, b, c = der_of("a"), der_of("b"), der_of("c")
    r = rs.parse_ccadb(ccadb_csv([(a, "Websites;Email", "2026.08.06"), (b, "Email", ""), (c, "Websites", "")]))
    assert set(r) == {sha(a), sha(c)}
    assert r[sha(a)]["distrust_after"] == "2026-08-06T00:00:00Z" and r[sha(c)]["distrust_after"] is None


def test_parse_ccadb_rejects_fingerprint_mismatch():
    a = der_of("a")
    bad = ccadb_csv([(a, "Websites", "")]).replace(sha(a).upper(), "AB" * 32)
    with pytest.raises(rs.RootError):
        rs.parse_ccadb(bad)


def test_parse_certdata_server_auth_only():
    a, b = der_of("a"), der_of("b")
    assert rs.parse_certdata(certdata([(a, TD), (b, "CKT_NSS_MUST_VERIFY_TRUST")])) == {sha(a)}


def test_build_intersection_sorted_and_diff_limit():
    ds = [der_of(f"r{i}") for i in range(6)]
    cc = rs.parse_ccadb(ccadb_csv([(d, "Websites", "") for d in ds[:5]]))
    nss = {sha(d) for d in ds[:5]}
    chrome = {h: {"sct_not_after": None, "permitted_dns_names": []} for h in nss}
    roots, dropped = rs.build(cc, nss, chrome)
    assert dropped == [] and [r["sha256"] for r in roots] == sorted(nss)
    assert roots[0]["subject"].startswith("CN=r")
    assert len(rs.build(cc, nss | {sha(ds[5])}, chrome, max_diff=1)[0]) == 5
    with pytest.raises(rs.RootError):
        rs.build(cc, {sha(ds[0])}, chrome, max_diff=2)


def test_build_chrome_drops_and_never_adds():
    a, b, extra = der_of("a"), der_of("b"), der_of("chrome-only")
    cc = rs.parse_ccadb(ccadb_csv([(a, "Websites", "2026.08.06"), (b, "Websites", "")]))
    chrome = {sha(a): {"sct_not_after": "2027-01-01T00:00:00Z", "permitted_dns_names": ["x.com"]},
              sha(extra): {"sct_not_after": None, "permitted_dns_names": []}}
    roots, dropped = rs.build(cc, {sha(a), sha(b)}, chrome)
    assert [r["sha256"] for r in roots] == [sha(a)] and dropped == [sha(b)]
    assert roots[0]["distrust_after"] == "2026-08-06T00:00:00Z"
    assert roots[0]["sct_not_after"] == "2027-01-01T00:00:00Z" and roots[0]["permitted_dns_names"] == ["x.com"]


def test_next_serial():
    assert rs.next_serial(0, NOW) == 2026112300
    assert rs.next_serial(2026112300, NOW) == 2026112301
    assert rs.next_serial(2026112200, NOW) == 2026112300


def corpus(n=rs.MIN_ROOTS):
    ds = [der_of(f"root{i}", "rsa" if i % 10 == 0 else "ec") for i in range(n)]
    return ds, ccadb_csv([(d, "Websites", "") for d in ds]), certdata([(d, TD) for d in ds])


LOGKEYS = [ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for _ in range(4)]
SIGKEY = rsa.generate_private_key(65537, 2048)
SIGPEM = SIGKEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def loglist(states=("usable", "usable", "usable", "retired")):
    logs = []
    for k, st in zip(LOGKEYS, states):
        logs.append({"name": "l", "log_id": base64.b64encode(hashlib.sha256(k).digest()).decode(),
                     "key": base64.b64encode(k).decode(), "state": {st: {"timestamp": "2026-01-01T00:00:00Z"}},
                     "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"}})
    logs.append({"name": "p", "log_id": "x", "key": "x", "state": {"pending": {"timestamp": "2026-01-01T00:00:00Z"}}})
    data = json.dumps({"operators": [{"name": "Op", "logs": logs}]}).encode()
    return data, SIGKEY.sign(data, padding.PKCS1v15(), hashes.SHA256())


def gen_kwargs(chrome_hashes, **kw):
    data, sig = loglist()
    return dict(chrome_text=chrome_txt([(h, None, None) for h in chrome_hashes]), loglist=data, loglist_sig=sig,
                pubkey_pem=SIGPEM, **kw)


def test_log_list_signature_and_filters():
    data, sig = loglist()
    rs.verify_log_list(data, sig, SIGPEM)
    with pytest.raises(rs.RootError, match="signature"):
        rs.verify_log_list(data + b" ", sig, SIGPEM)
    logs = rs.parse_log_list(data)
    assert len(logs) == 4 and {l["state"] for l in logs} == {"usable", "retired"}  # pending dropped
    assert logs[0]["temporal_interval"] == {"start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"}
    assert logs[0]["state_since"] == "2026-01-01T00:00:00Z" and logs[0]["operator"] == "Op"
    few, _ = loglist(("usable", "usable", "retired", "retired"))
    with pytest.raises(rs.RootError, match="usable"):
        rs.parse_log_list(few)


def test_generate_deterministic_and_unchanged(tmp_path):
    ds, cc, nss = corpus()
    out = tmp_path / "roots.json"
    kw = gen_kwargs([sha(d) for d in ds])
    assert rs.generate(out, now=NOW, ccadb_text=cc, certdata_text=nss, **kw) is True
    first = out.read_text()
    assert rs.generate(out, now=NOW, ccadb_text=cc, certdata_text=nss, **kw) is False
    assert out.read_text() == first
    out2 = tmp_path / "b.json"
    rs.generate(out2, now=NOW, ccadb_text=cc, certdata_text=nss, **kw)
    assert out2.read_text() == first
    doc = json.loads(first)
    assert doc["serial"] == 2026112300 and doc["generated_at"] == "2026-11-23T12:00:00Z"
    rs.validate(doc)
    assert len(doc["ct_logs"]) == 4 and doc["roots"][0]["permitted_dns_names"] == []


def test_generate_chrome_floor_and_bad_signature(tmp_path):
    ds, cc, nss = corpus()
    with pytest.raises(rs.RootError, match="floor"):  # Chrome drops most roots
        rs.generate(tmp_path / "r.json", now=NOW, ccadb_text=cc, certdata_text=nss, **gen_kwargs([sha(ds[0])]))
    kw = gen_kwargs([sha(d) for d in ds])
    kw["loglist_sig"] = b"\0" * 256
    with pytest.raises(rs.RootError, match="signature"):
        rs.generate(tmp_path / "r.json", now=NOW, ccadb_text=cc, certdata_text=nss, **kw)


def test_generate_floor(tmp_path):
    ds = [der_of(f"root{i}") for i in range(5)]
    with pytest.raises(rs.RootError):
        rs.generate(tmp_path / "r.json", now=NOW, ccadb_text=ccadb_csv([(d, "Websites", "") for d in ds]),
                    certdata_text=certdata([(d, TD) for d in ds]), **gen_kwargs([sha(d) for d in ds]))


def doc_of(n=rs.MIN_FINAL_ROOTS):
    ds, cc, nss = corpus(n)
    chrome = {sha(d): {"sct_not_after": None, "permitted_dns_names": []} for d in ds}
    return {"schema": 1, "serial": 5, "generated_at": "2026-11-23T12:00:00Z",
            "sources": {"ccadb_sha256": "a", "certdata_rev": "b"},
            "ct_logs": rs.parse_log_list(loglist()[0]),
            "roots": rs.build(rs.parse_ccadb(cc), rs.parse_certdata(nss), chrome)[0]}


def test_validate_ok_and_serial():
    d = doc_of()
    rs.validate(d, prev_serial=4)
    with pytest.raises(rs.RootError):
        rs.validate(d, prev_serial=5)


def test_validate_failures():
    d = doc_of()
    with pytest.raises(rs.RootError, match="floor"):
        rs.validate(doc_of(5))
    bad = json.loads(json.dumps(d)); bad["roots"][0]["sha256"] = "0" * 64
    with pytest.raises(rs.RootError):
        rs.validate(bad)
    bad = json.loads(json.dumps(d)); bad["roots"][1], bad["roots"][2] = bad["roots"][2], bad["roots"][1]
    with pytest.raises(rs.RootError, match="sorted"):
        rs.validate(bad)
    bad = json.loads(json.dumps(d)); bad["schema"] = 2
    with pytest.raises(rs.RootError):
        rs.validate(bad)


def test_validate_ct_logs():
    d = doc_of()
    bad = json.loads(json.dumps(d)); bad["ct_logs"][0]["state"] = "pending"
    with pytest.raises(rs.RootError):
        rs.validate(bad)
    bad = json.loads(json.dumps(d)); bad["ct_logs"] = [l for l in bad["ct_logs"] if l["state"] != "usable"][:1] + bad["ct_logs"][:2]
    bad["ct_logs"] = sorted({l["log_id"]: l for l in bad["ct_logs"]}.values(), key=lambda l: l["log_id"])[:2]
    with pytest.raises(rs.RootError, match="usable"):
        rs.validate(bad)
    bad = json.loads(json.dumps(d)); bad["ct_logs"][0]["log_id"] = "AAAA"
    with pytest.raises(rs.RootError):
        rs.validate(bad)
    bad = json.loads(json.dumps(d)); bad["roots"][0]["sct_not_after"] = "garbage"
    with pytest.raises(rs.RootError):
        rs.validate(bad)


def test_validate_rejects_bad_self_signature_and_non_self_issued():
    d = doc_of()
    forged = make_cert("forged", self_signed=False)  # self-issued name, signed by another key
    bad = json.loads(json.dumps(d))
    bad["roots"][0] = {"sha256": sha(forged), "subject": "CN=forged", "der": base64.b64encode(forged).decode(),
                       "distrust_after": None, "sct_not_after": None, "permitted_dns_names": []}
    bad["roots"].sort(key=lambda r: r["sha256"])
    with pytest.raises(rs.RootError, match="self-signature"):
        rs.validate(bad)


def r(h, dist=None, sct=None, dns=()):
    return {"sha256": h, "subject": "CN=" + h, "der": "", "distrust_after": dist, "sct_not_after": sct,
            "permitted_dns_names": list(dns)}


def lg(i, state="usable", since="2026-01-01T00:00:00Z", ti=None):
    return {"log_id": i, "key": "k", "operator": "o", "state": state, "state_since": since, "temporal_interval": ti}


@pytest.mark.parametrize("old,new,status", [
    ([r("a")], [r("a")], "none"),
    ([r("a"), r("b")], [r("a")], "auto"),
    ([r("a")], [r("a", "2026-01-01T00:00:00Z")], "auto"),
    ([r("a", "2026-06-01T00:00:00Z")], [r("a", "2026-01-01T00:00:00Z")], "auto"),
    ([r("a", "2026-01-01T00:00:00Z")], [r("a", "2026-06-01T00:00:00Z")], "review"),
    ([r("a", "2026-01-01T00:00:00Z")], [r("a")], "review"),
    ([r("a")], [r("a"), r("b")], "review"),
    ([r("a"), r("b")], [r("a"), r("c")], "review"),
    ([r("a")], [r("a", sct="2027-01-01T00:00:00Z")], "auto"),
    ([r("a", sct="2027-06-01T00:00:00Z")], [r("a", sct="2027-01-01T00:00:00Z")], "auto"),
    ([r("a", sct="2027-01-01T00:00:00Z")], [r("a", sct="2027-06-01T00:00:00Z")], "review"),
    ([r("a", sct="2027-01-01T00:00:00Z")], [r("a")], "review"),
    ([r("a")], [r("a", dns=["x.com"])], "auto"),
    ([r("a", dns=["x.com", "y.com"])], [r("a", dns=["x.com"])], "auto"),
    ([r("a", dns=["x.com"])], [r("a", dns=["x.com", "y.com"])], "review"),
    ([r("a", dns=["x.com"])], [r("a")], "review"),
])
def test_classify(old, new, status):
    s, added = rs.classify({"roots": old}, {"roots": new})
    assert s == status
    if status == "review" and {x["sha256"] for x in new} - {x["sha256"] for x in old}:
        body = rs.pr_body(added)
        assert added[0]["sha256"] in body and "crt.sh" in body


@pytest.mark.parametrize("old,new,status", [
    ([lg("1")], [lg("1")], "none"),
    ([lg("1")], [lg("1"), lg("2")], "review"),
    ([lg("1"), lg("2")], [lg("1")], "auto"),
    ([lg("1")], [lg("1", "readonly")], "auto"),
    ([lg("1", "readonly")], [lg("1", "retired")], "auto"),
    ([lg("1", "retired")], [lg("1", "usable")], "review"),
    ([lg("1", "retired")], [lg("1", "retired", since="2026-06-01T00:00:00Z")], "review"),
    ([lg("1")], [lg("1", ti={"start": "a", "end": "b"})], "review"),
])
def test_classify_logs(old, new, status):
    assert rs.classify({"roots": [], "ct_logs": old}, {"roots": [], "ct_logs": new})[0] == status


def test_classify_old_file_without_logs():
    assert rs.classify({"roots": [r("a")]}, {"roots": [r("a")], "ct_logs": []})[0] == "none"
