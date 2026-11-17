import json

from spf_lookups import cli
from spf_lookups.core import check

ZONE = {
    ("example.com", "TXT"): ("ok", ["google-site-verification=abc", "v=spf1 include:_spf.mail.test include:send.test a mx ip4:192.0.2.1 -all"]),
    ("_spf.mail.test", "TXT"): ("ok", ["v=spf1 include:_a.mail.test include:_b.mail.test ~all"]),
    ("_a.mail.test", "TXT"): ("ok", ["v=spf1 ip4:198.51.100.0/24 ~all"]),
    ("_b.mail.test", "TXT"): ("ok", ["v=spf1 ip6:2001:db8::/32 ~all"]),
    ("send.test", "TXT"): ("ok", ["v=spf1 exists:%{i}.rbl.send.test redirect=_spf.send.test"]),
    ("_spf.send.test", "TXT"): ("ok", ["v=spf1 a:out.send.test -all"]),
    ("out.send.test", "A"): ("ok", ["203.0.113.5"]),
    ("out.send.test", "AAAA"): ("nodata", []),
    ("example.com", "A"): ("ok", ["192.0.2.10"]),
    ("example.com", "AAAA"): ("nodata", []),
    ("example.com", "MX"): ("ok", ["mx1.example.com", "mx2.example.com"]),
    # too many
    ("big.test", "TXT"): ("ok", ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(11)) + " -all"]),
    # void + loop + missing
    ("bad.test", "TXT"): ("ok", ["v=spf1 include:gone.test include:nospf.test a:nohost.test include:bad.test ptr -all"]),
    ("gone.test", "TXT"): ("nxdomain", []),
    ("nospf.test", "TXT"): ("ok", ["something else"]),
    ("nohost.test", "A"): ("nxdomain", []),
    ("nohost.test", "AAAA"): ("nxdomain", []),
    ("two.test", "TXT"): ("ok", ["v=spf1 -all", "v=spf1 ~all"]),
    ("redir.test", "TXT"): ("ok", ["v=spf1 redirect=_spf.send.test ~all"]),
}
for n in range(11):
    ZONE[(f"i{n}.test", "TXT")] = ("ok", ["v=spf1 ip4:192.0.2.0/24 ~all"])


def fake(name, rtype):
    return ZONE.get((name, rtype), ("nxdomain", []))


def test_counts_nested_includes_redirect_and_macros():
    r = check("example.com", fake)
    # include, include, a, mx (4) + _spf.mail.test: 2 + send.test: exists + redirect (2) + _spf.send.test: a (1)
    assert r.total() == 9
    assert r.total_void() == 0
    assert [c.domain for c in r.children] == ["_spf.mail.test", "send.test"]
    assert r.children[1].children[0].via == "redirect"
    assert r.all_problems() == []


def test_over_limit():
    r = check("big.test", fake)
    assert r.total() == 11


def test_void_loop_missing_ptr():
    r = check("bad.test", fake)
    p = " | ".join(r.all_problems())
    assert r.total_void() == 2          # gone.test (nxdomain) and a:nohost.test
    assert "loop" in p and "ptr" in p and "nospf.test has no SPF record" in p


def test_multiple_records_and_redirect_ignored_with_all():
    assert "2 SPF records" in check("two.test", fake).problems[0]
    r = check("redir.test", fake)
    assert r.total() == 0 and r.children == []


def test_cli_exit_codes_and_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "dns_resolver", lambda timeout: fake)
    assert cli.main(["example.com"]) == 0
    assert "DNS lookups:  9 of 10" in capsys.readouterr().out
    assert cli.main(["big.test"]) == 1
    capsys.readouterr()
    assert cli.main(["nothing.test", "--json"]) == 2
    d = json.loads(capsys.readouterr().out)
    assert d["ok"] is False and d["lookups"] == 0
