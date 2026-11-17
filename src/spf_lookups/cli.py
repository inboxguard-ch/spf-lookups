"""Command line interface: spf-lookups example.com"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import LOOKUP_LIMIT, VOID_LIMIT, Node, check, dns_resolver


def _tree(node: Node, prefix: str = "", out=None) -> list:
    out = [] if out is None else out
    label = node.domain if not node.via else f"{node.via}:{node.domain}"
    out.append(f"{prefix}{label}  [{node.total()} lookup{'s' if node.total() != 1 else ''}]")
    child_prefix = prefix + "    "
    if node.record:
        out.append(f"{child_prefix}{node.record}")
    for c in node.children:
        _tree(c, child_prefix, out)
    return out


def _as_dict(node: Node) -> dict:
    return {
        "domain": node.domain,
        "via": node.via or None,
        "record": node.record,
        "lookups": node.total(),
        "own_lookups": node.lookups,
        "void_lookups": node.total_void(),
        "terms": [{"term": t, "cost": c, "note": n or None} for t, c, n in node.terms],
        "problems": node.problems,
        "children": [_as_dict(c) for c in node.children],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="spf-lookups",
        description="Count the DNS lookups of an SPF record including all nested includes (RFC 7208 limit: 10).",
        epilog="Exit codes: 0 = within limits, 1 = limit exceeded or permerror, 2 = no SPF record or DNS error. "
        "Free web version and DMARC check: https://www.igs.ch/?p=tool&t=spf",
    )
    p.add_argument("domain", help="domain to check, e.g. example.com")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout per query in seconds (default 5)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    root = check(a.domain, dns_resolver(a.timeout))
    total, void = root.total(), root.total_void()
    problems = root.all_problems()
    if not root.record:
        code = 2
    elif total > LOOKUP_LIMIT or void > VOID_LIMIT or any("permerror" in x or "loop" in x for x in problems):
        code = 1
    else:
        code = 0

    if a.json:
        print(json.dumps({"domain": root.domain, "lookups": total, "limit": LOOKUP_LIMIT,
                          "void_lookups": void, "void_limit": VOID_LIMIT, "ok": code == 0,
                          "problems": problems, "tree": _as_dict(root)}, indent=2))
        return code

    if not root.record:
        print(f"{root.domain}: {problems[0] if problems else 'no SPF record found'}")
        return code
    print("\n".join(_tree(root)))
    print()
    print(f"DNS lookups:  {total} of {LOOKUP_LIMIT}" + ("  -> LIMIT EXCEEDED (permerror)" if total > LOOKUP_LIMIT else ""))
    print(f"Void lookups: {void} of {VOID_LIMIT}" + ("  -> LIMIT EXCEEDED (permerror)" if void > VOID_LIMIT else ""))
    for x in dict.fromkeys(problems):
        print(f"! {x}")
    print("Result: OK" if code == 0 else "Result: FAIL – receivers will treat SPF as permerror")
    return code


if __name__ == "__main__":
    sys.exit(main())
