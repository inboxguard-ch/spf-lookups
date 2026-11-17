"""Count the DNS lookups of an SPF record (RFC 7208, section 4.6.4)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

LOOKUP_LIMIT = 10      # RFC 7208 4.6.4: mechanisms/modifiers that cause DNS queries
VOID_LIMIT = 2         # RFC 7208 4.6.4: lookups returning NXDOMAIN or no answer
MX_LIMIT = 10          # RFC 7208 4.6.4: at most 10 MX hosts per mx mechanism
MAX_RECORDS = 40       # safety stop for very large trees

LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists")

# A resolver returns (status, answers). status: "ok", "nxdomain", "nodata", "error".
Resolver = Callable[[str, str], "tuple[str, list[str]]"]


@dataclass
class Node:
    domain: str
    via: str = ""                         # "include", "redirect" or "" for the root
    record: Optional[str] = None
    lookups: int = 0                      # lookups caused by terms of this record (not children)
    void: int = 0
    terms: list = field(default_factory=list)   # (term, cost, note)
    children: list = field(default_factory=list)
    problems: list = field(default_factory=list)

    def total(self) -> int:
        return self.lookups + sum(c.total() for c in self.children)

    def total_void(self) -> int:
        return self.void + sum(c.total_void() for c in self.children)

    def all_problems(self) -> list:
        out = list(self.problems)
        for c in self.children:
            out += c.all_problems()
        return out


def dns_resolver(timeout: float = 5.0) -> Resolver:
    import dns.resolver
    import dns.exception

    r = dns.resolver.Resolver()
    r.lifetime = timeout

    def resolve(name: str, rtype: str):
        try:
            ans = r.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return "nxdomain", []
        except dns.resolver.NoAnswer:
            return "nodata", []
        except (dns.exception.DNSException, OSError):
            return "error", []
        if rtype == "TXT":
            return "ok", [b"".join(rd.strings).decode("utf-8", "replace") for rd in ans]
        if rtype == "MX":
            return "ok", [str(rd.exchange).rstrip(".") for rd in ans]
        return "ok", [rd.to_text() for rd in ans]

    return resolve


def _spf_records(txts: list) -> list:
    return [t.strip() for t in txts if t.strip().lower() == "v=spf1" or t.strip().lower().startswith("v=spf1 ")]


def _target(arg: str, current: str) -> str:
    return (arg or current).split("/")[0].rstrip(".").lower()


class Counter:
    def __init__(self, resolve: Resolver):
        self.resolve = resolve
        self.seen: set = set()
        self.records = 0

    def check(self, domain: str) -> Node:
        return self._walk(domain.rstrip(".").lower(), "", 0)

    def _void(self, node: Node, status: str, what: str):
        if status in ("nxdomain", "nodata"):
            node.void += 1
            node.problems.append(f"void lookup: {what} ({status})")
        elif status == "error":
            node.problems.append(f"DNS error: {what}")

    def _walk(self, domain: str, via: str, depth: int) -> Node:
        node = Node(domain, via)
        if domain in self.seen:
            node.problems.append(f"loop: {domain} is referenced again")
            return node
        if depth > 10 or self.records >= MAX_RECORDS:
            node.problems.append("tree too large, counting stopped")
            return node
        self.seen.add(domain)
        self.records += 1

        status, txts = self.resolve(domain, "TXT")
        recs = _spf_records(txts)
        if not recs:
            if status in ("nxdomain", "nodata", "ok"):
                if depth > 0:
                    node.void += 1 if status != "ok" else 0
                node.problems.append(f"{domain} has no SPF record" + (" (permerror)" if depth > 0 else ""))
            else:
                node.problems.append(f"DNS error reading TXT of {domain}")
            return node
        if len(recs) > 1:
            node.problems.append(f"{domain} has {len(recs)} SPF records (permerror)")
        node.record = recs[0]

        terms = recs[0].split()[1:]
        has_all = any(t.lstrip("+-~?").lower() == "all" for t in terms)
        redirect = None
        for raw in terms:
            t = raw.lower()
            mech = t.lstrip("+-~?")
            name, sep, arg = mech.partition(":") if ":" in mech.split("/")[0] else (mech.split("/")[0], "", "")
            if mech.startswith("redirect="):
                redirect = raw.split("=", 1)[1]
                continue
            if name not in LOOKUP_MECHS:
                node.terms.append((raw, 0, ""))
                continue
            node.lookups += 1
            if "%" in arg:
                node.terms.append((raw, 1, "macro, target known only at the receiver"))
                continue
            if name == "include":
                node.terms.append((raw, 1, ""))
                node.children.append(self._walk(_target(arg, domain), "include", depth + 1))
            elif name == "a":
                tgt = _target(arg, domain)
                st4, a4 = self.resolve(tgt, "A")
                st6, a6 = self.resolve(tgt, "AAAA")
                if not a4 and not a6:
                    self._void(node, st4 if st4 != "ok" else st6, f"a → {tgt}")
                node.terms.append((raw, 1, ""))
            elif name == "mx":
                tgt = _target(arg, domain)
                st, hosts = self.resolve(tgt, "MX")
                note = ""
                if not hosts:
                    self._void(node, st, f"mx → {tgt}")
                elif len(hosts) > MX_LIMIT:
                    node.problems.append(f"mx → {tgt} has {len(hosts)} MX hosts (more than {MX_LIMIT}, permerror)")
                else:
                    note = f"{len(hosts)} MX host(s)"
                node.terms.append((raw, 1, note))
            elif name == "ptr":
                node.terms.append((raw, 1, "ptr is deprecated (RFC 7208 5.5)"))
                node.problems.append("ptr mechanism should not be used")
            elif name == "exists":
                node.terms.append((raw, 1, ""))
        if redirect is not None:
            if has_all:
                node.terms.append(("redirect=" + redirect, 0, "ignored because 'all' is present"))
            else:
                node.lookups += 1
                node.terms.append(("redirect=" + redirect, 1, ""))
                if "%" not in redirect:
                    node.children.append(self._walk(_target(redirect, domain), "redirect", depth + 1))
        return node


def check(domain: str, resolve: Optional[Resolver] = None) -> Node:
    return Counter(resolve or dns_resolver()).check(domain)
