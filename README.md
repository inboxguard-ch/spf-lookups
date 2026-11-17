# spf-lookups

Count the DNS lookups of an SPF record – including every nested `include` and `redirect` – and see which entry breaks the limit.

RFC 7208 allows at most **10 DNS lookups** and **2 void lookups** per SPF evaluation. Above that, receivers return `permerror`, SPF no longer counts for DMARC, and mail that relies on SPF alignment starts to fail. Every SaaS sender you add (newsletter, ticketing, CRM, invoicing) usually adds another `include`, so domains cross the limit without anyone noticing.

```
$ spf-lookups example.com
example.com  [9 lookups]
    v=spf1 include:_spf.mail.test include:send.test a mx ip4:192.0.2.1 -all
    include:_spf.mail.test  [2 lookups]
        v=spf1 include:_a.mail.test include:_b.mail.test ~all
        include:_a.mail.test  [0 lookups]
            v=spf1 ip4:198.51.100.0/24 ~all
        include:_b.mail.test  [0 lookups]
            v=spf1 ip6:2001:db8::/32 ~all
    include:send.test  [3 lookups]
        v=spf1 exists:%{i}.rbl.send.test redirect=_spf.send.test
        redirect:_spf.send.test  [1 lookup]
            v=spf1 a:out.send.test -all

DNS lookups:  9 of 10
Void lookups: 0 of 2
Result: OK
```

## Install

```
pip install git+https://github.com/inboxguard-ch/spf-lookups
```

Requires Python 3.9+ and [dnspython](https://www.dnspython.org/).

## Usage

```
spf-lookups example.com            # tree and totals
spf-lookups example.com --json     # machine-readable
spf-lookups example.com --timeout 3
```

Exit codes, for scripts and CI: `0` within limits · `1` limit exceeded or permerror · `2` no SPF record or DNS error.

## What is counted

| Term | Lookups |
|---|---|
| `include`, `a`, `mx`, `ptr`, `exists`, `redirect` | 1 each, plus everything inside an included or redirected record |
| `ip4`, `ip6`, `all`, `exp` | 0 |
| `redirect` when `all` is present | 0 (ignored, RFC 7208 6.1) |

It also reports void lookups (NXDOMAIN or empty answers), includes pointing to domains without SPF, more than one SPF record, loops, `ptr` (deprecated) and `mx` targets with more than 10 hosts. Macros such as `%{i}` are counted, but their target can only be resolved by the receiver.

## How to get below 10

1. Remove services you no longer use.
2. Take services out of SPF that sign with DKIM in your domain – DMARC passes on aligned DKIM alone.
3. Move bulk senders to a subdomain with its own SPF record (`news.example.com`).
4. Flattening (IP addresses instead of `include`) only with monitoring: providers change their ranges without notice.

## Web version and DMARC

No install needed: the same check runs in the browser at **[igs.ch – SPF lookups](https://www.igs.ch/?p=tool&t=spf)**, next to a DMARC report reader and a DMARC record builder. To check SPF, DKIM, DMARC and MTA-STS of a whole domain at once: **[free DMARC check](https://www.igs.ch/?p=check)**.

`spf-lookups` is maintained by [Inbox Guard Switzerland](https://www.igs.ch), a Swiss service that takes domains safely from DMARC `p=none` to `p=reject`.

## License

MIT
