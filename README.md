# Seekr

## See what the web sees.

Why does a website work from one network but fail from another?

A 403 doesn't tell you whether you're blocked by your IP, your location,
a WAF, a rate limit, or something else.

Seekr investigates.

It observes a target from different network vantage points, collects
evidence across DNS, TCP, TLS, HTTP, network identity, and response
content, then compares the results to explain what changed and what is
most likely causing the difference.

Don't just check if it works. Understand why.

**SEE → COMPARE → EXPLAIN**

![Seekr diagnosing a geo-restricted site from two network vantages](assets/demo.gif)

## What Seekr Actually Does

```text
Target
  ↓
Network Vantage
  ↓
Observe
  ↓
Compare
  ↓
Detect
  ↓
Explain
```

## Not Another Proxy Checker

A proxy checker asks:

> "Does this proxy work?"

Seekr asks:

> "Why does the web behave differently through this network?"

It doesn't reduce a request to a status code. It correlates multiple
observations — status, content, identity, timing — before producing a
diagnosis, and it refuses to guess when the evidence isn't there.

## More Than a Status Code

Seekr doesn't only handle 403. It investigates the full picture:

- **Access responses** — 403, 429 with Retry-After, 452, 5xx, and block
  pages served with 200 (different content or landing page per region).
- **Transport failures** — DNS, TCP, TLS, timeouts, redirect loops,
  truncated bodies — each attributed to the right stage, not lumped
  together.
- **Vantage failures** — dead proxies, bad auth, slow exits are reported
  as vantage problems, never mistaken for target blocking.
- **Divergence signals** — status, content fingerprint, final URL, IP,
  country, ASN, timing, instability across repeated probes.

One signal is never enough for a verdict. A lone 403 without
corroborating evidence yields `unknown`, not a guess.

## Use Cases

### Who it's for

- **Developers shipping multi-region products** — verify a page, API, or
  checkout actually behaves the same from every market you serve, before
  your users tell you it doesn't.
- **QA / SRE teams** — turn "works on my network" into reproducible,
  evidence-backed checks in CI instead of screenshots over chat.
- **Researchers and analysts** — measure access differences across
  networks with machine-readable output instead of manual curl
  archaeology.
- **Anyone operating through proxies or regional exits** — confirm the
  path works *and* understand what the destination sees through it.

### What it's for

**"It works from the US but not from here."**
Diagnose the same URL from direct and a regional vantage. Seekr tells
you whether the difference is geographic, address-based, or something
else entirely — with the evidence to back it.

```bash
seekr diagnose https://example.com/shop --proxy http://us-exit:8080
```

**"Is it me or is it them?"**
A failing proxy looks identical to a blocked target if you only watch
status codes. Seekr separates vantage problems (`proxy_failure`) from
target-side behavior, so you stop blaming the wrong layer.

**"Am I being rate limited or blocked?"**
429 with Retry-After plus repeated same-vantage behavior reads as rate
limiting with a concrete back-off step; a lone 403 without markers
reads as `unknown` instead of a confident-sounding misdiagnosis.

**Fleet checks and automation.**
`batch` runs a target list with bounded parallelism and input-order
results; `--json` plus exit codes (`0` healthy, `1` restriction,
`3+` unreliable run) plug straight into scripts and CI.

```bash
seekr batch targets.txt --json | jq '.summary'
```

## Install

```bash
cargo build --release
./target/release/seekr --help
```

## Usage

```bash
seekr diagnose <URL>
seekr compare <URL>
seekr probe <URL>
seekr trace <URL>
seekr batch <FILE>
```

Common flags:

```text
--proxy <URL>            single extra vantage (http/https/socks5)
--proxy-file <PATH>      one proxy URL per line, # comments allowed
--no-direct              skip the direct path
--timeout <SECONDS>      total timeout per request (default 15)
--retries <N>            retries for safe methods only (default 1)
--method <METHOD>        HTTP method (default GET)
--header <"Name: value"> repeatable
--user-agent <STRING>
--json                   stdout carries JSON only; logs go to stderr
--quiet                  print only the result kind
--verbose
--max-probes <N>         per-target probe budget (default 10)
--concurrency <N>        batch parallelism (default 4)
--no-identity-lookup     skip IP/country/ASN enrichment (default: on)
--geo-map <PATH>         JSON file mapping vantage label substring to
                         identity ({ "sg": {"country":"SG", ...} });
                         static entries win over auto lookup
```

## Identity

By default seekr learns each vantage's egress IP, country, and ASN by
querying `https://ipinfo.io/json` through that same vantage, so the
observed identity is what the web actually sees from that path. Lookup
failures degrade to `null` and never fail the run. Only the lookup
request goes to the provider — never your target list. Disable with
`--no-identity-lookup`. A `--geo-map` file overrides auto results for
matching vantages (useful for static egress or offline runs).

File formats: `targets` are CLI args; proxy files hold one proxy URL per
line, blank lines and `#` comments are ignored. Invalid lines are skipped
with a warning on stderr.

## Examples

```bash
seekr diagnose https://example.com/
seekr compare https://example.com/ --proxy http://127.0.0.1:8080
seekr probe https://example.com/ --json
seekr trace https://example.com/
seekr batch targets.txt --concurrency 4
seekr diagnose https://example.com/ --quiet
```

`targets.txt` holds one URL per line; blank lines and `#` comments are
ignored and bad lines are skipped with a stderr warning.

## Shell completions

```bash
seekr completions bash >> ~/.bash_completion
seekr completions zsh > ~/.zsh/_seekr
seekr completions fish > ~/.config/fish/completions/seekr.fish
```

## Exit codes

```text
0 = healthy, no material restriction
1 = restriction or abnormal behavior diagnosed
2 = invalid arguments or target
3 = target or network unreachable
4 = configured vantage failure
5 = timeout
6 = internal error
7 = partial or unknown diagnosis
```

## JSON

`--json` prints a single object with `schema_version: "1"`, the target,
per-vantage evidence, signals, and (for `diagnose`) a diagnosis with
confidence, backing evidence ids, an interpretation, and a next step.
Missing timings are `null`, never zero. Credentials never appear in output.
