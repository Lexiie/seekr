# seekr

Network vantage diagnostic engine: see what the web sees from different
network paths, compare the results, and explain why access differs.

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
