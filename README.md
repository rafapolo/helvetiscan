
# helvetiscan

Process and visualize the entire Swiss `.ch` namespace — ~2.5 million domains mapped to their authoritative nameservers — as an interactive force graph.

The graph exposes the DNS dependency structure of the Swiss internet: who controls the infrastructure, where concentration sits, and what a disruption to a single provider would cascade into.

<div align="center">

![50k nodes sample](50knodes.jpg)

</div>

50k domain nodes rendered. See it online [here](https://xn--2dk.xyz/dataviz/swiss/?maxPoints=50000&sim=1).

---

## What it does
(work in progress [^1])

1. **Process** — Python and JS scripts convert raw CSV output to Apache Arrow / Parquet for fast columnar loading.
2. **Visualize** — A Bun-served web app renders the full graph in-browser via [Cosmograph](https://cosmograph.app/), a WebGL force-graph renderer capable of handling millions of nodes.
3. **Scan Swiss internet infrastructure** — Rust CLI (`helvetiscan`) scans the `.ch` namespace for HTTP, DNS, TLS, port-level metadata, and subdomain discovery.

Node colors encode connectivity:
- **Blue** — leaf domain (1–2 connections)
- **Pink** — mid-tier node (3–100 connections)
- **Orange** — major DNS hub (100+ connections)

---

## Project structure

```
├── src/
│   ├── main.rs          # Rust async scraper (tokio + reqwest)
│   └── process/         # Data conversion scripts (Python + JS)
├── web/
│   ├── index.html       # Cosmograph visualization
│   ├── serve.js         # Bun static file server
│   ├── nodes.arrow      # Pre-built graph data (served to browser)
│   └── edges.arrow
├── data/
│   ├── domains.duckdb   # Queryable database (DuckDB)
│   └── ...              # Raw and intermediate data (gitignored)
```

---

## Quickstart

**Serve and open:**

```bash
bun run serve
# → http://localhost:3000
```

**Explore the database:**

```bash
duckdb data/domains.duckdb -ui
# → http://localhost:4213
```

### URL parameters

| Parameter | Default | Description |
|---|---|---|
| `?maxPoints=N` | all | Cap nodes rendered (use for weaker GPUs) |
| `?sim=1` | off | Enable continuous force simulation |
| `?labels=0` | on | Disable node labels |

---

**Targeted single-domain scan** (all four passes, prints a summary table):

```bash
helvetiscan --domain migros.ch --all
```

**Build on a small VPS**

The default build uses DuckDB's `bundled` feature, which compiles DuckDB from source and can exhaust RAM on small machines. To link a prebuilt `libduckdb` instead:

```bash
DUCKDB_DOWNLOAD_LIB=1 cargo build --no-default-features
```

That keeps the Rust build but skips the heavy bundled C++ compile step.

**Key scan options** (all have defaults; override only what you need):

| Flag | Default | Description |
|---|---|---|
| `--db` | `data/domains.duckdb` | DuckDB path |
| `--concurrency` | 500 / 250 / 150 / 300 / 200 | Parallel workers (scan/dns/tls/ports/subdomains) |
| `--connect-timeout` | `5s` | TCP connect timeout |
| `--request-timeout` | `20s` | Full HTTP request timeout |
| `--max-kbytes` | `128` | Body download cap (scan only) |
| `--limit-success N` | — | Stop scan after N HTTP-200 writes |
| `--rescan` | off | Re-scan already-completed rows (dns/tls/ports) |

See [SCHEMA.md](SCHEMA.md) for the full database schema.

---

## Research directions — digital sovereignty

The dataset makes visible structural patterns that are otherwise opaque. Current and planned analyses:

**DNS concentration**
→ Which providers control Swiss DNS? How many domains fail if a single nameserver operator goes offline? What fraction of the Swiss namespace depends on infrastructure physically or legally outside Switzerland?

**Foreign dependency mapping**
→ Classify nameserver operators by jurisdiction (CH / EU / US / other). Measure the share of `.ch` domains that ultimately resolve through non-Swiss infrastructure — a proxy for digital sovereignty exposure.

**Hub resilience**
Model cascading failure scenarios: remove the top-N DNS hubs, measure reachability loss across the graph. Identify the minimum set of providers whose failure would partition Swiss internet access.

**Longitudinal tracking**
→ Re-run the scrape periodically. Detect new domains, expired domains, nameserver migrations, and shifts in provider market share over time.

**Phishing and lookalike detection**
→ The full namespace enables detection of typosquat and look-alike domains targeting Swiss brands, banks, and government entities.

**SME digital exposure scoring**
→ Cross-reference DNS data with open-port scans, certificate expiry, and HTTP security headers to produce a per-domain risk score — useful for the attack surface intelligence.

---

## Stack

| Layer | Technology |
|---|---|
| Database | DuckDB |
| Web server | Bun |
| Scanner | Rust, tokio, reqwest, hickory-resolver, rustls |
| Data processing | Python (pandas, pyarrow), JavaScript (apache-arrow) |
| Visualization | Cosmograph (WebGL), Apache Arrow IPC |

---

[^1]: Raw data not published. Consider processed edges.arrow and nodes.arrow tables.
