# Module 08 — Sector Classification

Domains are classified into industry sectors using keyword heuristics applied to the domain name and page title (combined, lowercased). The first matching rule wins; rules are ordered from most specific to least specific.

## Priority Rules (evaluated first)

| Pattern | Sector | Subsector | Confidence | Notes |
|---------|--------|-----------|-----------|-------|
| `domain == admin.ch` or ends with `.admin.ch` | government | — | 0.95 | Federal administration |
| domain ends with a cantonal suffix (see below) | government | — | 0.90 | 26 cantonal domains |

### Cantonal Domains

`bs.ch` `zh.ch` `be.ch` `ag.ch` `sg.ch` `lu.ch` `ti.ch` `vd.ch` `ge.ch` `vs.ch` `fr.ch` `so.ch` `tg.ch` `gr.ch` `ne.ch` `sz.ch` `zg.ch` `gl.ch` `nw.ch` `ow.ch` `ur.ch` `ai.ch` `ar.ch` `sh.ch` `bl.ch` `ju.ch`

## Keyword Rules (ordered, first match wins)

| Keyword | Sector | Subsector | Confidence |
|---------|--------|-----------|-----------|
| `kantonalbank` | finance | banking | 0.90 |
| `sparkasse` | finance | banking | 0.80 |
| `bank` | finance | banking | 0.70 |
| `credit` | finance | banking | 0.65 |
| `finanz` | finance | banking | 0.65 |
| `versicherung` | finance | insurance | 0.75 |
| `insurance` | finance | insurance | 0.70 |
| `pharma` | pharma | — | 0.70 |
| `biotech` | pharma | — | 0.70 |
| `klinik` | healthcare | — | 0.75 |
| `spital` | healthcare | — | 0.80 |
| `hospital` | healthcare | — | 0.75 |
| `medizin` | healthcare | — | 0.60 |
| `anwalt` | legal | — | 0.65 |
| `advokat` | legal | — | 0.75 |
| `notariat` | legal | — | 0.80 |
| `law` | legal | — | 0.50 |
| `schule` | education | — | 0.65 |
| `hochschule` | education | — | 0.80 |
| `universitaet` | education | — | 0.85 |
| `eth.ch` | education | — | 0.95 |
| `shop` | retail | — | 0.50 |
| `boutique` | retail | — | 0.55 |
| `news` | media | — | 0.50 |
| `zeitung` | media | — | 0.70 |
| `gemeinde` | government | — | 0.80 |
| `kanton` | government | — | 0.80 |
| `admin.ch` | government | — | 0.95 |

## Matching Logic

- The domain name and page `<title>` are concatenated and lowercased before matching.
- Keywords are checked as substrings (e.g. `bank` matches `postbank`, `bankverein`).
- The government priority rules (exact/suffix domain checks) run before keyword rules.
- Domains that match no rule are left unclassified (`sector = NULL`).
- Confidence scores are stored in `domain_classification.confidence` and used to weight sector benchmarks.
