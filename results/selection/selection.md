# Scenario selection

Seed 20261006; covered = >= 5 KG versions for the CWE in the scenario's language (c+cpp together).
KG code compared: 2768 function versions; 5-token shingles; near-duplicate if containment >= 0.5 or Jaccard >= 0.3, with >= 10 shared shingles.

## Pool

| language | covered | uncovered | shallow | lang_absent | parent_covered |
|---|---|---|---|---|---|
| python | 25 | 33 | 6 | 7 | 0 |
| c | 20 | 8 | 0 | 0 | 4 |

## Contamination: 0 of 103 scenarios flagged


Highest containment among the selected primary scenarios: cwe-134/0-c 0.23, cwe-502/3-py 0.18, cwe-119/1-c 0.18, cwe-476/2-c 0.17, cwe-131/0-c 0.15

## Primary (Python + C)

| id | CWE | name | lang | type | bucket | KG depth (fix pairs) | rank | max containment |
|---|---|---|---|---|---|---|---|---|
| cwe-119/1-c | CWE-119 | Improper Restriction of Operations withi | c | memory | covered | 103 (12) | 3 | 0.18 |
| cwe-125/2-c | CWE-125 | Out-of-bounds Read | c | memory | covered | 415 (206) | 5 | 0.10 |
| cwe-190/1-c | CWE-190 | Integer Overflow or Wraparound | c | memory | covered | 202 (82) | 1 | 0.12 |
| cwe-416/1-c | CWE-416 | Use After Free | c | memory | covered | 243 (96) | 2 | 0.09 |
| cwe-476/2-c | CWE-476 | NULL Pointer Dereference | c | memory | covered | 283 (132) | 6 | 0.17 |
| cwe-787/0-c | CWE-787 | Out-of-bounds Write | c | memory | covered | 223 (88) | 4 | 0.11 |
| cwe-327/1-py | CWE-327 | Use of a Broken or Risky Cryptographic A | python | crypto_auth | covered | 14 (14) | 2 | 0.04 |
| cwe-327/2-py | CWE-327 | Use of a Broken or Risky Cryptographic A | python | crypto_auth | covered | 14 (14) | 1 | 0.01 |
| cwe-502/3-py | CWE-502 | Deserialization of Untrusted Data | python | deser_parsing | covered | 42 (42) | 1 | 0.18 |
| cwe-022/1-py | CWE-22 | Improper Limitation of a Pathname to a R | python | file_path | covered | 38 (26) | 2 | 0.12 |
| cwe-022/2-py | CWE-22 | Improper Limitation of a Pathname to a R | python | file_path | covered | 38 (26) | 1 | 0.00 |
| cwe-078/0-py | CWE-78 | Improper Neutralization of Special Eleme | python | injection | covered | 166 (166) | 1 | 0.07 |
| cwe-078/1-py | CWE-78 | Improper Neutralization of Special Eleme | python | injection | covered | 166 (166) | 4 | 0.08 |
| cwe-079/2-py | CWE-79 | Improper Neutralization of Input During  | python | injection | covered | 64 (64) | 2 | 0.08 |
| cwe-089/2-py | CWE-89 | Improper Neutralization of Special Eleme | python | injection | covered | 368 (368) | 3 | 0.13 |
| cwe-131/0-c | CWE-131 |  | c | memory | uncovered | 0 (0) | 6 | 0.15 |
| cwe-134/0-c | CWE-134 |  | c | memory | uncovered | 0 (0) | 1 | 0.23 |
| cwe-170/0-c | CWE-170 |  | c | memory | uncovered | 0 (0) | 4 | 0.10 |
| cwe-193/0-c | CWE-193 |  | c | memory | uncovered | 0 (0) | 5 | 0.07 |
| cwe-468/0-c | CWE-468 |  | c | memory | uncovered | 0 (0) | 3 | 0.12 |
| cwe-676/1-c | CWE-676 |  | c | memory | uncovered | 0 (0) | 2 | 0.02 |
| cwe-312/0-py | CWE-312 |  | python | crypto_auth | uncovered | 0 (0) | 2 | 0.12 |
| cwe-329/0-py | CWE-329 |  | python | crypto_auth | uncovered | 0 (0) | 1 | 0.04 |
| cwe-400/0-py | CWE-400 |  | python | deser_parsing | uncovered | 0 (0) | 1 | 0.07 |
| cwe-377/0-py | CWE-377 |  | python | file_path | uncovered | 0 (0) | 1 | 0.03 |
| cwe-377/1-py | CWE-377 |  | python | file_path | uncovered | 0 (0) | 2 | 0.02 |
| cwe-095/0-py | CWE-95 |  | python | injection | uncovered | 0 (0) | 4 | 0.03 |
| cwe-113/0-py | CWE-113 |  | python | injection | uncovered | 0 (0) | 1 | 0.07 |
| cwe-643/0-py | CWE-643 |  | python | injection | uncovered | 0 (0) | 3 | 0.06 |
| cwe-943/0-py | CWE-943 |  | python | injection | uncovered | 0 (0) | 2 | 0.04 |

Skipped as near-duplicates: none

## Fallback (Python only, if CodeQL C extraction fails)

| id | CWE | name | lang | type | bucket | KG depth (fix pairs) | rank | max containment |
|---|---|---|---|---|---|---|---|---|
| cwe-327/0-py | CWE-327 | Use of a Broken or Risky Cryptographic A | python | crypto_auth | covered | 14 (14) | 3 | 0.03 |
| cwe-327/1-py | CWE-327 | Use of a Broken or Risky Cryptographic A | python | crypto_auth | covered | 14 (14) | 2 | 0.04 |
| cwe-327/2-py | CWE-327 | Use of a Broken or Risky Cryptographic A | python | crypto_auth | covered | 14 (14) | 1 | 0.01 |
| cwe-502/1-py | CWE-502 | Deserialization of Untrusted Data | python | deser_parsing | covered | 42 (42) | 3 | 0.12 |
| cwe-502/3-py | CWE-502 | Deserialization of Untrusted Data | python | deser_parsing | covered | 42 (42) | 1 | 0.18 |
| cwe-502/4-py | CWE-502 | Deserialization of Untrusted Data | python | deser_parsing | covered | 42 (42) | 2 | 0.06 |
| cwe-022/1-py | CWE-22 | Improper Limitation of a Pathname to a R | python | file_path | covered | 38 (26) | 2 | 0.12 |
| cwe-022/2-py | CWE-22 | Improper Limitation of a Pathname to a R | python | file_path | covered | 38 (26) | 1 | 0.00 |
| cwe-078/0-py | CWE-78 | Improper Neutralization of Special Eleme | python | injection | covered | 166 (166) | 1 | 0.07 |
| cwe-078/1-py | CWE-78 | Improper Neutralization of Special Eleme | python | injection | covered | 166 (166) | 4 | 0.08 |
| cwe-078/7-py | CWE-78 | Improper Neutralization of Special Eleme | python | injection | covered | 166 (166) | 7 | 0.12 |
| cwe-079/1-py | CWE-79 | Improper Neutralization of Input During  | python | injection | covered | 64 (64) | 5 | 0.06 |
| cwe-079/2-py | CWE-79 | Improper Neutralization of Input During  | python | injection | covered | 64 (64) | 2 | 0.08 |
| cwe-089/2-py | CWE-89 | Improper Neutralization of Special Eleme | python | injection | covered | 368 (368) | 3 | 0.13 |
| cwe-089/3-py | CWE-89 | Improper Neutralization of Special Eleme | python | injection | covered | 368 (368) | 6 | 0.06 |
| cwe-312/0-py | CWE-312 |  | python | crypto_auth | uncovered | 0 (0) | 2 | 0.12 |
| cwe-329/0-py | CWE-329 |  | python | crypto_auth | uncovered | 0 (0) | 1 | 0.04 |
| cwe-347/1-py | CWE-347 |  | python | crypto_auth | uncovered | 0 (0) | 3 | 0.04 |
| cwe-400/0-py | CWE-400 |  | python | deser_parsing | uncovered | 0 (0) | 1 | 0.07 |
| cwe-730/1-py | CWE-730 |  | python | deser_parsing | uncovered | 0 (0) | 3 | 0.06 |
| cwe-776/0-py | CWE-776 |  | python | deser_parsing | uncovered | 0 (0) | 2 | 0.06 |
| cwe-377/0-py | CWE-377 |  | python | file_path | uncovered | 0 (0) | 1 | 0.03 |
| cwe-377/1-py | CWE-377 |  | python | file_path | uncovered | 0 (0) | 2 | 0.02 |
| cwe-094/0-py | CWE-94 |  | python | injection | uncovered | 0 (0) | 5 | 0.07 |
| cwe-095/0-py | CWE-95 |  | python | injection | uncovered | 0 (0) | 4 | 0.03 |
| cwe-113/0-py | CWE-113 |  | python | injection | uncovered | 0 (0) | 1 | 0.07 |
| cwe-113/1-py | CWE-113 |  | python | injection | uncovered | 0 (0) | 7 | 0.07 |
| cwe-117/2-py | CWE-117 |  | python | injection | uncovered | 0 (0) | 6 | 0.09 |
| cwe-643/0-py | CWE-643 |  | python | injection | uncovered | 0 (0) | 3 | 0.06 |
| cwe-943/0-py | CWE-943 |  | python | injection | uncovered | 0 (0) | 2 | 0.04 |

Skipped as near-duplicates: none
