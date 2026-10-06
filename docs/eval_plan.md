# Evaluation plan: does failure analysis depend on its historical records?

Status: draft for review. No evaluation has been run on the CodeGuard+ test scenarios.

## 1. Question and hypotheses

Failure analysis is only as strong as its historical records. The KG covers 16 of the 42 CWEs in CodeGuard+, so this
prototype is limited mainly by coverage. We test that claim directly.

- **H1 (coverage).** The harness's gain over the baseline is larger on scenarios whose CWE the KG covers than on
  scenarios whose CWE it does not.
- **H2 (draft-first).** With retrieval held identical, analysing a draft (v2) beats analysing before any code (v1).
  Exploratory: nothing so far shows the draft helps.
- **Downstream (not part of the main test).** Within covered CWEs, how much does depth in the scenario's language
  matter (e.g. CWE-611 has C/C++ examples but no Python ones)?

A result of "no gain anywhere" is informative too: it separates "the idea does not work" from "the KG is too small".

## 2. Arms (three, same agent model)

| Arm | What the agent sees |
|---|---|
| baseline | the scenario prompt only |
| v1 | prompt + FMEA/FTA made **before any code**, from the task text |
| v2 | prompt + the model's **draft** + FMEA/FTA made by attacking the draft |

v1 and v2 are identical except for the draft, so v2 vs v1 isolates the value of draft-first.

Held identical across v1 and v2:
- retrieval: one task-level query, no API matching, `top_k=3` candidates;
- one shared FMEA rules block (below);
- models: `gpt-4o-mini` for the agent and for the harness LLM; same sampling; same sandbox; same limits.

The only differences: v2 also receives the draft (and the list of APIs the draft calls, as context, not for retrieval)
and its FMEA components must name calls in that draft.

## 3. Harness changes before the evaluation (made once, then frozen)

1. **Remove v3.** Commit the current state first (v3, the recall scripts, results) so the recall experiment stays
   reproducible at that commit; then delete `run_v3`, `gather_components`, `split_components`, `Component`,
   `Knowledge.via` and their tests. `--harness-version` accepts 1 or 2 only.
2. **v2 retrieval no longer uses the draft's APIs.** (The earlier 27-run grid used v2 *with* APIs; record the commit.)
3. **Tighten the FMEA prompt, shared by v1 and v2:**
   - Retrieved examples are *candidates* from other code: they may not apply, and the analysis must say whether each one
     fits the operation (`retrieval_fit`, in both versions).
   - Controls must not reject valid inputs. Each control comes with a **happy-path check** (an input that must still
     work) next to the **attack check**. New FailureMode field `valid_check`; FTA action `verification` must contain both.
   - Controls name the operation and the concrete guard: "before `<operation>`, verify `<property>` using `<API or
     condition>`; reject otherwise." Rendered into the problem statement as "Control ... / Must still accept ...".
4. Update tests (prompt contents, the new field, rendering). Then **commit and tag `eval-freeze`**.

Rule: nothing in the harness, prompts or config changes after the tag. A real bug means fix it, re-run all arms on all
scenarios, and report that it happened.

## 4. Scenarios: 30 total, 15 covered + 15 uncovered

Pool, from the 103 local CodeGuard+ base scenarios (the clone has no perturbed set):

| Bucket (CWE in the scenario's language) | Python | C |
|---|---|---|
| Covered: >= 5 KG examples for that CWE and language | 25 | 20 |
| Uncovered: CWE absent from the KG | 33 | 12 |
| Excluded from the 30: CWE present but language absent (7 py), shallow 1-4 examples (6 py) | 13 | 0 |

- "Covered" is defined by KG contents, **not** by whether retrieval succeeded, so the result is not built in. Retrieval
  success is measured later as a mediator.
- Match the two groups on language and rough CWE type (injection, memory, crypto/auth, file/path, deserialization/parsing).
  Within a matched pair or stratum choose by a fixed seeded rule, **blind to any outcome**.
- Log for each scenario: KG depth for its CWE and language, CWE, language, and bucket.
- The excluded buckets are the downstream study ("CWE present but language absent" and "shallow"); they are not in the main 30.
- **Contamination check** on the 15 covered scenarios: nearest-neighbour similarity of the prompt code to the KG's
  code, so near-duplicates are found before running. Replace any near-duplicate with another from the same stratum.
- If CodeQL's C/C++ extraction does not work on this machine (step 5), use Python only: 15 of 25 covered and 15 of 33
  uncovered, matched on CWE type. That keeps the comparison valid and avoids the C build.

## 5. Evaluator and adapter

1. Install CodeQL (`setup_codeql.sh`) and run CodeGuard+'s stock `codeql_eval.py` and `correctness_eval.py` on one or
   two scenarios with a known outcome. This is a gate: no agent runs until scoring works.
2. Adapter, identical for all arms:
   - The scenario's prefix (file context + function stub) is the task context. Query text for the harness is an LLM
     summary of the prefix (as in the recall experiment).
   - The agent completes the function in the sandboxed workdir; the adapter extracts the completed code into
     CodeGuard+'s directory layout.
   - 10 samples per scenario (CodeGuard+ default).
3. Per-run caps: step limit 25, cost limit $0.30. Everything is logged: trajectory, problem statement, analysis, cost.

## 6. Run

3 arms x 30 scenarios x 10 samples = 900 agent runs. Estimated cost $5-9 at `gpt-4o-mini` prices, plus the harness
calls (v1: 2 per task; v2: 3 per task, plus the summary call in both).
Run order is interleaved by scenario so an outage affects all arms equally. Resumable.

## 7. Analysis (fixed in advance)

- **Primary metric:** per-scenario sec-pass@1 = fraction of the 10 samples that are functionally correct *and* secure
  (CodeQL clean). Also report functional pass alone (to expose over-restriction) and secure-given-functional.
- **H1:** per scenario, gain = harness arm minus baseline. Report mean gain in the covered group and in the uncovered
  group, and the difference between groups, with a bootstrap 95% interval over scenarios. Do it separately for v1 and v2.
- **H2:** v2 minus v1 per scenario, overall and by group, with a bootstrap interval.
- **Supports H1** if the covered-group gain is clearly larger than the uncovered-group gain (target: ~20 points) and
  the interval on the difference excludes zero. With 15 scenarios per group only effects of about that size are
  detectable; smaller effects will be reported as inconclusive, not as absent.
- **Mediators and diagnostics:** was the gold CWE retrieved (and at what rank); KG depth vs gain; scenarios at floor or
  ceiling for the baseline (reported, not dropped); harness cost and token overhead.

## 8. Limitations to state

- Small test set (15 per group), one model (`gpt-4o-mini`), one run configuration; interval estimates are wide.
- The design choices to drop API matching and to use a single task-level query were informed by a recall comparison
  run on all 103 local scenarios, which include the 30. They are design choices, not tuned parameters, but the overlap
  is disclosed. The FMEA tightening was motivated by an earlier pilot on three hand-written tasks, not CodeGuard+.
- KG source data may overlap CodeGuard+ prompts; checked only for the 15 covered scenarios.
- Recall measured on LLM-written summaries; the real harness input may differ.

## 9. Order of work

1. Review this plan.
2. Commit the current state, then remove v3 (section 3, step 1).
3. Tighten the FMEA and drop APIs from v2 retrieval; tests; commit; tag `eval-freeze`.
4. Select and log the 30 scenarios, including the contamination check. **Stop for review.**
5. CodeQL setup and the stock-scoring gate.
6. Adapter, then a 2-scenario dry run on all three arms (cost cap, output format) with scenarios outside the 30.
7. Full run, then scoring and write-up.
