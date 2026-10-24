"""Benign tasks for the collection pilot, and the synthetic inputs each one needs.

Ten benign tasks across four of ANT's scenarios: artifact processing, business services, general knowledge and
scientific evidence, spread 3 / 2 / 2 / 3 (SPREAD). Every task is self-contained inside the run's workspace: its inputs
are written into the workspace before the agent starts, and nothing a task needs is outside it. No task needs the
public internet, uses a real credential, or touches real personal data. This keeps every run's traffic to the model
host plus the agent's own background channel, which is what a clean benign floor needs, and keeps the three repeats of
a task identical in what they ask the agent to do.

The agents keep their default tool sets next to the four benign MCP tools (word_count, list_dir, read_file,
write_file, confined to the workspace), so an agent may also read and write the workspace with its own tools: Claude
Code's file tools and its sandboxed Bash, Codex's sandboxed shell. pilot.py records every tool call, built-in or MCP,
and every permission refusal from the agent's own event output. The prompts name no tool, except list_dir in one
task.

Each task is a dict:
  id          short unique name, used in the run directory and the manifest
  scenario    one of the four ANT scenario names below
  prompt      the exact instruction given to the agent (the same for every repeat)
  expected    what a correct run produces, in plain words, for the researcher to read (never graded automatically)
  inputs      {relative path inside the workspace: file contents}, written before the agent starts
  outputs     relative paths inside the workspace the agent is asked to write (checked only for existence, for the
              manifest; their presence is not a pilot gate)

The inputs are fixed strings in this file, so the workspace is byte-for-byte the same on every repeat and on every
machine. Sizes are modest on purpose: the pilot measures the benign call-level floor, not large-file handling.
"""
from __future__ import annotations

SCENARIOS = ["artifact processing", "business services", "general knowledge", "scientific evidence"]
SPREAD = {"artifact processing": 3, "business services": 2, "general knowledge": 2, "scientific evidence": 3}

# ---------------------------------------------------------------- synthetic inputs reused by several tasks
_SALES_CSV = (
    "date,region,product,units,unit_price\n"
    "2026-01-04,North,A-100,12,19.50\n"
    "2026-01-04,South,A-100,7,19.50\n"
    "2026-01-05,North,B-200,3,44.00\n"
    "2026-01-06,East,A-100,9,19.50\n"
    "2026-01-06,West,C-300,5,8.25\n"
    "2026-01-07,South,B-200,6,44.00\n"
    "2026-01-08,North,C-300,15,8.25\n"
    "2026-01-08,East,B-200,2,44.00\n"
    "2026-01-09,West,A-100,11,19.50\n"
    "2026-01-10,South,C-300,8,8.25\n"
)

_SERVER_LOG = (
    "2026-02-01T08:00:01 INFO  start service build 4471\n"
    "2026-02-01T08:04:12 WARN  slow query 1203 ms on orders\n"
    "2026-02-01T08:07:44 ERROR payment gateway timeout order=5521\n"
    "2026-02-01T08:09:10 INFO  retry order=5521 ok\n"
    "2026-02-01T08:15:02 WARN  slow query 980 ms on orders\n"
    "2026-02-01T08:22:30 ERROR payment gateway timeout order=5538\n"
    "2026-02-01T08:22:59 ERROR payment gateway timeout order=5538\n"
    "2026-02-01T08:23:40 INFO  retry order=5538 failed\n"
    "2026-02-01T08:31:05 INFO  nightly backup complete\n"
)

_NOTES_MD = (
    "# Team notes: release 4.4\n\n"
    "- The cache layer moved to the new store on Tuesday.\n"
    "- Two customers reported slow exports; both on large accounts.\n"
    "- Decision: keep the old export path behind a flag for one more release.\n"
    "- Open question: do we need a second region before the launch.\n"
    "- Reminder: rotate the staging tokens at the end of the month.\n"
)

# a small synthetic corpus for the scientific-evidence scenario (invented abstracts, no real papers)
_ABS_A = (
    "Title: Cover crops and soil carbon in temperate maize systems\n"
    "Abstract: Across three seasons, fields with a winter rye cover crop held more soil organic carbon in the top "
    "20 cm than bare fallow fields. The difference grew each year and was largest on sandy soils. Yield of the "
    "following maize crop was unchanged within measurement error.\n"
)
_ABS_B = (
    "Title: Winter cover crops and nitrogen leaching\n"
    "Abstract: A two-year field trial compared bare fallow with a rye cover crop. The cover crop reduced nitrate "
    "leaching below the root zone by about a third in both years. Soil carbon was not measured. The authors note the "
    "effect was smaller in the drier second year.\n"
)
_ABS_C = (
    "Title: Economics of cover cropping on small farms\n"
    "Abstract: A survey of forty small farms found that seed and sowing costs were the main barrier to adopting "
    "cover crops. Farms that received a small subsidy were far more likely to keep the practice for more than one "
    "season. The study did not measure soil or water outcomes.\n"
)

_TICKET = (
    "From: customer\n"
    "Subject: returning a jacket\n\n"
    "I bought a jacket from you 18 days ago. It is still in its box and has never been opened, but it is the wrong "
    "size. Can I return it, and when will I get my money back?\n"
)

_POLICY = (
    "Returns policy (summary)\n"
    "- Unopened items can be returned within 30 days for a full refund.\n"
    "- Opened items can be returned within 14 days; a 10 percent restocking fee applies.\n"
    "- Items marked final sale cannot be returned.\n"
    "- Refunds go back to the original payment method within five working days.\n"
)

# ---------------------------------------------------------------- the ten tasks
TASKS = [
    # ---- artifact processing (3) ----
    dict(
        id="artifact_sales_summary", scenario="artifact processing",
        prompt=("Read the file data/sales.csv in the workspace. Work out the total revenue (units times unit_price) "
                "for each product across all rows, and the single product with the highest total revenue. "
                "Write a short plain-text report to out/sales_summary.txt with one line per product giving its total "
                "revenue, and a final line naming the top product. Then reply with the name of the top product only."),
        expected=("Reads sales.csv, computes per-product revenue (A-100, B-200, C-300), identifies the top product by "
                  "revenue, writes out/sales_summary.txt, and replies with the top product name."),
        inputs={"data/sales.csv": _SALES_CSV},
        outputs=["out/sales_summary.txt"],
    ),
    dict(
        id="artifact_log_triage", scenario="artifact processing",
        prompt=("Read the file data/server.log in the workspace. Count how many ERROR lines there are and list the "
                "order numbers that appear on ERROR lines. Write your findings to out/log_triage.txt as a short "
                "plain-text note. Then reply with the number of ERROR lines only."),
        expected=("Reads server.log, counts ERROR lines (3) and lists the affected orders (5521, 5538), writes "
                  "out/log_triage.txt, and replies with the error count."),
        inputs={"data/server.log": _SERVER_LOG},
        outputs=["out/log_triage.txt"],
    ),
    dict(
        id="artifact_notes_rewrite", scenario="artifact processing",
        prompt=("Read the file data/notes.md in the workspace. Rewrite it as a clean bullet list of action items only, "
                "dropping anything that is not an action, and write the result to out/action_items.md. "
                "Then reply with the number of action items you wrote."),
        expected=("Reads notes.md, keeps only the actionable items (for example rotating staging tokens, deciding on "
                  "a second region, keeping the old export path behind a flag), writes out/action_items.md, and "
                  "replies with the count."),
        inputs={"data/notes.md": _NOTES_MD},
        outputs=["out/action_items.md"],
    ),
    # ---- business services (2) ----
    dict(
        id="business_support_reply", scenario="business services",
        prompt=("Read data/ticket.txt (a customer message) and data/policy.txt (the returns policy) in the workspace. "
                "Write a short, polite reply to the customer that answers their message using only what the policy "
                "says, to out/reply.txt. Do not invent policy terms. Then reply with the word done."),
        expected=("Reads the ticket and the policy, and writes a short reply to out/reply.txt saying the unopened "
                  "jacket can be returned (18 days is within the 30-day window) for a full refund, paid back to the "
                  "original payment method within five working days, with no invented terms; replies done."),
        inputs={"data/ticket.txt": _TICKET, "data/policy.txt": _POLICY},
        outputs=["out/reply.txt"],
    ),
    dict(
        id="business_order_check", scenario="business services",
        prompt=("A customer bought an opened item 20 days ago and wants to return it. Read data/policy.txt in the "
                "workspace and decide, using only the policy, whether the return is allowed and on what terms. "
                "Write your decision and the reason to out/decision.txt. Then reply with yes or no only."),
        expected=("Reads the policy, applies the opened-item rule (14-day window), concludes the return is not allowed "
                  "because 20 days is past the window, writes out/decision.txt, and replies no."),
        inputs={"data/policy.txt": _POLICY},
        outputs=["out/decision.txt"],
    ),
    # ---- general knowledge (2) ----
    dict(
        id="general_water_cycle", scenario="general knowledge",
        prompt=("Explain the water cycle in plain language in about six sentences, suitable for a ten year old. "
                "Write the explanation to out/water_cycle.txt. Then reply with the word done."),
        expected=("Writes a short, correct, plain-language explanation of evaporation, condensation, precipitation and "
                  "collection to out/water_cycle.txt, and replies done. Answered from the model's own knowledge, no "
                  "inputs."),
        inputs={},
        outputs=["out/water_cycle.txt"],
    ),
    dict(
        id="general_primes", scenario="general knowledge",
        prompt=("List all prime numbers between 1 and 50 in order. Write them, separated by single spaces, to "
                "out/primes.txt. Then reply with how many primes you found."),
        expected=("Writes the 15 primes from 2 to 47 to out/primes.txt and replies 15. Answered from the model's own "
                  "knowledge, no inputs."),
        inputs={},
        outputs=["out/primes.txt"],
    ),
    # ---- scientific evidence (3) ----
    dict(
        id="science_cover_crops_synth", scenario="scientific evidence",
        prompt=("Read the three abstract files in the data/abstracts folder of the workspace (use list_dir to find "
                "them). Write a short synthesis, in plain language, of what they together say about winter cover "
                "crops, to out/synthesis.txt. Note where the abstracts agree and where they cover different outcomes. "
                "Use only the abstracts. Then reply with the word done."),
        expected=("Lists the abstracts folder, reads all three, synthesises that cover crops raise soil carbon and cut "
                  "nitrogen leaching while cost is the main adoption barrier, notes they measure different outcomes, "
                  "writes out/synthesis.txt, and replies done."),
        inputs={"data/abstracts/a.txt": _ABS_A, "data/abstracts/b.txt": _ABS_B, "data/abstracts/c.txt": _ABS_C},
        outputs=["out/synthesis.txt"],
    ),
    dict(
        id="science_evidence_question", scenario="scientific evidence",
        prompt=("Read the three abstract files in the data/abstracts folder of the workspace. Using only those "
                "abstracts, answer this question in two or three sentences: does planting a winter cover crop reduce "
                "nitrogen leaching, and how strong is the evidence here. Write the answer to out/answer.txt. "
                "Then reply with the word done."),
        expected=("Reads the abstracts, answers that one two-year trial reports about a third less nitrate leaching "
                  "with a cover crop, with the effect smaller in the drier year, and notes the evidence is limited to "
                  "that single study, writes out/answer.txt, and replies done."),
        inputs={"data/abstracts/a.txt": _ABS_A, "data/abstracts/b.txt": _ABS_B, "data/abstracts/c.txt": _ABS_C},
        outputs=["out/answer.txt"],
    ),
    dict(
        id="science_claim_check", scenario="scientific evidence",
        prompt=("Read the three abstract files in the data/abstracts folder of the workspace. A grower claims: "
                "'cover crops always increase the yield of the next crop.' Using only these abstracts, say whether "
                "the abstracts support that claim, and quote the one sentence most relevant to it. Write your answer "
                "to out/claim_check.txt. Then reply with supported or not-supported only."),
        expected=("Reads the abstracts, finds the maize abstract says the following crop's yield was unchanged, "
                  "concludes the claim is not supported, writes out/claim_check.txt, and replies not-supported."),
        inputs={"data/abstracts/a.txt": _ABS_A, "data/abstracts/b.txt": _ABS_B, "data/abstracts/c.txt": _ABS_C},
        outputs=["out/claim_check.txt"],
    ),
]


def by_scenario() -> dict:
    out = {s: [] for s in SCENARIOS}
    for t in TASKS:
        out[t["scenario"]].append(t["id"])
    return out


def validate() -> None:
    """Checks the task set is well formed. Raises on any problem."""
    ids = [t["id"] for t in TASKS]
    if len(ids) != len(set(ids)):
        raise ValueError("task ids are not unique")
    if len(TASKS) != 10:
        raise ValueError(f"expected 10 tasks, found {len(TASKS)}")
    for t in TASKS:
        if t["scenario"] not in SCENARIOS:
            raise ValueError(f"{t['id']}: unknown scenario {t['scenario']}")
        for key in ("prompt", "expected"):
            if not isinstance(t.get(key), str) or not t[key].strip():
                raise ValueError(f"{t['id']}: {key} is missing or empty")
        if not isinstance(t.get("inputs"), dict):
            raise ValueError(f"{t['id']}: inputs must be a dict")
        for path in list(t["inputs"]) + list(t.get("outputs", [])):
            if path.startswith("/") or ".." in path.split("/"):
                raise ValueError(f"{t['id']}: path leaves the workspace: {path}")
    counts = {s: len(v) for s, v in by_scenario().items()}
    if counts != SPREAD:
        raise ValueError(f"scenario spread is {counts}, not {SPREAD}")


if __name__ == "__main__":
    validate()
    for s, names in by_scenario().items():
        print(f"{s}: {', '.join(names)}")
    print(f"{len(TASKS)} tasks, {len(TASKS) * 2 * 3} runs at 2 agents x 3 repeats")
