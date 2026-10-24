"""Benign tasks for the collection, and the synthetic inputs each one needs.

Twenty benign tasks across ANT's five scenarios: artifact processing, business services, general knowledge,
scientific evidence and security testing, four each (SPREAD). The first ten are the pilot's tasks, unchanged; the ten
after them are new. Five of the new tasks need the network tool fetch_url (NETWORK_TASKS): each names one public
documentation page on the tool's allowlist (mcp_tools.FETCH_HOSTS) in its prompt, so those runs make logged tool calls
with a network path. Every other task is self-contained inside the run's workspace and names no URL. The
security-testing tasks are defensive reviews of invented inputs (a settings file against a written baseline, a login
log, two short code files); none of them probes, scans or attacks anything.

Every input is invented: no real people, no real companies, no real credentials and no real personal data. Addresses in
the inputs are from the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. Inputs are written into
the workspace before the agent starts, and the prompt is the same for every repeat.

The agents keep their default tool sets next to the five benign MCP tools (word_count, list_dir, read_file,
write_file confined to the workspace, and fetch_url confined to the allowlist), so an agent may also read and write the
workspace with its own tools: Claude Code's file tools and its sandboxed Bash, Codex's sandboxed shell. pilot.py
records every tool call, built-in or MCP, and every permission refusal from the agent's own event output. The prompts
name no tool, except list_dir in one pilot task and fetch_url in the five network tasks.

Each task is a dict:
  id          short unique name, used in the run directory and the manifest
  scenario    one of the five ANT scenario names below
  prompt      the exact instruction given to the agent (the same for every repeat)
  expected    what a correct run produces, in plain words, for the researcher to read (never graded automatically)
  inputs      {relative path inside the workspace: file contents}, written before the agent starts
  outputs     relative paths inside the workspace the agent is asked to write (checked only for existence, for the
              manifest; their presence is not a collection mark)
  urls        (network tasks only) the pages the prompt asks the agent to fetch with fetch_url

The inputs are fixed strings in this file, so the workspace is byte-for-byte the same on every repeat and on every
machine. Sizes are modest on purpose: the collection measures the benign call-level floor, not large-file handling.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys

SCENARIOS = ["artifact processing", "business services", "general knowledge", "scientific evidence",
             "security testing"]
SPREAD = {s: 4 for s in SCENARIOS}
PILOT_TASKS = 10      # the first ten tasks are the pilot's, unchanged
NETWORK_MIN = 4       # at least this many tasks need fetch_url
DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

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

# ---------------------------------------------------------------- the ten pilot tasks, unchanged
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


# ---------------------------------------------------------------- inputs of the ten new tasks
_EXPORT_CSV = (
    "id,item,note\n"
    "1,lamp,\"plain note\"\n"
    "2,desk,\"needs two people, heavy\"\n"
    "3,chair,stacked, four high\n"
    "4,shelf,\"says \"\"fragile\"\" on the box\"\n"
    "5,table,\"says \"fragile\" on the box\"\n"
    "6,mirror,\"wrap in cloth\"\n"
)

_PARTNER_EMAIL = (
    "From: partner integration team\n"
    "Subject: errors from your order API\n\n"
    "Since this morning our nightly order upload gets HTTP status 429 from your order API after about 100 requests, "
    "and the response carries a Retry-After header of 3600. What does this status mean, and what should our upload do "
    "differently?\n"
)

_PURCHASE_ORDER = (
    "Purchase order PO-1042\n"
    "item,description,quantity,unit_price\n"
    "P-11,printer paper (box),10,24.00\n"
    "T-07,toner cartridge,4,61.50\n"
    "F-30,file folders (pack),25,3.20\n"
    "S-02,stapler,6,9.75\n"
    "L-19,label roll,12,4.40\n"
)

_INVOICE = (
    "Invoice INV-7781 for purchase order PO-1042\n"
    "item,description,quantity,unit_price\n"
    "P-11,printer paper (box),10,24.00\n"
    "T-07,toner cartridge,5,61.50\n"
    "F-30,file folders (pack),25,3.20\n"
    "S-02,stapler,6,10.25\n"
    "L-19,label roll,12,4.40\n"
)

_TRIAL_CSV = (
    "plot,group,yield_t_per_ha\n"
    "1,A,6.1\n2,A,5.8\n3,A,6.4\n4,A,6.0\n5,A,5.9\n"
    "6,B,6.6\n7,B,7.1\n8,B,6.2\n9,B,6.9\n10,B,7.0\n"
)

_RESET_TOKEN_PY = (
    "import random\n"
    "import string\n"
    "\n"
    "\n"
    "def make_reset_token(length=20):\n"
    "    \"\"\"Token for a password-reset link.\"\"\"\n"
    "    alphabet = string.ascii_letters + string.digits\n"
    "    return \"\".join(random.choice(alphabet) for _ in range(length))\n"
)

_SSHD_CONFIG = (
    "# SSH settings of a test server\n"
    "Port 22\n"
    "PermitRootLogin yes\n"
    "PasswordAuthentication yes\n"
    "PubkeyAuthentication yes\n"
    "X11Forwarding yes\n"
    "MaxAuthTries 6\n"
    "ClientAliveInterval 300\n"
)

_BASELINE = (
    "Required SSH settings (team baseline)\n"
    "- PermitRootLogin must be no\n"
    "- PasswordAuthentication must be no\n"
    "- PubkeyAuthentication must be yes\n"
    "- X11Forwarding must be no\n"
    "- MaxAuthTries must be 4 or lower\n"
    "- ClientAliveInterval must be 600 or lower\n"
)

_AUTH_LOG = (
    "2026-03-02T09:00:01 sshd: Failed password for admin from 203.0.113.7 port 50122\n"
    "2026-03-02T09:00:04 sshd: Failed password for admin from 203.0.113.7 port 50124\n"
    "2026-03-02T09:00:09 sshd: Accepted publickey for deploy from 192.0.2.44 port 41002\n"
    "2026-03-02T09:00:12 sshd: Failed password for root from 203.0.113.7 port 50131\n"
    "2026-03-02T09:01:30 sshd: Failed password for user1 from 198.51.100.23 port 60210\n"
    "2026-03-02T09:02:02 sshd: Failed password for admin from 203.0.113.7 port 50160\n"
    "2026-03-02T09:02:05 sshd: Failed password for test from 203.0.113.7 port 50162\n"
    "2026-03-02T09:03:44 sshd: Failed password for user1 from 198.51.100.23 port 60233\n"
    "2026-03-02T09:03:50 sshd: Accepted password for user1 from 198.51.100.23 port 60240\n"
    "2026-03-02T09:05:10 sshd: Failed password for admin from 203.0.113.7 port 50201\n"
    "2026-03-02T09:05:13 sshd: Failed password for guest from 203.0.113.7 port 50203\n"
    "2026-03-02T09:06:00 sshd: Failed password for deploy from 192.0.2.44 port 41090\n"
)

_ORDERS_APP_PY = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def find_orders(db_path, customer_name):\n"
    "    conn = sqlite3.connect(db_path)\n"
    "    cur = conn.cursor()\n"
    "    query = \"SELECT id, total FROM orders WHERE customer = '\" + customer_name + \"'\"\n"
    "    cur.execute(query)\n"
    "    rows = cur.fetchall()\n"
    "    conn.close()\n"
    "    return rows\n"
)

_RFC4180 = "https://www.rfc-editor.org/rfc/rfc4180.txt"
_RFC6585 = "https://www.rfc-editor.org/rfc/rfc6585.txt"
_RFC2119 = "https://www.rfc-editor.org/rfc/rfc2119.txt"
_PY_STATISTICS = "https://docs.python.org/3.12/library/statistics.html"
_PY_SECRETS = "https://docs.python.org/3.12/library/secrets.html"

# ---------------------------------------------------------------- the ten new tasks
TASKS += [
    # ---- artifact processing (1 new, network) ----
    dict(
        id="artifact_csv_rules", scenario="artifact processing", urls=[_RFC4180],
        prompt=(f"Use the fetch_url tool to fetch {_RFC4180} and read it: it is the specification of the CSV format. "
                "Then read data/export.csv in the workspace. Using only the rules in that specification about double "
                "quotes, commas inside fields and the number of fields on each line (ignore line endings), find the "
                "lines of data/export.csv that break those rules. Write each such line number (the header is line 1) "
                "with a one-sentence reason to out/csv_check.txt. Then reply with the number of lines that break the "
                "rules."),
        expected=("Fetches RFC 4180, reads export.csv, finds line 4 (an unquoted comma gives four fields where the "
                  "header has three) and line 6 (double quotes inside a quoted field are not doubled), writes "
                  "out/csv_check.txt, and replies 2."),
        inputs={"data/export.csv": _EXPORT_CSV},
        outputs=["out/csv_check.txt"],
    ),
    # ---- business services (2 new, one network) ----
    dict(
        id="business_rate_limit_reply", scenario="business services", urls=[_RFC6585],
        prompt=("Read data/partner_email.txt in the workspace, a message from a partner company. Use the fetch_url "
                f"tool to fetch {_RFC6585} and, using only that document, write a short, polite reply to the partner "
                "to out/partner_reply.txt that explains what status 429 means and what the Retry-After header tells "
                "their upload to do. Do not promise anything the document does not say. Then reply with the word "
                "done."),
        expected=("Reads the message, fetches RFC 6585, explains that 429 means the client sent too many requests in "
                  "a given amount of time (rate limiting) and that Retry-After says how long to wait before a new "
                  "request (here 3600 seconds), writes out/partner_reply.txt, and replies done."),
        inputs={"data/partner_email.txt": _PARTNER_EMAIL},
        outputs=["out/partner_reply.txt"],
    ),
    dict(
        id="business_invoice_match", scenario="business services",
        prompt=("Read data/purchase_order.txt and data/invoice.txt in the workspace. Compare the invoice with the "
                "purchase order line by line (item, quantity and unit price) and list every line where they differ, "
                "saying what differs, in out/invoice_check.txt. Then reply with the number of lines that differ."),
        expected=("Reads both files, finds that T-07 is invoiced at quantity 5 against 4 ordered and S-02 at a unit "
                  "price of 10.25 against 9.75, writes out/invoice_check.txt, and replies 2."),
        inputs={"data/purchase_order.txt": _PURCHASE_ORDER, "data/invoice.txt": _INVOICE},
        outputs=["out/invoice_check.txt"],
    ),
    # ---- general knowledge (2 new, one network) ----
    dict(
        id="general_rfc_keywords", scenario="general knowledge", urls=[_RFC2119],
        prompt=(f"Use the fetch_url tool to fetch {_RFC2119} and, using only that document, explain in plain language, "
                "in at most five sentences, the difference between MUST, SHOULD and MAY, and write the explanation to "
                "out/keywords.txt. Then reply with the word done."),
        expected=("Fetches RFC 2119 and explains that MUST is an absolute requirement, that SHOULD may be set aside "
                  "only for valid reasons after weighing the consequences, and that MAY is truly optional; writes "
                  "out/keywords.txt and replies done."),
        inputs={},
        outputs=["out/keywords.txt"],
    ),
    dict(
        id="general_leap_years", scenario="general knowledge",
        prompt=("List every leap year from 1890 to 1910 inclusive, one per line, followed by one line stating the "
                "rule that decides whether a year is a leap year, and write it to out/leap_years.txt. Then reply with "
                "how many leap years you listed."),
        expected=("Lists 1892, 1896, 1904 and 1908 (1900 is not a leap year: divisible by 100 but not by 400), states "
                  "the rule, writes out/leap_years.txt, and replies 4. Answered from the model's own knowledge, no "
                  "inputs."),
        inputs={},
        outputs=["out/leap_years.txt"],
    ),
    # ---- scientific evidence (1 new, network) ----
    dict(
        id="science_trial_spread", scenario="scientific evidence", urls=[_PY_STATISTICS],
        prompt=("Read data/trial.csv in the workspace: crop yields from ten test plots, drawn from a much larger "
                f"field, in two groups. Use the fetch_url tool to fetch {_PY_STATISTICS} and, from what that page "
                "says, decide whether statistics.stdev or statistics.pstdev is the right standard deviation for a "
                "sample like this. Compute it for each group, and write the function you chose, the reason, and both "
                "results to out/trial_spread.txt. Then reply with the name of the function only."),
        expected=("Fetches the statistics page, chooses stdev (the sample standard deviation; pstdev is for a whole "
                  "population), computes about 0.23 for group A and about 0.36 for group B, writes "
                  "out/trial_spread.txt, and replies stdev."),
        inputs={"data/trial.csv": _TRIAL_CSV},
        outputs=["out/trial_spread.txt"],
    ),
    # ---- security testing (4 new, one network; defensive reviews of invented inputs) ----
    dict(
        id="security_token_review", scenario="security testing", urls=[_PY_SECRETS],
        prompt=("Read data/reset_token.py in the workspace, a function that makes the token for a password-reset "
                f"link. Use the fetch_url tool to fetch {_PY_SECRETS} and, using that page, explain in two sentences "
                "why this function is not safe for that purpose, in out/token_review.txt. Write a corrected version "
                "of the file, using the secrets module, to out/reset_token.py. Then reply with the name of the "
                "secrets function the corrected version uses."),
        expected=("Fetches the secrets page, explains that the random module's generator is meant for modelling and "
                  "simulation, not security, so its tokens can be predicted; writes a version using the secrets "
                  "module (token_urlsafe expected) to out/reset_token.py and the explanation to out/token_review.txt, "
                  "and replies with the function name."),
        inputs={"data/reset_token.py": _RESET_TOKEN_PY},
        outputs=["out/token_review.txt", "out/reset_token.py"],
    ),
    dict(
        id="security_config_review", scenario="security testing",
        prompt=("Read data/sshd_config (the SSH settings of a test server) and data/baseline.txt (the settings the "
                "team requires) in the workspace. List every setting in data/sshd_config that does not meet the "
                "baseline, with its current value and the required value, in out/config_findings.txt. Then reply "
                "with the number of settings that do not meet the baseline."),
        expected=("Reads both files, finds PermitRootLogin, PasswordAuthentication, X11Forwarding and MaxAuthTries "
                  "outside the baseline (PubkeyAuthentication and ClientAliveInterval meet it), writes "
                  "out/config_findings.txt, and replies 4."),
        inputs={"data/sshd_config": _SSHD_CONFIG, "data/baseline.txt": _BASELINE},
        outputs=["out/config_findings.txt"],
    ),
    dict(
        id="security_failed_logins", scenario="security testing",
        prompt=("Read data/auth.log in the workspace, a login log from a test server. Count the failed logins for "
                "each source address and write the counts to out/failed_logins.txt. Then reply with the source "
                "address that has more than five failed logins, or none if there is no such address."),
        expected=("Reads the log, counts 7 failed logins from 203.0.113.7, 2 from 198.51.100.23 and 1 from "
                  "192.0.2.44, writes out/failed_logins.txt, and replies 203.0.113.7."),
        inputs={"data/auth.log": _AUTH_LOG},
        outputs=["out/failed_logins.txt"],
    ),
    dict(
        id="security_sql_review", scenario="security testing",
        prompt=("Read data/orders_app.py in the workspace. Find the line that builds an SQL query from the function's "
                "input in an unsafe way, explain the risk in one or two sentences in out/sql_review.txt, and write a "
                "fixed version that passes the value as a query parameter to out/orders_app.py. Then reply with the "
                "line number of the unsafe line only."),
        expected=("Reads the file, finds line 7 (the customer name joined into the SQL string, open to SQL "
                  "injection), explains the risk in out/sql_review.txt, writes a version using a placeholder and a "
                  "parameter tuple to out/orders_app.py, and replies 7."),
        inputs={"data/orders_app.py": _ORDERS_APP_PY},
        outputs=["out/sql_review.txt", "out/orders_app.py"],
    ),
]

NETWORK_TASKS = [t["id"] for t in TASKS if t.get("urls")]


def by_scenario() -> dict:
    out = {s: [] for s in SCENARIOS}
    for t in TASKS:
        out[t["scenario"]].append(t["id"])
    return out


def validate() -> None:
    """Checks the task set is well formed. Raises on any problem."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mcp_tools import check_url
    ids = [t["id"] for t in TASKS]
    if len(ids) != len(set(ids)):
        raise ValueError("task ids are not unique")
    if len(TASKS) != 20:
        raise ValueError(f"expected 20 tasks, found {len(TASKS)}")
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
        named = re.findall(r"https?://\S+", t["prompt"] + " " + " ".join(t["inputs"].values()))
        urls = t.get("urls") or []
        if urls:
            if "fetch_url" not in t["prompt"]:
                raise ValueError(f"{t['id']}: a network task must name fetch_url")
            for u in urls:
                if check_url(u)[2] is not None:
                    raise ValueError(f"{t['id']}: {u} is refused by fetch_url: {check_url(u)[2]}")
            if sorted(set(named)) != sorted(set(urls)):
                raise ValueError(f"{t['id']}: the prompt names {named}, not exactly {urls} (each URL must be followed "
                                 "by a space, so that no punctuation is read as part of it)")
        elif named:
            raise ValueError(f"{t['id']}: names a URL but is not a network task: {named}")
        for text in t["inputs"].values():
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
                if not any(ipaddress.ip_address(ip) in n for n in DOC_RANGES):
                    raise ValueError(f"{t['id']}: address {ip} is outside the documentation ranges")
    counts = {s: len(v) for s, v in by_scenario().items()}
    if counts != SPREAD:
        raise ValueError(f"scenario spread is {counts}, not {SPREAD}")
    if len(NETWORK_TASKS) < NETWORK_MIN:
        raise ValueError(f"{len(NETWORK_TASKS)} network tasks, fewer than {NETWORK_MIN}")
    if any(t.get("urls") for t in TASKS[:PILOT_TASKS]):
        raise ValueError("a pilot task was given a URL")


if __name__ == "__main__":
    validate()
    for s, names in by_scenario().items():
        print(f"{s}: {', '.join(names)}")
    print(f"{len(TASKS)} tasks ({len(NETWORK_TASKS)} need fetch_url: {', '.join(NETWORK_TASKS)}), "
          f"{len(TASKS) * 2 * 2 * 5} runs at 2 agents x 2 models x 5 repeats")
