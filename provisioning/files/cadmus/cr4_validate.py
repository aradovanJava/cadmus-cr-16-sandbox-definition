#!/usr/bin/env python3
"""
CADMUS-CR-16 :: CR4 validation — pipeline, exploit regression, release gate

    python3 cr4_validate.py --session <id> --level all
    python3 cr4_validate.py --session <id> --level E2
    python3 cr4_validate.py --session <id> --level E2 --no-run

DESIGN NOTE
-----------
E1 parses a workflow; E3 checks an evidence bundle. Both are structural.
E2 is not: it EXECUTES the scenario pack against the participant's build. A
pipeline that is green while an exploit still succeeds has validated nothing,
so E2 is the mandatory gate for this exercise.

The other thing E2 enforces is that participant-authored scenarios assert on
BEHAVIOUR rather than on source content. A scenario that greps for
android:exported="false" is satisfied by a comment; one that sends the Intent
and observes the refusal is not.
"""

import argparse
import json
import os
import re
import subprocess
import sys

# Revision 2 (CR-16 sandbox): defaults follow the sandbox account.
PROJECT = os.environ.get("CR4_PROJECT", os.path.expanduser("~/vulnbank"))
SESSION_DIR = os.environ.get("CR_SESSION_DIR", os.path.expanduser("~/cr-session"))
WORKFLOW = os.path.join(PROJECT, ".github", "workflows", "security.yml")
EXPLOITS = os.path.join(PROJECT, "exploits")

POINTS = {"E1": 150, "E2": 200, "E3": 150}
MANDATORY_SCENARIOS = ["EX-01", "EX-02", "EX-03", "EX-04", "EX-05", "EX-06"]


def sh(cmd, timeout=600, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd or PROJECT)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def sfile(session, name):
    return os.path.join(SESSION_DIR, session, name)


class Result:
    def __init__(self, level):
        self.level = level
        self.checks = []

    def check(self, name, ok, guidance=""):
        self.checks.append((name, bool(ok), guidance))

    @property
    def passed(self):
        return all(ok for _, ok, _ in self.checks)


# ------------------------------------------------------------------ E1
def e1(session):
    """Pipeline construction."""
    r = Result("E1")
    wf = read(WORKFLOW)
    r.check("Workflow file present at .github/workflows/security.yml", bool(wf.strip()),
            "Create the workflow before validating E1")
    if not wf:
        return r

    flat = re.sub(r"\s+", " ", wf)

    # triggers
    r.check("Triggered on pull_request", "pull_request:" in wf)
    r.check("Triggered on push to main", re.search(r"push:.*branches", flat) is not None)
    r.check("SCHEDULED trigger present", "schedule:" in wf and "cron" in wf,
            "Every other trigger fires when code changes. Most dependency risk arrives "
            "when an advisory is published against code that has not changed")

    # the four jobs
    jobs = {
        "secret detection": r"gitleaks|trufflehog|secret[-_]?scan|detect[-_]secrets",
        "static analysis": r"sonar|semgrep|codeql",
        "composition analysis": r"dependencycheck|dependency-check|snyk|owasp",
        "SBOM generation": r"cyclonedx|cyclonedxBom|spdx|sbom",
    }
    for label, pat in jobs.items():
        r.check(f"Job present: {label}", re.search(pat, wf, re.I) is not None,
                f"no step matching {label} found in the workflow")

    # enforce vs report
    r.check("Static analysis waits for the quality gate result",
            re.search(r"qualitygate\.wait\s*=\s*true|quality[-_]?gate.*wait", wf, re.I) is not None,
            "Without waiting for the gate, the job succeeds regardless of the result. "
            "That is a pipeline that reports, not one that enforces")

    # SBOM retained
    r.check("SBOM retained as a build artefact",
            re.search(r"upload-artifact", wf, re.I) is not None,
            "The SBOM must outlive the build; you cannot triage a release without it")
    m = re.search(r"retention-days:\s*(\d+)", wf)
    r.check("Artefact retention suited to a mobile release lifetime",
            bool(m) and int(m.group(1)) >= 180,
            "Old versions keep running on devices you cannot reach. The platform "
            "default is far too short for a mobile release")

    # ordering: secrets first
    order = [(m.start(), m.group(0)) for m in
             re.finditer(r"gitleaks|sonar|dependencycheck|cyclonedx", wf, re.I)]
    if order:
        r.check("Secret detection runs before the longer jobs",
                re.search(r"gitleaks|secret", order[0][1], re.I) is not None,
                "Secrets is the fastest check with the largest downside. Fail early")

    # no credentials inline
    inline = re.findall(r"(?:token|password|key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", wf)
    inline = [x for x in inline if "secrets." not in x]
    r.check("No credential literal in the workflow file", not inline,
            "Use repository secrets; the secret-detection job will fail the build otherwise")

    # actions pinned
    uses = re.findall(r"uses:\s*([\w.\-]+/[\w.\-]+)@(\S+)", wf)
    unpinned = [f"{a}@{v}" for a, v in uses if not re.fullmatch(r"[0-9a-f]{40}", v)]
    r.check("Actions pinned to commit hashes rather than tags", not unpinned,
            f"a tag can be moved by whoever controls the repository: {unpinned[:3]}"
            if unpinned else "")

    return r


# ------------------------------------------------------------------ E2
SOURCE_ONLY = re.compile(
    r"(open\s*\(|read\s*\(\)|\bgrep\b|re\.search\s*\([^)]*,\s*(src|source|manifest|content))",
    re.I)
BEHAVIOURAL = re.compile(
    r"(adb\s+shell|am\s+start|am\s+broadcast|content\s+query|requests\.|curl|subprocess)",
    re.I)


def e2(session, run=True):
    """Exploit regression suite. The mandatory gate."""
    r = Result("E2")

    pack = os.path.join(EXPLOITS, "run_scenarios.py")
    r.check("Scenario harness present", os.path.exists(pack),
            "The supplied pack lives in exploits/")

    # --- execute the pack ------------------------------------------------
    if run and os.path.exists(pack):
        rc, out, err = sh(f"python3 {pack} --json", timeout=900)
        data = None
        try:
            data = json.loads(out)
        except Exception:
            pass
        if data is None:
            r.check("MANDATORY: scenario pack executed", False,
                    "the harness did not produce a result; check the emulator and build")
        else:
            results = {x["id"]: x for x in data.get("results", [])}
            for sid in MANDATORY_SCENARIOS:
                x = results.get(sid)
                if not x:
                    r.check(f"MANDATORY: {sid} executed", False, "scenario did not run")
                else:
                    r.check(f"MANDATORY: {sid} attack refused", x.get("refused") is True,
                            x.get("detail", ""))
    else:
        r.check("MANDATORY: scenario pack executed (skipped with --no-run)", False,
                "E2 cannot be awarded without executing the scenarios")

    # --- participant-authored scenarios ----------------------------------
    authored = []
    for fn in sorted(os.listdir(EXPLOITS)) if os.path.isdir(EXPLOITS) else []:
        if fn.startswith("scenario_") and fn.endswith(".py"):
            authored.append(os.path.join(EXPLOITS, fn))
    r.check(f"At least two participant-authored scenarios ({len(authored)} found)",
            len(authored) >= 2,
            "Author scenarios named exploits/scenario_<name>.py from your own CR1 findings")

    # each must reference a CR1 finding and assert on behaviour
    reg = load_json(sfile(session, "cr1_findings.json")) or {}
    known = {f.get("id") for f in (reg.get("findings") or [])}
    for path in authored:
        src = read(path)
        name = os.path.basename(path)

        refs = re.findall(r"VB-CR1-\d+", src)
        ok_ref = bool(refs) and (not known or any(x in known for x in refs))
        r.check(f"{name} references a finding from the participant's CR1 report", ok_ref,
                "each authored scenario must name the finding it regresses against")

        behavioural = BEHAVIOURAL.search(src) is not None
        source_only = SOURCE_ONLY.search(src) is not None and not behavioural
        r.check(f"{name} asserts on observed behaviour, not source content",
                behavioural and not source_only,
                "a test that searches the source is satisfied by a comment. Attack the "
                "application and observe what it does")

    # --- wired into the pipeline -----------------------------------------
    wf = read(WORKFLOW)
    r.check("Exploit suite wired into the pipeline",
            re.search(r"run_scenarios|exploit[-_]regression", wf, re.I) is not None,
            "Add an exploit-regression job so the suite runs on every commit")
    r.check("The exploit job can fail the build",
            not re.search(r"run_scenarios.*\n?.*continue-on-error:\s*true", wf, re.I),
            "continue-on-error would let an exploit pass unnoticed")

    return r


# ------------------------------------------------------------------ E3
def e3(session):
    """Full validation run and release gate."""
    r = Result("E3")

    run = load_json(sfile(session, "pipeline_run.json")) or {}
    jobs = run.get("jobs") or []
    r.check("A complete pipeline run is recorded", bool(jobs),
            "Trigger a full run and record the result as pipeline_run.json")
    if jobs:
        failed = [j.get("name") for j in jobs if j.get("conclusion") != "success"]
        r.check("Every pipeline job succeeded", not failed,
                f"failed jobs: {failed}" if failed else "")
        r.check("The exploit regression job ran in this pipeline execution",
                any(re.search(r"exploit", j.get("name", ""), re.I) for j in jobs),
                "a green pipeline that never ran the exploit suite has validated nothing")

    # artefact identity
    bundle = load_json(sfile(session, "evidence_bundle.json")) or {}
    digest = (bundle.get("apk_sha256") or "").lower().strip()
    r.check("Release artefact digest recorded", bool(re.fullmatch(r"[a-f0-9]{64}", digest)),
            "a validated build is identified by digest, not by version name")

    apk = os.path.join(PROJECT, "app", "build", "outputs", "apk", "release", "app-release.apk")
    if os.path.exists(apk) and digest:
        rc, out, _ = sh(f"sha256sum {apk}")
        actual = out.split()[0] if out else ""
        r.check("Recorded digest matches the built artefact", actual == digest,
                "regenerate the digest after your final change")

    # SBOM describes THIS build
    bom = load_json(os.path.join(PROJECT, "build", "reports", "bom.json"))
    r.check("SBOM present for the validated build", bom is not None,
            "the inventory must describe the artefact you are submitting")
    if bom:
        meta = json.dumps(bom.get("metadata") or {})
        r.check("SBOM has components and a timestamp",
                bool(bom.get("components")) and "timestamp" in meta)

    # residual coverage statement
    stmt = read(sfile(session, "residual_coverage.md"))
    r.check("Residual coverage statement present", len(stmt.strip()) > 150,
            "name at least one class of defect this pipeline cannot detect")
    if stmt:
        names_gap = re.search(
            r"(authoris|authoriz|business logic|design|privacy|logic flaw|"
            r"access control|missing control)", stmt, re.I)
        r.check("Statement names a defect class the pipeline cannot detect",
                names_gap is not None,
                "a pipeline of scanners cannot reach authorisation logic or missing controls")

    return r


# ------------------------------------------------------------------ main
def run_level(name, session, execute=True):
    if name == "E1":
        return e1(session)
    if name == "E2":
        return e2(session, run=execute)
    return e3(session)


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--level", default="all", choices=["all", "E1", "E2", "E3"])
    ap.add_argument("--no-run", action="store_true",
                    help="skip executing the scenario pack (E2 cannot be awarded)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    names = ["E1", "E2", "E3"] if a.level == "all" else [a.level]
    results = [run_level(n, a.session, execute=not a.no_run) for n in names]
    awarded = sum(POINTS[r.level] for r in results if r.passed)

    e2r = next((r for r in results if r.level == "E2"), None)
    gate = None
    if e2r:
        gate = all(ok for n, ok, _ in e2r.checks if n.startswith("MANDATORY"))

    if a.json:
        print(json.dumps({
            "session": a.session, "points_awarded": awarded,
            "exploit_gate": gate,
            "levels": [{"level": r.level, "passed": r.passed,
                        "points": POINTS[r.level] if r.passed else 0,
                        "checks": [{"name": n, "passed": ok, "guidance": g if not ok else ""}
                                   for n, ok, g in r.checks]} for r in results],
        }, indent=2))
        sys.exit(0 if all(r.passed for r in results) else 1)

    print(f"\nCR4 validation — session {a.session}")
    for r in results:
        print("\n" + "=" * 68)
        print(f"  {r.level}  {'PASSED' if r.passed else 'NOT PASSED'}"
              f"   ({POINTS[r.level] if r.passed else 0}/{POINTS[r.level]} points)")
        print("=" * 68)
        for n, ok, g in r.checks:
            print(f"  [{'PASS' if ok else 'FAIL'}]  {n}")
            if not ok and g:
                for ln in _wrap(g, 60):
                    print(f"          {ln}")

    print("\n" + "=" * 68)
    print(f"  Points: {awarded}/500     Pass mark: 350")
    if gate is not None:
        print(f"  Exploit regression gate: {'satisfied' if gate else 'NOT SATISFIED'}")
        if not gate:
            print("\n  One or more supplied scenarios still succeed. A green pipeline")
            print("  while an exploit works has validated nothing.")
    print("=" * 68 + "\n")
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
