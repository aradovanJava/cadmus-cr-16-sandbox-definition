#!/usr/bin/env python3
"""
CADMUS-CR-16 :: CR1 automated level validation

Called by the Cyber Range to award or withhold level points. Each check returns
(passed, detail) so the platform can show the participant WHY a level did not
complete rather than only that it did not.

  python3 cr1_validate.py --level A1 --session <id>
  python3 cr1_validate.py --level A4 --session <id> --report findings.md

Files the levels read (revision 2, CR-16 sandbox): they live in
$CR_SESSION_DIR/$CR_SESSION/ - in the sandbox ~/cr-session/cr16/ - and are
written by the participant:

  a1_artefact.json   {"apk_sha256": "<sha256 of app-release.apk>",
                      "version_name": "1.2.0", "version_code": 3}
  mobsf_report.json  MobSF JSON report      (A2)
  zap_alerts.json    ZAP alerts, JSON or XML (zap_alerts.xml)   (A2)
  a3_counts.json     {"vulnerabilities": n, "bugs": n, "code_smells": n,
                      "security_hotspots": n, "quality_profile": "Sonar way"}

A3 queries SonarQube with SONAR_ADMIN_TOKEN, or SONAR_TOKEN when that is
not set: a *user* token of your SonarQube account.

IMPORTANT: A4 validates STRUCTURE ONLY. Whether the reasoning is any good is
not machine-checkable and is graded by the instructor against the rubric in
CR1_Instructor_Pack.md section 5. A well-formed report is not a good one.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

PACKAGE = "eu.cadmus.vulnbank"
SONAR_PROJECT = "cadmus-vulnbank"

MOBSF = os.environ.get("MOBSF_URL", "http://mobsf.sandbox.local:8000")
ZAP = os.environ.get("ZAP_URL", "http://zap.sandbox.local:8080")
SONAR = os.environ.get("SONAR_URL", "http://sonarqube.sandbox.local:9000")


# --------------------------------------------------------------- helpers
def sh(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def session_file(session, name):
    return os.path.join(os.environ.get("CR_SESSION_DIR", os.path.expanduser("~/cr-session")),
                        session, name)


def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


# --------------------------------------------------------------- A1
def check_a1(session):
    """Environment verified, target deployed, artefact identity pinned."""
    checks = []

    rc, out, _ = sh(f"adb shell pm list packages | grep -F {PACKAGE}")
    checks.append(("Target application installed on the emulator",
                   rc == 0 and PACKAGE in out,
                   "Run: adb install -r app-release.apk"))

    rc, out, _ = sh("adb shell getprop sys.boot_completed")
    checks.append(("Emulator finished booting",
                   out.strip() == "1",
                   "The emulator is still starting. Wait for sys.boot_completed to return 1."))

    # participant-recorded digest must match the artefact actually deployed
    recorded = None
    meta = load_json(session_file(session, "a1_artefact.json"))
    if meta:
        recorded = (meta.get("apk_sha256") or "").lower().strip()

    apk = os.environ.get("CR1_APK_PATH", "/opt/cadmus/vulnbank/app-release.apk")
    actual = None
    if os.path.exists(apk):
        h = hashlib.sha256()
        with open(apk, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
        actual = h.hexdigest()

    checks.append(("Recorded APK SHA-256 matches the deployed artefact",
                   bool(recorded) and recorded == actual,
                   "Record the digest of the APK you actually analysed (sha256sum app-release.apk) "
                   f"in {session_file(session, 'a1_artefact.json')} as "
                   '{"apk_sha256": "<digest>"}'))

    rc, out, _ = sh(f'curl -s -o /dev/null -w "%{{http_code}}" '
                    f'-H "Authorization: $MOBSF_KEY" {MOBSF}/api/v1/scans')
    checks.append(("Authenticated MobSF API call succeeds",
                   out.strip() in ("200", "201"),
                   "Retrieve the API key: docker logs MSF1 | grep -i 'api key'"))

    return checks


# --------------------------------------------------------------- A2
def check_a2(session):
    """Both dynamic tools produced real evidence about the recorded artefact."""
    checks = []

    meta = load_json(session_file(session, "a1_artefact.json")) or {}
    apk_hash = (meta.get("apk_sha256") or "").lower()

    rc, out, _ = sh(f'curl -s -H "Authorization: $MOBSF_KEY" {MOBSF}/api/v1/scans')
    scans = []
    try:
        scans = json.loads(out).get("content", [])
    except Exception:
        pass
    checks.append(("A completed MobSF scan exists for the recorded artefact",
                   any(PACKAGE in json.dumps(s) for s in scans),
                   "Upload the RELEASE apk you recorded in A1, then start the scan."))

    # ZAP must have observed the app's own traffic, not just been switched on
    rc, out, _ = sh(f"curl -s '{ZAP}/JSON/core/view/urls/'")
    urls = out if rc == 0 else ""
    saw_login = "/login" in urls
    saw_transfer = "/transfer" in urls
    checks.append(("ZAP observed a request to the login endpoint",
                   saw_login,
                   "Setting the proxy is not enough. Open the app and log in."))
    checks.append(("ZAP observed a request to the transfer endpoint",
                   saw_transfer,
                   "Exercise a funds transfer in the application so ZAP sees the request."))

    for f in ("mobsf_report.json",):
        checks.append((f"Exported {f}",
                       os.path.exists(session_file(session, f)),
                       f"Export the MobSF JSON report to {session_file(session, f)} "
                       "(curl -X POST -d hash=$H -H \"Authorization: $MOBSF_KEY\" "
                       "$MOBSF/api/v1/report_json)."))
    zap_ok = any(os.path.exists(session_file(session, n))
                 for n in ("zap_alerts.json", "zap_alerts.xml"))
    checks.append(("Exported the ZAP alert list",
                   zap_ok,
                   f"Export ZAP alerts to {session_file(session, 'zap_alerts.json')} "
                   f"(curl -s {ZAP}/JSON/core/view/alerts/) or zap_alerts.xml."))

    return checks


# --------------------------------------------------------------- A3
def check_a3(session):
    """Static analysis ran, and the participant recorded results meaningfully."""
    checks = []

    tok = os.environ.get("SONAR_ADMIN_TOKEN") or os.environ.get("SONAR_TOKEN", "")
    if not tok:
        checks.append(("SonarQube token available", False,
                       "export SONAR_TOKEN=<a user token of your SonarQube account> "
                       "(My Account > Security > Generate Tokens, type 'User Token')"))
    rc, out, _ = sh(f'curl -s -u {tok}: '
                    f'"{SONAR}/api/components/show?component={SONAR_PROJECT}"')
    exists = f'"key":"{SONAR_PROJECT}"' in out.replace(" ", "")
    checks.append((f"SonarQube project '{SONAR_PROJECT}' exists",
                   exists,
                   "Create the project with exactly this key before running the analysis."))

    rc, out, _ = sh(f'curl -s -u {tok}: '
                    f'"{SONAR}/api/measures/component'
                    f'?component={SONAR_PROJECT}'
                    f'&metricKeys=vulnerabilities,bugs,code_smells,security_hotspots"')
    measures = {}
    try:
        for m in json.loads(out)["component"]["measures"]:
            measures[m["metric"]] = int(m["value"])
    except Exception:
        pass
    checks.append(("A completed analysis is present",
                   len(measures) >= 3,
                   "Run ./gradlew sonar and wait for background processing to finish."))

    # the participant's recorded counts must match -- catches a silently failed scan
    rec = load_json(session_file(session, "a3_counts.json")) or {}
    matched = all(
        str(rec.get(k, "")).strip() == str(measures.get(k, "?"))
        for k in ("vulnerabilities", "bugs", "code_smells", "security_hotspots")
    ) and bool(measures)
    checks.append(("Recorded counts match the analysis, including security hotspots",
                   matched,
                   "Record all FOUR counts separately in "
                   f"{session_file(session, 'a3_counts.json')}: vulnerabilities, bugs, "
                   "code_smells, security_hotspots. A Security Hotspot is not a Vulnerability."))

    checks.append(("Quality profile recorded",
                   bool((rec.get("quality_profile") or "").strip()),
                   "A findings count without a stated profile and scope conveys almost nothing."))

    return checks


# --------------------------------------------------------------- A4
REQUIRED_FIELDS = ["ID", "TITLE", "CATEGORY", "FLAW TYPE", "ROOT CAUSE",
                   "LOCATION", "IMPACT", "EVIDENCE", "TRIAGE", "PRIORITY",
                   "REMEDIATION", "VERIFY"]

RETIRED_2016 = [
    "improper platform usage", "client code quality", "reverse engineering",
    "extraneous functionality", "code tampering",
]


def check_a4(session, report_path):
    """
    STRUCTURE ONLY. The instructor grades the reasoning against the rubric.
    """
    checks = []

    if not report_path or not os.path.exists(report_path):
        return [("Findings report submitted", False,
                 "A4 is mandatory. Submit the completed findings report.")]

    text = open(report_path, encoding="utf-8", errors="replace").read()
    low = text.lower()

    checks.append(("Findings report submitted", True, ""))

    # header identity
    checks.append(("Report header records the APK SHA-256",
                   re.search(r"[a-f0-9]{64}", low) is not None,
                   "Record the digest of the artefact you analysed."))

    # findings blocks
    ids = re.findall(r"\bVB-CR1-\d+\b", text)
    n = len(set(ids))
    checks.append((f"At least three findings documented (found {n})",
                   n >= 3,
                   "Use the ID format VB-CR1-01, VB-CR1-02, ..."))

    # every required field present at least as often as there are findings
    for f in REQUIRED_FIELDS:
        cnt = len(re.findall(rf"^\s*{re.escape(f)}\b", text, re.M | re.I))
        checks.append((f"Field '{f}' completed for every finding",
                       n > 0 and cnt >= n,
                       f"{cnt} of {n} findings carry a {f} field."))

    # OWASP 2024 categories, and NOT the retired 2016 names
    cats = set(re.findall(r"\bM(10|[1-9])\b", text))
    checks.append((f"OWASP Mobile Top 10 (2024) categories assigned ({len(cats)} distinct)",
                   len(cats) >= 3,
                   "Map every finding to a 2024 category."))
    used_2016 = [c for c in RETIRED_2016 if c in low]
    checks.append(("No retired 2016 category names used",
                   not used_2016,
                   f"Retired 2016 categories found: {', '.join(used_2016)}. "
                   "Use the 2024 Final Release list."))

    # triage vocabulary -- all four outcomes must be understood, not just used
    triage_terms = ["true positive", "false positive",
                    "not exploitable", "accepted risk"]
    present = [t for t in triage_terms if t in low]
    checks.append((f"Triage outcomes applied ({len(present)} of 4 vocabularies used)",
                   len(present) >= 2,
                   "Use the four outcomes. Teams with only two corrupt their suppression list."))

    # priority derived, not copied
    checks.append(("Priority justified against tool severity",
                   re.search(r"tool severity", low) is not None,
                   "State the tool's severity and justify any difference from your priority."))

    # design vs implementation classification
    checks.append(("Design vs implementation classification present",
                   "design flaw" in low and "implementation flaw" in low,
                   "Classify each finding, and identify at least one design flaw."))

    # THE discriminator: the defect no tool reported
    section = re.search(r"defect no tool reported(.{0,2500})", low, re.S)
    sec = section.group(1) if section else ""
    found_it = (
        ("export" in sec and ("intent" in sec or "extras" in sec))
        or ("authorisation" in sec or "authorization" in sec)
    ) and len(sec.strip()) > 200
    checks.append(("The unreported defect is identified and described",
                   found_it,
                   "At least one serious defect is reported by none of your tools. "
                   "It concerns who makes an authorisation decision."))

    tools_explained = sum(1 for t in ("mobsf", "zap", "sonar") if t in sec)
    checks.append((f"Explained why each tool missed it ({tools_explained} of 3)",
                   tools_explained >= 3,
                   "Name the mechanism by which each of the three tools missed this defect."))

    # suppressions carry reasons
    if "false positive" in low or "not exploitable" in low:
        checks.append(("Suppressions carry a written reason",
                       "reason" in low or "rationale" in low,
                       "A suppression with no rationale is indistinguishable from concealment."))

    return checks


# --------------------------------------------------------------- main
LEVELS = {"A1": check_a1, "A2": check_a2, "A3": check_a3}
POINTS = {"A1": 100, "A2": 100, "A3": 100, "A4": 200}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", required=True, choices=["A1", "A2", "A3", "A4"])
    ap.add_argument("--session", required=True)
    ap.add_argument("--report", help="path to the findings report (A4)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()

    if a.level == "A4":
        checks = check_a4(a.session, a.report)
    else:
        checks = LEVELS[a.level](a.session)

    passed = sum(1 for _, ok, _ in checks if ok)
    total = len(checks)
    complete = passed == total
    awarded = POINTS[a.level] if complete else 0

    if a.json:
        print(json.dumps({
            "level": a.level, "session": a.session,
            "checks_passed": passed, "checks_total": total,
            "level_complete": complete, "points_awarded": awarded,
            "checks": [{"name": nm, "passed": ok, "guidance": g if not ok else ""}
                       for nm, ok, g in checks],
        }, indent=2))
    else:
        print(f"\nCR1 level {a.level} — session {a.session}")
        print("=" * 62)
        for nm, ok, guidance in checks:
            print(f"  [{'PASS' if ok else 'FAIL'}]  {nm}")
            if not ok and guidance:
                print(f"          -> {guidance}")
        print("=" * 62)
        print(f"  {passed}/{total} checks passed — "
              f"{'LEVEL COMPLETE' if complete else 'NOT COMPLETE'} "
              f"({awarded} points)")
        if a.level == "A4":
            print("\n  NOTE: structure only. The instructor grades the reasoning")
            print("        against the rubric in CR1_Instructor_Pack.md section 5.")

    sys.exit(0 if complete else 1)


if __name__ == "__main__":
    main()
