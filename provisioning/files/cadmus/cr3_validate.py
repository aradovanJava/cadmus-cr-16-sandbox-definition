#!/usr/bin/env python3
"""
CADMUS-CR-16 :: CR3 dependency remediation validation

    python3 cr3_validate.py --session <id> --level all
    python3 cr3_validate.py --session <id> --level D2
    python3 cr3_validate.py --session <id> --level D2 --no-build

DESIGN NOTES
------------
Two things distinguish this from a scanner wrapper.

1. THE FUNCTIONALITY GATE (D2). The stated outcome is to replace or update
   vulnerable components WHILE MAINTAINING APPLICATION FUNCTIONALITY. Clearing
   every advisory by deleting the libraries the app depends on satisfies a
   scanner and destroys the product. D2 awards nothing unless the branch builds
   and the tests pass.

2. FALSE-REMEDIATION DETECTION. An advisory can be made to disappear from a
   report without the component leaving the build. The validator compares the
   participant's claims against the RESOLVED release runtime classpath, which
   is the only ground truth here.
"""

import argparse
import json
import os
import re
import subprocess
import sys

# Revision 2 (CR-16 sandbox): defaults follow the sandbox account.
PROJECT = os.environ.get("CR3_PROJECT", os.path.expanduser("~/vulnbank"))
SESSION_DIR = os.environ.get("CR_SESSION_DIR", os.path.expanduser("~/cr-session"))
GRADLE = "./gradlew"
CONFIG = "releaseRuntimeClasspath"

POINTS = {"D1": 150, "D2": 200, "D3": 150}


# ------------------------------------------------------------------ shell
def sh(cmd, timeout=420, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd or PROJECT)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def sfile(session, name):
    return os.path.join(SESSION_DIR, session, name)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# ------------------------------------------------------- resolved classpath
_RESOLVED_CACHE = None
COORD = re.compile(r"([\w.\-]+):([\w.\-]+):([\w.\-+]+)")


def resolved_components():
    """
    The ground truth: what actually resolves onto the shipped classpath.
    Returns {"group:name": "version"}. Honours Gradle's '->' substitutions.
    """
    global _RESOLVED_CACHE
    if _RESOLVED_CACHE is not None:
        return _RESOLVED_CACHE

    rc, out, _ = sh(f"{GRADLE} -q :app:dependencies --configuration {CONFIG}")
    comps = {}
    for line in out.splitlines():
        if "->" in line:                      # "a:b:1.0 -> 1.2" : take the winner
            left, right = line.rsplit("->", 1)
            m = COORD.search(left)
            v = right.strip().split()[0] if right.strip() else None
            if m and v:
                comps[f"{m.group(1)}:{m.group(2)}"] = v
                continue
        m = COORD.search(line)
        if m:
            comps.setdefault(f"{m.group(1)}:{m.group(2)}", m.group(3))
    _RESOLVED_CACHE = comps
    return comps


class Result:
    def __init__(self, level):
        self.level = level
        self.checks = []
        self.warnings = []

    def check(self, name, ok, guidance=""):
        self.checks.append((name, bool(ok), guidance))

    def warn(self, title, detail):
        self.warnings.append((title, detail))

    @property
    def passed(self):
        return all(ok for _, ok, _ in self.checks) and not self.warnings


# ------------------------------------------------------------------ D1
def d1(session):
    """Composition analysis run, and every advisory triaged with reachability."""
    r = Result("D1")

    sca = (load_json(sfile(session, "sca_report.json"))
           or load_json(os.path.join(PROJECT, "app/build/reports/dependency-check-report.json")))
    r.check("Composition analysis report present", sca is not None,
            "Run ./gradlew dependencyCheckAnalyze (report: "
            "app/build/reports/dependency-check-report.json)")

    reg = load_json(sfile(session, "dependency_register.json"))
    r.check("Dependency register submitted", reg is not None,
            "The deliverable is a triaged register, not a scanner export. Write it to "
            f"{sfile(session, 'dependency_register.json')} (format: "
            "CR3_Dependency_Register_Template.md)")
    if not reg:
        return r

    entries = reg.get("advisories", [])
    r.check(f"Register contains advisories ({len(entries)})", len(entries) >= 1)

    # every advisory needs direct/transitive, reachability and an outcome
    missing_scope = [e for e in entries if e.get("scope") not in ("direct", "transitive")]
    r.check("Every advisory marked direct or transitive", not missing_scope,
            f"{len(missing_scope)} entries missing a scope marker")

    missing_reach = [e for e in entries
                     if not str(e.get("reachable", "")).strip()
                     or not str(e.get("reachability_reasoning", "")).strip()]
    r.check("Every advisory carries a reachability determination with reasoning",
            not missing_reach,
            f"{len(missing_reach)} entries have no reachability reasoning. An advisory "
            "against a shipped component is not automatically exploitable in your app")

    valid = {"update", "replace", "remove", "accept"}
    missing_outcome = [e for e in entries if e.get("planned_outcome") not in valid]
    r.check("Every advisory has a planned outcome", not missing_outcome,
            f"use one of: {', '.join(sorted(valid))}")

    # transitive entries must name the introducing dependency
    orphan = [e for e in entries
              if e.get("scope") == "transitive" and not str(e.get("introduced_by", "")).strip()]
    r.check("Transitive advisories name the dependency that introduced them", not orphan,
            f"{len(orphan)} transitive entries do not say what pulled them in")

    # the cheap win
    r.check("Unused dependencies identified",
            bool(reg.get("unused_dependencies")),
            "At least one declared dependency is referenced by no code. Removing it "
            "is the cheapest remediation available")

    # dynamic ranges are a finding in their own right
    r.check("Dynamic version ranges identified",
            "dynamic_ranges" in reg,
            "Record any dependency declared with a range; it makes the build non-reproducible")

    # coverage: register must account for every advisory the scan produced
    if sca:
        scanned = set()
        for dep in (sca.get("dependencies") or []):
            for v in (dep.get("vulnerabilities") or []):
                if v.get("name"):
                    scanned.add(v["name"])
        listed = {e.get("id") for e in entries}
        gap = scanned - listed
        r.check(f"Register covers every advisory the scan produced ({len(scanned)} found)",
                not gap,
                f"{len(gap)} advisories in the scan are absent from the register")

    return r


def executed_tests():
    """Number of unit tests in the JUnit XML results of the last './gradlew test'."""
    total = 0
    base = os.path.join(PROJECT, "app", "build", "test-results")
    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.startswith("TEST-") and f.endswith(".xml"):
                m = re.search(r'<testsuite[^>]*\btests="(\d+)"[^>]*\bskipped="(\d+)"',
                              read(os.path.join(root, f)))
                if m:
                    total += int(m.group(1)) - int(m.group(2))
    return total


# ------------------------------------------------------------------ D2
def d2(session, build=True):
    """Remediation applied, functionality preserved. The mandatory gate."""
    r = Result("D2")
    reg = load_json(sfile(session, "dependency_register.json")) or {}
    entries = reg.get("advisories", [])

    # --- the mandatory functionality gate ------------------------------
    if build:
        rc, out, err = sh(f"{GRADLE} assembleRelease -q", timeout=600)
        built = rc == 0
        r.check("MANDATORY: the branch compiles", built,
                "A remediation that breaks the build has not remediated anything")
        if built:
            rc, out, err = sh(f"{GRADLE} test -q", timeout=900)
            ran = executed_tests()
            r.check(f"MANDATORY: the functional test suite passes ({ran} tests executed)",
                    rc == 0 and ran > 0,
                    "Components must be updated or replaced WHILE MAINTAINING functionality"
                    if rc != 0 else
                    "no test was executed: the project's smoke tests (app/src/test) are "
                    "part of the gate - restore them rather than deleting them")
        else:
            r.check("MANDATORY: the functional test suite passes", False,
                    "cannot run tests: the branch does not compile")
    else:
        r.check("MANDATORY: build and tests (skipped with --no-build)", False,
                "D2 cannot be awarded without the functionality gate")

    comps = resolved_components()
    r.check(f"Release classpath resolves ({len(comps)} components)", bool(comps),
            "could not resolve the release runtime classpath")

    # --- exact pinning ---------------------------------------------------
    gradle_src = read(os.path.join(PROJECT, "app", "build.gradle"))
    catalog = read(os.path.join(PROJECT, "gradle", "libs.versions.toml"))
    ranges = re.findall(r"[\"']([\w.\-]+:[\w.\-]+:[^\"']*[+\[\](),][^\"']*)[\"']",
                        gradle_src + "\n" + catalog)
    r.check("No dynamic version ranges declared", not ranges,
            f"found: {ranges}" if ranges else "")

    # --- every advisory dispositioned -----------------------------------
    unresolved = []
    for e in entries:
        key = e.get("component", "")
        outcome = e.get("planned_outcome")
        still = comps.get(key)
        if outcome == "remove" and still:
            unresolved.append((key, "marked for removal but still on the classpath"))
        elif outcome in ("update", "replace") and still and still == e.get("version"):
            unresolved.append((key, f"still resolves at the vulnerable version {still}"))
        elif outcome == "accept":
            acc = e.get("acceptance") or {}
            if not all(str(acc.get(k, "")).strip() for k in ("owner", "rationale", "review_date")):
                unresolved.append((key, "accepted without owner, rationale and review date"))
    r.check("Every advisory resolved or formally accepted", not unresolved,
            "; ".join(f"{k}: {why}" for k, why in unresolved[:4]) if unresolved else "")

    # --- unused dependencies actually removed ---------------------------
    unused = reg.get("unused_dependencies") or []
    still_present = [u for u in unused if u in comps]
    r.check("Unused dependencies removed from the build", not still_present,
            f"still resolving: {still_present}" if still_present else "")

    # === FALSE REMEDIATION ==============================================

    # (a) hidden rather than removed
    supp = read(os.path.join(PROJECT, "config", "dependency-check-suppressions.xml"))
    sbom = load_json(os.path.join(PROJECT, "build", "reports", "bom.json")) or {}
    sbom_keys = {f"{c.get('group')}:{c.get('name')}" for c in (sbom.get("components") or [])}
    for e in entries:
        key = e.get("component", "")
        if key and key in comps and key not in sbom_keys and sbom_keys:
            r.warn("Component absent from the inventory but present in the build",
                   f"{key} resolves onto the release classpath yet does not appear in the "
                   "SBOM. Falsifying the inventory to silence a finding is worse than the "
                   "finding: the next person to ask 'are we affected?' will get the wrong "
                   "answer.")

    # (b) direct updated, vulnerable transitive unchanged
    for e in entries:
        if e.get("scope") != "transitive":
            continue
        key, oldv = e.get("component", ""), e.get("version")
        parent = e.get("introduced_by", "")
        if key in comps and comps[key] == oldv and parent and parent in comps:
            if comps.get(parent) != e.get("introduced_by_version"):
                r.warn("Direct dependency updated but the vulnerable transitive did not move",
                       f"{parent} was updated, yet {key} still resolves at {oldv}. Another path "
                       "is pinning it. Re-resolve the classpath and add an explicit constraint, "
                       "or update the dependency that actually controls it.")

    # (c) suppression without rationale
    if supp:
        notes = re.findall(r"<notes>(.*?)</notes>", supp, re.S)
        sups = re.findall(r"<suppress", supp)
        if len(sups) > len([n for n in notes if n.strip()]):
            r.warn("Advisory suppressed without a written rationale",
                   "A suppression with no reason and no review date is indistinguishable from "
                   "concealment, and will be read that way in an incident post-mortem.")

    return r


# ------------------------------------------------------------------ D3
def d3(session):
    """Inventory, verification metadata, durable records, risk statement."""
    r = Result("D3")

    bom_path = os.path.join(PROJECT, "build", "reports", "bom.json")
    bom = load_json(bom_path)
    r.check("CycloneDX SBOM generated by the build", bom is not None,
            "Run ./gradlew cyclonedxBom. A hand-written inventory is wrong within a sprint")
    if not bom:
        return r

    r.check("SBOM declares a CycloneDX format and spec version",
            bom.get("bomFormat") == "CycloneDX" and bool(bom.get("specVersion")))

    comps = {f"{c.get('group')}:{c.get('name')}": c.get("version")
             for c in (bom.get("components") or [])}
    r.check(f"SBOM lists components ({len(comps)})", len(comps) >= 5)

    with_purl = [c for c in (bom.get("components") or []) if c.get("purl")]
    r.check("Every SBOM component carries a purl",
            len(with_purl) == len(bom.get("components") or []),
            "purl is what lets a scanner match your entry against advisory data automatically")

    # --- reconcile against ground truth ---------------------------------
    resolved = resolved_components()
    if resolved:
        missing = {k: v for k, v in resolved.items() if k not in comps}
        wrong = {k: (comps[k], resolved[k]) for k in comps
                 if k in resolved and comps[k] != resolved[k]}
        r.check("SBOM reconciles against the resolved release classpath",
                not missing and not wrong,
                (f"{len(missing)} components on the classpath are absent from the SBOM; "
                 f"{len(wrong)} version mismatches") if (missing or wrong) else "")

    # --- verification metadata ------------------------------------------
    vm = read(os.path.join(PROJECT, "gradle", "verification-metadata.xml"))
    r.check("Dependency verification metadata committed", bool(vm.strip()),
            "Run ./gradlew --write-verification-metadata sha256,pgp help and commit the result")
    if vm:
        r.check("Verification metadata records checksums",
                "sha256" in vm.lower() or "<sha512" in vm.lower())
        verified = set(re.findall(r'group="([^"]+)"\s+name="([^"]+)"', vm))
        verified = {f"{g}:{n}" for g, n in verified}
        res = set(resolved_components())
        gap = res - verified
        # allow a 5% tail for platform-supplied artefacts, but no blanket tolerance:
        # on a small project that would pass a near-empty metadata file.
        tolerated = len(res) * 0.05
        r.check("Verification metadata covers the resolved components",
                len(gap) == 0 or len(gap) <= tolerated,
                f"{len(gap)} of {len(res)} resolved components have no recorded checksum")

    # --- durable records for carried-forward advisories ------------------
    reg = load_json(sfile(session, "dependency_register.json")) or {}
    carried = [e for e in (reg.get("advisories") or [])
               if e.get("planned_outcome") == "accept"
               or str(e.get("reachable", "")).lower() in ("no", "false", "not_reachable")]
    vex = (load_json(sfile(session, "vex.json"))
           or load_json(os.path.join(PROJECT, "build", "reports", "vex.json")) or {})
    vex_ids = {v.get("id") for v in (vex.get("vulnerabilities") or [])}

    if carried:
        undocumented = [e for e in carried if e.get("id") not in vex_ids]
        r.check("Carried-forward advisories recorded durably",
                not undocumented,
                f"{len(undocumented)} advisories judged unreachable or accepted have no durable "
                "record. Without one the same conclusion is re-derived on every future scan")
        no_date = [v for v in (vex.get("vulnerabilities") or [])
                   if not re.search(r"\d{4}-\d{2}-\d{2}",
                                    json.dumps(v.get("analysis") or {}))]
        r.check("Every durable record carries a review date", not no_date,
                "A justification that never expires is an exception nobody owns")

    # --- risk exposure statement ----------------------------------------
    stmt = read(sfile(session, "risk_exposure.md"))
    r.check("Risk exposure statement present", len(stmt.strip()) > 200,
            "State what residual exposure remains, why, and what would change it, in "
            f"{sfile(session, 'risk_exposure.md')}")

    return r


# ------------------------------------------------------------------ main
LEVELS = {"D1": d1, "D3": d3}


def run(name, session, build=True):
    if name == "D2":
        return d2(session, build=build)
    return LEVELS[name](session)


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
    ap.add_argument("--level", default="all", choices=["all", "D1", "D2", "D3"])
    ap.add_argument("--no-build", action="store_true",
                    help="skip the D2 functionality gate (D2 cannot be awarded)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    names = ["D1", "D2", "D3"] if a.level == "all" else [a.level]
    results = [run(n, a.session, build=not a.no_build) for n in names]
    awarded = sum(POINTS[r.level] for r in results if r.passed)
    d2r = next((r for r in results if r.level == "D2"), None)
    gate_ok = None
    if d2r:
        gate_ok = all(ok for n, ok, _ in d2r.checks if n.startswith("MANDATORY"))

    if a.json:
        print(json.dumps({
            "session": a.session, "points_awarded": awarded,
            "functionality_gate": gate_ok,
            "levels": [{
                "level": r.level, "passed": r.passed,
                "points": POINTS[r.level] if r.passed else 0,
                "checks": [{"name": n, "passed": ok, "guidance": g if not ok else ""}
                           for n, ok, g in r.checks],
                "false_remediation_warnings": [{"title": t, "detail": d} for t, d in r.warnings],
            } for r in results],
        }, indent=2))
        sys.exit(0 if all(r.passed for r in results) else 1)

    print(f"\nCR3 dependency remediation — session {a.session}")
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
        for t, dt in r.warnings:
            print(f"\n  [!! FALSE REMEDIATION ]  {t}")
            for ln in _wrap(dt, 60):
                print(f"          {ln}")

    print("\n" + "=" * 68)
    print(f"  Points: {awarded}/500     Pass mark: 350")
    if gate_ok is not None:
        print(f"  Functionality gate (D2): {'satisfied' if gate_ok else 'NOT SATISFIED'}")
        if not gate_ok:
            print("\n  The branch must build and its tests must pass. Clearing advisories")
            print("  by removing components the application needs is not remediation.")
    print("=" * 68 + "\n")
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
