#!/usr/bin/env python3
"""
CADMUS-CR-16 :: CR2 security checkpoint validation

Run by the participant, repeatedly, while refactoring. Reports which checkpoints
are satisfied, which are not, and -- the part that matters pedagogically --
where a change has closed a scanner finding without closing the vulnerability.

    python3 cr2_validate.py --session <id> --checkpoint all
    python3 cr2_validate.py --session <id> --checkpoint CP3
    python3 cr2_validate.py --session <id> --checkpoint CP5   # rebuilds + installs

DESIGN NOTE
-----------
Pattern checks alone are gameable: a participant can delete a line to satisfy a
regex without changing what an attacker can do. Two mechanisms guard against it:

  1. FALSE-REMEDIATION DETECTION -- looks for defects that have been PROTECTED
     rather than REMOVED, and reports them as warnings that block the checkpoint.
  2. CP5 BEHAVIOURAL TEST -- builds and installs the participant's APK and
     actually attempts the N1 Intent exploit. Passing requires the transfer to
     be refused, not merely for the manifest to look right.
"""

import argparse
import json
import os
import re
import subprocess
import sys

PACKAGE = "eu.cadmus.vulnbank"
# Revision 2 (CR-16 sandbox): defaults follow the sandbox account (~/vulnbank);
# the sandbox also sets CR2_PROJECT and CR2_SRC in /etc/profile.d.
PROJECT = os.environ.get("CR2_PROJECT", os.path.expanduser("~/vulnbank"))
SRC = os.environ.get("CR2_SRC", os.path.join(PROJECT, "app", "src", "main"))

POINTS = {"CP1": 60, "CP2": 60, "CP3": 80, "CP4": 60, "CP5": 140}

# checkpoints whose failure is recoverable vs the mandatory one
MANDATORY = "CP5"


# ------------------------------------------------------------------ helpers
def sh(cmd, timeout=180, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def java_files():
    out = []
    for root, _dirs, files in os.walk(SRC):
        if os.sep + "test" in root:
            continue
        for f in files:
            if f.endswith(".java"):
                out.append(os.path.join(root, f))
    return out


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def strip_comments(src):
    """So a participant cannot satisfy a check by commenting a line out."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def grep_src(pattern, files=None, flags=re.I):
    """Search live (non-comment) Java code. Returns [(file, line_no, line)]."""
    hits = []
    for path in (files or java_files()):
        raw = read(path)
        clean = strip_comments(raw)
        for i, line in enumerate(clean.splitlines(), 1):
            if re.search(pattern, line, flags):
                hits.append((os.path.relpath(path, SRC), i, line.strip()))
    return hits


def grep_file(path, pattern, flags=re.I):
    txt = read(path)
    return re.search(pattern, txt, flags) is not None


MANIFEST = os.path.join(SRC, "AndroidManifest.xml")
NSC = os.path.join(SRC, "res", "xml", "network_security_config.xml")
STRINGS = os.path.join(SRC, "res", "values", "strings.xml")


class Result:
    def __init__(self, cp):
        self.cp = cp
        self.checks = []       # (name, passed, guidance)
        self.warnings = []     # false-remediation warnings

    def check(self, name, passed, guidance=""):
        self.checks.append((name, bool(passed), guidance))

    def warn(self, title, detail):
        self.warnings.append((title, detail))

    @property
    def passed(self):
        return all(ok for _, ok, _ in self.checks) and not self.warnings


# ------------------------------------------------------------------ CP1
def cp1():
    """M1 Credentials · M9 Data at rest."""
    r = Result("CP1")

    secret_pat = r"""(password|passwd|secret|api_?key|token|pin)\s*=\s*["'][^"']{4,}"""
    hits = [h for h in grep_src(secret_pat) if "BuildConfig" not in h[2]]
    r.check("No hardcoded credentials in Java source", not hits,
            f"{len(hits)} found, first at {hits[0][0]}:{hits[0][1]}" if hits else "")

    res_secret = grep_file(STRINGS, r"(api_key|secret|basic_auth|gateway).*>.{8,}<")
    r.check("No secrets in string resources", not res_secret,
            "resources.arsc is plain UTF-8; unzip and aapt2 read it without decompilation")

    bc = grep_src(r"buildConfigField.*(KEY|SECRET|TOKEN)")
    gradle = read(os.path.join(PROJECT, "app", "build.gradle"))
    bc_gradle = re.search(r"buildConfigField.*(KEY|SECRET|TOKEN)", gradle, re.I)
    r.check("No secrets in BuildConfig fields", not bc and not bc_gradle,
            "BuildConfig constants land in classes.dex as plain strings")

    persisted = grep_src(r"put(String|Boolean)\s*\(\s*[\"'](password|pin|pin_enc|role)[\"']")
    r.check("No password, PIN or role persisted", not persisted,
            f"found: {[h[2][:60] for h in persisted]}" if persisted else "")

    ext = grep_src(r"getExternalStorage|Environment\.DIRECTORY_")
    r.check("No writes to shared external storage", not ext,
            "Files there are world-readable and survive uninstall")

    logs = grep_src(r"Log\.[dviwe]\s*\(.*(password|passwd|pin|token|national_id)")
    r.check("No credentials or PII written to logs", not logs,
            "logcat is collected by crash reporters and lands in bug reports")

    # --- false remediation: role protected rather than removed -------------
    enc_role = grep_src(r"EncryptedSharedPreferences|encrypt\s*\(")
    role_still = grep_src(r"[\"']role[\"']|getRole\s*\(")
    if enc_role and role_still:
        r.warn("Role protected rather than removed",
               "An encrypted store still hands the client an authorisation decision. "
               "The role must not be persisted at all -- the server asserts it as a claim. "
               "See your C1 layer choice for this finding.")

    return r


# ------------------------------------------------------------------ CP2
def cp2():
    """M10 Cryptography."""
    r = Result("CP2")

    weak_alg = grep_src(r"getInstance\s*\(\s*[\"'](DES|DESede|RC2|RC4|MD5|SHA-?1)\b")
    r.check("No broken cryptographic primitives", not weak_alg,
            f"found: {[h[2][:60] for h in weak_alg]}" if weak_alg else "")

    ecb = grep_src(r"[\"'][A-Z0-9]+/ECB/")
    r.check("No ECB mode", not ecb, "ECB preserves plaintext structure")

    unauth = grep_src(r"[\"']AES/CBC/")
    r.check("AEAD mode used rather than unauthenticated CBC", not unauth,
            "Unauthenticated CBC is malleable; use AES/GCM/NoPadding")

    static_iv = grep_src(r"IvParameterSpec\s*\(\s*(STATIC_IV|[\"'])")
    r.check("No fixed initialisation vector", not static_iv,
            "A fixed IV makes encryption deterministic")

    insecure_rng = grep_src(r"new\s+Random\s*\(")
    # allow non-security use if clearly annotated
    insecure_rng = [h for h in insecure_rng if "jitter" not in h[2].lower()]
    r.check("SecureRandom used for security-relevant values", not insecure_rng,
            "java.util.Random is an LCG; its state is recoverable from a few outputs")

    keystore = grep_src(r"AndroidKeyStore|KeyGenParameterSpec")
    r.check("Key material comes from the Android Keystore", bool(keystore),
            "A key in the binary is an encoding, not a key")

    hardcoded_key = grep_src(r"(SecretKeySpec|DESKeySpec)\s*\(\s*[\"']")
    r.check("No hardcoded key material", not hardcoded_key)

    # --- fail-closed: no catch that returns the input ----------------------
    failopen = []
    for path in java_files():
        clean = strip_comments(read(path))
        for m in re.finditer(r"catch\s*\([^)]*\)\s*\{([^}]{0,240})\}", clean, re.S):
            blk = m.group(1)
            if re.search(r"return\s+(plaintext|pt|input|value|password)\s*;", blk):
                failopen.append(os.path.relpath(path, SRC))
    r.check("Cryptographic operations fail closed", not failopen,
            f"a catch block returns its input in {set(failopen)}" if failopen else "")

    # --- false remediation: hashPassword strengthened, not deleted ---------
    hp = grep_src(r"\bhashPassword\s*\(")
    if hp:
        kdf = grep_src(r"PBKDF2|Argon2|scrypt|SecretKeyFactory")
        callers = [h for h in hp if "public static" not in h[2] and "private static" not in h[2]]
        if kdf and not callers:
            r.warn("Client-side password hash strengthened rather than deleted",
                   "hashPassword() has no callers once authentication is server-side. "
                   "Upgrading MD5 to a memory-hard KDF closes the scanner finding and "
                   "leaves the client doing something only a server should do. "
                   "The correct remediation is deletion.")

    return r


# ------------------------------------------------------------------ CP3
def cp3():
    """M4 Input and output validation."""
    r = Result("CP3")

    concat_sql = grep_src(r"(rawQuery|execSQL)\s*\(\s*[\"'][^\"']*[\"']\s*\+")
    r.check("No SQL built by string concatenation", not concat_sql,
            f"found at {[f'{h[0]}:{h[1]}' for h in concat_sql]}" if concat_sql else "")

    bound = grep_src(r"rawQuery\s*\([^,]+,\s*new\s+String\[\]")
    r.check("Parameterised queries in use", bool(bound),
            "Pass bound arguments as a String[] rather than concatenating")

    allowlist = grep_src(r"(SORTABLE|ALLOWED_COLUMNS|allowedColumns)")
    rejects = grep_src(r"throw\s+new\s+IllegalArgumentException")
    r.check("ORDER BY identifier allow-listed", bool(allowlist),
            "Identifiers cannot be bound; use an allow-list")
    r.check("Allow-list rejects rather than substituting a default", bool(rejects),
            "Silently defaulting hides both a bug and an attack probe")

    bridge = grep_src(r"addJavascriptInterface")
    r.check("No JavaScript bridge exposed to the WebView", not bridge,
            "A bridge exposes native methods to whatever page loads")

    file_access = grep_src(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true|"
                           r"setAllowFileAccessFromFileURLs\s*\(\s*true")
    r.check("WebView file access from file URLs disabled", not file_access)

    intent_url = grep_src(r"loadUrl\s*\(\s*(target|url|getIntent|data\.)")
    r.check("WebView does not load a URL taken from an Intent", not intent_url,
            "The URL must not be attacker-influenceable")

    # amount validated for meaning, not just type
    meaning = grep_src(r"(signum\s*\(\)|scale\s*\(\)|BigDecimal|isNaN|isInfinite)")
    r.check("Transfer amount validated for meaning", bool(meaning),
            "parseDouble accepts negatives, NaN and Infinity. Check sign, scale and finiteness")

    return r


# ------------------------------------------------------------------ CP4
def cp4():
    """M5 Transport."""
    r = Result("CP4")

    tm = grep_src(r"X509TrustManager|implements\s+TrustManager")
    r.check("No custom TrustManager", not tm,
            "The platform validates chains correctly by default. Delete it")

    hv = grep_src(r"HostnameVerifier|setDefaultHostnameVerifier")
    r.check("No custom HostnameVerifier", not hv)

    sf = grep_src(r"setDefaultSSLSocketFactory|SSLContext\.getInstance")
    r.check("No custom SSLSocketFactory", not sf)

    http = grep_src(r"[\"']http://(?!localhost|127\.0\.0\.1)")
    r.check("No plaintext HTTP endpoints", not http,
            f"found: {[h[2][:50] for h in http]}" if http else "")

    creds_in_url = grep_src(r"[\"'][^\"']*\?(user|pass|token)=")
    r.check("No credentials in URLs", not creds_in_url,
            "Query strings are written to proxy and server access logs")

    nsc = read(NSC)
    r.check("Cleartext traffic disabled in network security config",
            'cleartextTrafficPermitted="false"' in nsc.replace(" ", "")
            or "cleartextTrafficPermitted" not in nsc,
            "Set cleartextTrafficPermitted=\"false\" in the base config")
    r.check("User certificate store not trusted",
            'src="user"' not in nsc.replace(" ", ""),
            "Trusting user CAs makes an interception proxy transparent")

    manifest = read(MANIFEST)
    r.check("usesCleartextTraffic not enabled in the manifest",
            'android:usesCleartextTraffic="true"' not in manifest.replace(" ", ""))

    return r


# ------------------------------------------------------------------ CP5
def cp5(session, run_behavioural=True):
    """M8 Configuration · M3 Authorisation. Includes the behavioural test."""
    r = Result("CP5")
    manifest = read(MANIFEST)
    flat = manifest.replace(" ", "").replace("\n", "")

    # --- static posture ----------------------------------------------------
    r.check("Application not marked debuggable in the manifest",
            'android:debuggable="true"' not in flat,
            "The build type owns debuggable; a manifest entry applies to release too")

    r.check("Backup disabled or exclusions declared",
            'android:allowBackup="false"' in flat or "dataExtractionRules" in flat,
            "allowBackup copies the whole data directory unless excluded")

    # exported components must either be false or carry a permission
    exported_blocks = re.findall(
        r"<(activity|provider|receiver|service)\b[^>]*android:exported\s*=\s*\"true\"[^>]*>",
        manifest, re.S)
    unguarded = [b for b in exported_blocks
                 if "android:permission" not in b and "LAUNCHER" not in b]
    r.check("No unguarded exported components",
            not unguarded,
            f"{len(unguarded)} exported without android:permission" if unguarded else "")

    if "protectionLevel" in manifest:
        r.check("Signature-level permission declared for internal callers",
                'android:protectionLevel="signature"' in flat,
                "Use signature protection level so only your own apps qualify")

    # --- authorisation must have left the client ---------------------------
    role_gate = grep_src(r"(getRole\s*\(|\"ADMIN\"\.equals|ADMIN_DAILY_LIMIT|CUSTOMER_DAILY_LIMIT)")
    r.check("No client-side role or limit gate", not role_gate,
            f"found: {[f'{h[0]}:{h[1]}' for h in role_gate]}" if role_gate else "")

    preauth = grep_src(r"vb_preauth|getBooleanExtra\s*\(\s*[\"']\w*preauth")
    r.check("No Intent extra bypasses a security check", not preauth,
            "A flag that skips a check is a backdoor regardless of the expected sender")

    submits = grep_src(r"(submitToBackend|submitTransfer)\s*\(")
    intent_triggered = []
    for path in java_files():
        clean = strip_comments(read(path))
        for m in re.finditer(r"(handlePreAuthorisedIntent|prefillFromIntent)\s*\([^)]*\)\s*\{(.{0,900}?)\n\s{4}\}",
                             clean, re.S):
            if re.search(r"(submitToBackend|submitTransfer|api\.)", m.group(2)):
                intent_triggered.append(os.path.relpath(path, SRC))
    r.check("Intent extras pre-fill but never trigger an action", not intent_triggered,
            f"an Intent path still submits in {set(intent_triggered)}" if intent_triggered else "")

    src_in_body = grep_src(r"submitTransfer\s*\(\s*[\"']HR\d|fromIban")
    r.check("Transfer request does not name its own source account", not src_in_body,
            "The server derives the source from the authenticated principal")

    # --- false remediation: query fixed, component still exported ----------
    if not grep_src(r"(rawQuery|execSQL)\s*\(\s*[\"'][^\"']*[\"']\s*\+"):
        prov = re.search(r"<provider\b[^>]*>", manifest, re.S)
        if prov and 'android:exported="true"' in prov.group(0).replace(" ", ""):
            r.warn("Injection closed but the component is still exported",
                   "Parameterising the query closes the injection and leaves every row "
                   "reachable by any installed application. Both fixes are needed: "
                   "exported=\"false\" closes reachability, parameterisation closes the "
                   "weakness regardless of caller.")

    # --- behavioural test --------------------------------------------------
    if run_behavioural:
        ok, detail = behavioural_exploit_test()
        r.check("BEHAVIOURAL: the N1 Intent exploit is refused", ok, detail)
    else:
        r.check("BEHAVIOURAL: skipped (--no-build)", False,
                "CP5 cannot be awarded without the behavioural test. Rerun without --no-build")

    return r


def behavioural_exploit_test():
    """
    Build, install, and actually attempt the exploit. Passing requires the
    transfer to be refused -- not merely for the manifest to look correct.
    """
    rc, out, err = sh("./gradlew assembleDebug -q", timeout=420, cwd=PROJECT)
    if rc != 0:
        return False, "the project does not build; fix compilation before validating CP5"

    apk = os.path.join(PROJECT, "app", "build", "outputs", "apk", "debug", "app-debug.apk")
    if not os.path.exists(apk):
        return False, "build produced no debug APK"

    sh(f"adb uninstall {PACKAGE}", timeout=60)
    rc, out, err = sh(f"adb install -r {apk}", timeout=180)
    if rc != 0:
        return False, "could not install the rebuilt APK on the emulator"

    sh("adb logcat -c", timeout=30)

    # the six-line exploit from N1, as an am start
    rc, out, err = sh(
        "adb shell am start "
        "-a eu.cadmus.vulnbank.ACTION_TRANSFER "
        "--es vb_to HR0000000000000000099 "
        "--es vb_amount 50000.00 "
        "--ez vb_preauth true",
        timeout=90)

    combined = (out + err)
    # Refused at the platform boundary -- the component is no longer reachable.
    # "unable to resolve Intent": the intent filter is gone, nothing outside the
    # app can address the action any more (revision 2 - a correct fix failed here).
    if re.search(r"Permission Denial|does not exist|not exported|SecurityException|unable to resolve",
                 combined, re.I):
        return True, ""

    # It started. Did it actually submit anything?
    import time
    time.sleep(3)
    rc_p, pid, _ = sh(f"adb shell pidof {PACKAGE}", timeout=20)
    pid = pid.strip().split()[0] if pid.strip() else ""
    rc2, log, _ = sh(f"adb logcat -d --pid={pid}" if pid.isdigit() else "adb logcat -d -t 400",
                     timeout=60)
    if re.search(r"(submitTransfer|POST /api/v1/transfer|Transfer submitted|Transfer body|preauth=true)",
                 log, re.I):
        return False, ("the activity started AND submitted a transfer from a crafted Intent. "
                       "The exploit still works: correct the export posture and move the "
                       "authorisation decision to the server")
    if re.search(r"Starting: Intent", combined, re.I):
        return False, ("the activity is still launchable by an external Intent. Even though no "
                       "transfer was submitted, an unauthenticated caller reaches this screen")
    return True, ""


# ------------------------------------------------------------------ report
CHECKPOINTS = {"CP1": cp1, "CP2": cp2, "CP3": cp3, "CP4": cp4}


def run(name, session, build=True):
    if name == "CP5":
        return cp5(session, run_behavioural=build)
    return CHECKPOINTS[name]()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--checkpoint", default="all",
                    choices=["all", "CP1", "CP2", "CP3", "CP4", "CP5"])
    ap.add_argument("--no-build", action="store_true",
                    help="skip the CP5 behavioural test (CP5 cannot be awarded)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    names = ["CP1", "CP2", "CP3", "CP4", "CP5"] if a.checkpoint == "all" else [a.checkpoint]
    results = [run(n, a.session, build=not a.no_build) for n in names]

    awarded = sum(POINTS[r.cp] for r in results if r.passed)
    cp5 = next((r for r in results if r.cp == "CP5"), None)

    if a.json:
        print(json.dumps({
            "session": a.session,
            "points_awarded": awarded,
            "cp5_satisfied": bool(cp5 and cp5.passed) if cp5 else None,
            "checkpoints": [{
                "checkpoint": r.cp, "satisfied": r.passed, "points": POINTS[r.cp] if r.passed else 0,
                "checks": [{"name": n, "passed": ok, "guidance": g if not ok else ""}
                           for n, ok, g in r.checks],
                "false_remediation_warnings": [{"title": t, "detail": d} for t, d in r.warnings],
            } for r in results],
        }, indent=2))
        sys.exit(0 if all(r.passed for r in results) else 1)

    print(f"\nCR2 checkpoint validation — session {a.session}")
    for r in results:
        head = f"{r.cp}  {'SATISFIED' if r.passed else 'NOT SATISFIED'}"
        print("\n" + "=" * 68)
        print(f"  {head}   ({POINTS[r.cp] if r.passed else 0}/{POINTS[r.cp]} points)")
        print("=" * 68)
        for n, ok, g in r.checks:
            print(f"  [{'PASS' if ok else 'FAIL'}]  {n}")
            if not ok and g:
                print(f"          -> {g}")
        for t, dt in r.warnings:
            print(f"\n  [!! FALSE REMEDIATION ]  {t}")
            for line in _wrap(dt, 62):
                print(f"          {line}")

    print("\n" + "=" * 68)
    print(f"  Points: {awarded}/500     Pass mark: 350")
    if cp5:
        print(f"  CP5 (mandatory): {'satisfied' if cp5.passed else 'NOT SATISFIED'}")
        if awarded >= 350 and not cp5.passed:
            print("\n  You have reached the points threshold but CP5 is not satisfied.")
            print("  CR2 is not passed: the application remains exploitable.")
    print("=" * 68 + "\n")

    sys.exit(0 if all(r.passed for r in results) else 1)


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


if __name__ == "__main__":
    main()
