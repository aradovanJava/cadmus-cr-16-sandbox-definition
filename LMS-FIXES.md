# CR-16 — corrections to the LMS exercise material (revision 2)

The validators and the CR4 scenario pack on the LMS (course 44, resources 8288, 8299,
8307, 8316 and 8313) could not work as published in the Cyber Range. The corrected
copies are in [`provisioning/files/cadmus/`](provisioning/files/cadmus/) and are
installed on MOB1 as `/opt/cadmus/cr1_validate.py` … `cr4_validate.py` and
`/opt/cadmus/exploits/run_scenarios.py` (the paths the CR2 guide uses).

**The LMS has not been changed.** These files replace the LMS copies only after they
have passed in the sandbox and the course owner has confirmed.

| # | Problem in the LMS version | Correction |
|---|---|---|
| 1 | `run_scenarios.py` **EX-06** could never report the vulnerable app: Android 8+ does not deliver an implicit broadcast to a manifest receiver, and the log line it looked for (`persistSession…ADMIN`) is never written. | The broadcast names the package (`-p eu.cadmus.vulnbank`, `FLAG_INCLUDE_STOPPED_PACKAGES`). The effect is checked behaviourally: the session role is read before and after (with `run-as`, or `su` on the google_apis emulator when the build is not debuggable). A platform `Permission Denial` counts as refused. |
| 2 | **EX-04** read the whole device log and the app sent no request on launch. | The scenario drives the real login screen (uiautomator + `input`) with the fabricated demo account, reads only the app's process log (`logcat --pid`), and asks the mock backend (`docker logs vulnbank-backend`) whether a plain-HTTP request arrived. The participant app now sends the login to the backend (see the app repository's README). |
| — | EX-01/EX-03 also read the whole device log; EX-02 lost its SQL payload to shell quoting; EX-05 found no session store when nobody had logged in. | Process-local logs and backend evidence for EX-01/03; the EX-02 selection is quoted for the device shell (`' OR '1'='1`); EX-05 logs in first when no session exists. |
| 3 | CR3 runs `./gradlew analyzeDependencies` but the project had no such task or plugin. | The participant repository defines `analyzeDependencies` (Dependency Analysis Gradle Plugin 2.17.0, `buildHealth`). |
| 4 | CR1/CR3/CR4 validators read files from `$CR_SESSION_DIR/$CR_SESSION/` (`a1_artefact.json`, `a3_counts.json`, `mobsf_report.json`, `zap_alerts.json/xml`, `dependency_register.json`, `vex.json`, `risk_exposure.md`, `cr1_findings.json`, `pipeline_run.json`, `evidence_bundle.json`, `residual_coverage.md`); no guide says where or in which format. | The sandbox sets `CR_SESSION=cr16`, `CR_SESSION_DIR=~/cr-session` and puts a README with every file, its level and its format in `~/cr-session/cr16/`. The validators' guidance now prints the expected path and format; the default directory is `~/cr-session`. The training definition repeats this per level. |
| 5 | Validators defaulted to `/home/trainee/vulnbank`; the platform account is `user`. | Defaults are `~/vulnbank` (and the sandbox sets `CR2_PROJECT`, `CR2_SRC`, `CR3_PROJECT`, `CR4_PROJECT`). |
| 6 | CR3 D2 "the functional test suite passes": the app had no tests, so the gate checked nothing. | The participant repository has Robolectric smoke tests (every screen must start). `cr3_validate.py` D2 now also requires that at least one test was executed. |
| — | CR1 A3 needed `SONAR_ADMIN_TOKEN`, which no guide mentions, and called an admin-only API. | Falls back to `SONAR_TOKEN` (a user token) and reads the project with `api/components/show`. |

## Further observations for the course report (no change made)

- The framework assumes Windows tooling on the workstation, but the CR1–CR4 guides are
  written for a Linux shell (`adb`, `./gradlew`, `docker`, `sha256sum`). The sandbox
  runs them on MOB1 (Ubuntu) and SC1 reaches it through VS Code Remote-SSH, SSH and scrcpy.
- The course shipped no backend for `vulnbank.local` / `support.vulnbank.local`; ZAP had
  nothing to observe. Now provided: [cadmus-cr-16-vulnbank-backend](https://github.com/aradovanJava/cadmus-cr-16-vulnbank-backend).
- The participant ZIP did not build (Material3 theme with material 1.4.0, missing
  keystore, lint vetoing `assembleRelease`, no Gradle wrapper, non-literal plugin version).
- 8 of the 9 third-party libraries declared in `app/build.gradle` are referenced by no
  code; CR3's "unused dependency" finding is therefore most of the dependency list.
- CR1 A1 says "Both dynamic analysis containers healthy? `docker ps`": on MOB1 that shows
  MobSF (`MSF1`) and the backend; ZAP runs on OWZ1.
- CR1 A2 "check the session history" in ZAP: the sandbox's ZAP is a daemon (proxy + API);
  the history is at `http://zap.sandbox.local:8080/UI/core/view/messages/`.
