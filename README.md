# CADMUS-CR-16 · Secure Coding Mobile — sandbox definition

Sandbox definition for the CADMUS CyberRangeᶜᶻ platform (cr.cybersecurity-training.cti.gr)
used by the CADMUS bootcamp **BTCMP-02 Secure Coding**, Cyber Range course
**CADMUS-CR-16 Secure Coding Mobile** (LMS course 44).

It implements section 2 *Training Scenario Architecture* of the *CADMUS-CR-16 Cyber Range
Training Scenario Framework*: a Windows 11 workstation, the two Docker hosts carrying the
SAST and DAST tools, and a Linux mobile lab host with the Android emulator, because the
CR1–CR4 guides are written for a Linux shell. The application under test is
[`aradovanJava/cadmus-vulnbank-mobile-cr`](https://github.com/aradovanJava/cadmus-vulnbank-mobile-cr)
— *VulnBank*, a deliberately vulnerable Android banking client (participant distribution of
the LMS ZIP plus the documented build changes) — talking to the mock backend
[`aradovanJava/cadmus-cr-16-vulnbank-backend`](https://github.com/aradovanJava/cadmus-cr-16-vulnbank-backend).

> **Training system.** App and backend are deliberately vulnerable; every credential, key,
> IBAN and customer record is fabricated. Both stay inside the sandbox.

## Topology

```
                   internet-connection (WAN)
                             |
                          router  10.10.10.1
                             |
 dev-lan 10.10.10.0/24 ------+--------------------+--------------------+--------------------+
                             |                    |                    |                    |
                    sc1  10.10.10.10      mob1  10.10.10.11      sq1  10.10.10.20      owz1  10.10.10.30
                    VM1  Windows 11       mobile lab host        VM3  SonarQube        VM2  OWASP ZAP
                    RDP, VS Code          emulator (KVM), SDK,   (Docker, SAST)        (Docker, DAST)
                    Remote-SSH, scrcpy    Gradle, MobSF, backend
```

| Host | Framework ID | Image | Flavor | Role |
|---|---|---|---|---|
| `sc1` | VM1 · SC1 | `windows-11-x86_64` | `c4_r8_d60` | Trainee workstation (RDP). Works on MOB1 through VS Code Remote-SSH and SSH; shows the emulator with scrcpy |
| `mob1` | — · MOB1 | `ubuntu-noble-x86_64` | `c4_r8_d60` | Android SDK 34, emulator (google_apis x86_64, KVM), JDK 17, the project in `~/vulnbank`, MobSF (`MSF1`), mock backend, validators in `/opt/cadmus` |
| `sq1` | VM3 · SQ1 | `ubuntu-noble-x86_64` | `c4_r8_d40` | SonarQube Community Build 26.1 in Docker (Standard Experience) |
| `owz1` | VM2 · OWZ1 | `ubuntu-noble-x86_64` | `c4_r8_d40` | OWASP ZAP daemon in Docker: proxy and API on port 8080, no API key |
| `router` | — | `debian-12-x86_64` | `standard.small` | Gateway |

`mob1` uses the image/flavor pair that the CR-16 probe sandbox showed to expose `/dev/kvm`
(nested virtualisation). `binder` is not available there, so Android-in-Docker (redroid) is
not an option; the emulator runs headless with KVM.

### Names (resolved on every machine and inside the emulator)

| Name | Host | Used by |
|---|---|---|
| `mobsf.sandbox.local:8000` | MOB1 | CR1 A1/A2 (MobSF web: `mobsf` / `mobsf`; REST key: `docker logs MSF1 \| grep -i "api key"`) |
| `zap.sandbox.local:8080` | OWZ1 | CR1 A2 — emulator proxy and ZAP API |
| `sonarqube.sandbox.local:9000` | SQ1 | CR1 A3, CR4 E1 (`admin` / `admin`, change forced at first login) |
| `vulnbank.local`, `support.vulnbank.local` | MOB1 :80 | the app's backend and support portal |

Android does not read MOB1's `/etc/hosts`, so the provisioning writes the same names into
the emulator's `/system/etc/hosts` (the emulator runs with `-writable-system`) and then
returns `adbd` to an unprivileged shell, exactly what the CR4 scenarios assume.

### MOB1 layout

| Path | What it is |
|---|---|
| `~/vulnbank` | the participant repository, built once (`assembleRelease`, `test`) |
| `/opt/cadmus/vulnbank/app-release.apk` (+ `.sha256`) | the artefact CR1 analyses |
| `/opt/cadmus/cr1_validate.py` … `cr4_validate.py` | course validators, revision 2 ([LMS-FIXES.md](LMS-FIXES.md)) |
| `/opt/cadmus/exploits/run_scenarios.py` | CR4 scenario pack, revision 2 (copy into `~/vulnbank/exploits/` in CR4) |
| `~/cr-session/cr16/README.txt` | every file the validators read, with level and format |
| `/etc/profile.d/cadmus-cr16.sh` | `ANDROID_*`, `ANDROID_SERIAL`, `CR_SESSION`, `CR_SESSION_DIR`, `CR2_PROJECT`, `CR2_SRC`, `CR3_PROJECT`, `CR4_PROJECT`, `MOBSF`, `ZAP`, `SQ` |
| `/opt/cadmus/docker-compose.yml` | containers `MSF1` (MobSF) and `vulnbank-backend` |
| systemd `cadmus-adb`, `cadmus-emulator` | adb server on all interfaces (port 5037) and the headless emulator `emulator-5554` |
| systemd `cadmus-nvd-warmup` | one-off NVD download for Dependency-Check, started after provisioning |

## Access

| | |
|---|---|
| Account on all machines | `user` / `Password123` — the platform's standard sandbox account (administrator + RDP on SC1, sudo + docker on the Linux hosts). Never changed by this definition. |
| SC1 desktop | *VulnBank project (VS Code on MOB1)*, *MOB1 shell (ssh)* (key-based, no password), *VulnBank emulator screen* (scrcpy via `ADB_SERVER_SOCKET=tcp:10.10.10.11:5037 … --tunnel-host=10.10.10.11`), browser links to MobSF, ZAP history and SonarQube |

## Design decisions

1. **The guides' shell is MOB1.** Every command in CR1–CR4 (`adb`, `./gradlew`, `docker`,
   `sha256sum`, `python3 /opt/cadmus/…`) runs there. SC1 is the framework's Windows
   workstation and reaches MOB1 with VS Code Remote-SSH; the emulator screen comes to SC1
   with scrcpy against MOB1's adb server. Both sides use the same `platform-tools-latest`
   archive, fetched in the same allocation.
2. **SonarQube and ZAP on their own hosts, as in CR-14/CR-15.** ZAP runs as a daemon so
   that `zap.sandbox.local:8080` is proxy and API at once (CR1 A2 sets it as the emulator's
   global proxy; the A2 validator reads `core/view/urls`).
3. **SonarQube Standard Experience**: the guides count Vulnerabilities, Bugs, Code Smells and
   Security Hotspots; `admin`/`admin` stays untouched.
4. **Validators corrected, LMS untouched** — see [LMS-FIXES.md](LMS-FIXES.md).
5. **Self-tests at every allocation** (`cr16_self_test`), printed as `SELF-TEST` lines in
   the user-ansible log: build and smoke tests, install and launch, backend reachable
   from MOB1 and from the emulator, the CR1 A2 ZAP path (proxy set, login and transfer
   driven on the emulator, both requests in the ZAP history), MobSF key from the container
   log + upload + scan, `./gradlew sonar` with the four counts, `analyzeDependencies`,
   `cyclonedxBom`, the CR4 harness against the unmodified build (all six attacks must
   still succeed), the validators run without a traceback; on SC1: adb through MOB1's
   server, SSH key login, tool URLs. Everything is removed again afterwards (no MobSF
   scan, no SonarQube project or token, new ZAP session, emulator proxy unset, app
   uninstalled, project tree clean).
6. **Level E1 (GitHub Actions)** runs on GitHub. Trainees fork the participant repository
   and point `origin` of `~/vulnbank` at their fork.

## Using it on the platform

1. **Sandboxes → Definition → Create**: Git URL
   `https://github.com/aradovanJava/cadmus-cr-16-sandbox-definition.git`, revision = the full
   SHA of the commit to use (the platform reads `topology.yml` at creation and does not
   follow a branch).
2. **Sandboxes → Pool → Create** from that definition; size = number of trainees.
3. **Allocate.** MOB1 (SDK download, first Gradle build, emulator boot) and SC1 dominate:
   count on 75–100 minutes for a fresh allocation.
4. Link the pool to the training instance built from the CR-16 training definition.

## Notes for instructors

- For a course delivery pin `cr16_app_ref` (and keep `cr16_backend_ref`) to full SHAs in
  `provisioning/group_vars/all.yml`, then create the definition from that commit.
- `dependencyCheckAnalyze` needs the NVD data. The sandbox downloads it in the background
  after provisioning (`journalctl -u cadmus-nvd-warmup`, log in `~/.cache/`); without an NVD
  API key that takes 20–60 minutes. A key can be exported as `NVD_API_KEY` on MOB1.
- Restart the emulator with `sudo systemctl restart cadmus-emulator`; the lab names in its
  `/system/etc/hosts` survive restarts.
- The CR4 harness observes EX-06 with `su` when the participant's build is not debuggable;
  the google_apis system image provides it. Keep that image.

## Repository layout

```
topology.yml                         hosts, router, network, addressing
LMS-FIXES.md                         what was corrected in the LMS validators and why
provisioning/
├── playbook.yml                     Linux base, SQ1, OWZ1, MOB1, MOB1 self-test, SC1, SC1 check
├── requirements.yml                 roles and collections
├── group_vars/all.yml               credentials, IPs, names, images, versions, switches
├── files/cadmus/                    validators (rev. 2) and exploits/run_scenarios.py
├── files/selftest/                  self-test UI helper
└── templates/                       compose files, systemd units, environment, READMEs, self-tests
```

The CR-16 probe sandbox (virtualisation check) is on branch `probe`.

---

Co-funded by the European Union (Digital Europe Programme, grant agreement
101190006 — CADMUS). Views and opinions expressed are those of the author(s)
only and do not necessarily reflect those of the European Union or HaDEA.
