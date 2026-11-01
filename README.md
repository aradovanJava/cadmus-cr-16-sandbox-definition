# CADMUS-CR-16 probe sandbox (throw-away)

Two hosts, no course content. Allocation takes ~10 min on lx1 and ~5 min extra for sc1's first SSH boot.

How to read the result: in the sandbox allocation log (user-ansible stage) find the tasks
`PROBE RESULT (lx1)` and `PROBE RESULT (sc1)`, or log in and read `/home/user/probe-report.txt`
and `C:\Users\Public\probe-report.txt`.

## Decision table

| Observation | Meaning |
|---|---|
| lx1: `/dev/kvm` exists and `kvm-ok` says "KVM acceleration can be used" | Android emulator with acceleration works on the Linux workstation. Best case. |
| lx1: no `/dev/kvm`, binder module loads (or `binder` in /proc/filesystems) | No emulator acceleration, but redroid (Android in Docker) is feasible. |
| lx1: neither | No usable Android runtime on Ubuntu; test the Windows side / other images. |
| sc1: `VMMonitorModeExtensions: True` and `HypervisorPlatform` available | Android Emulator can use WHPX on Windows (needs a reboot after enabling the feature). |
| sc1: `VMMonitorModeExtensions: False` | No acceleration on Windows; emulator would run software-only (unusably slow). |

Delete the sandbox, pool and definition when done (ask the instructor first, per the working rules).
