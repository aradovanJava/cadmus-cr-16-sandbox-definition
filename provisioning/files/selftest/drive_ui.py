#!/usr/bin/env python3
"""CADMUS-CR-16 · MOB1 · provisioning self-test helper (not for trainees).

Uses the login driver of the CR4 harness to do what CR1 A2 asks a person to do:
log in with the fabricated demo account and submit one transfer.
"""
import sys
import time

sys.path.insert(0, "/opt/cadmus/exploits")
import run_scenarios as rs  # noqa: E402

if not rs.drive_login("demo", "demo"):
    print("login screen: fields not found")
    sys.exit(1)
print("login screen: demo / demo submitted")
time.sleep(2)
nodes = rs.ui_nodes()
to = rs.find(nodes, ":id/input_to_iban", "EditText", 0)
amount = rs.find(nodes, ":id/input_amount", "EditText", 1)
button = rs.find(nodes, ":id/button_transfer", "Button", 0)
if not (to and amount and button):
    print("transfer screen: not reached")
    sys.exit(1)
rs.tap(to)
rs.adb_shell("input text HR0000000000000000099")
rs.tap(amount)
rs.adb_shell("input text 10.00")
rs.tap(rs.find(rs.ui_nodes(), ":id/button_transfer", "Button", 0) or button)
time.sleep(4)
print("transfer screen: 10.00 to HR0000000000000000099 submitted")
