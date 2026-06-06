#!/usr/bin/python3

def Help():
    print('\033[93m\n{:<12} {}\n{}'.format("Command", "Description", "=" * 79))
    
    Modules = {
        "back":     "Background the current interactive session and return to main menu.",
        "exit":     "Terminate the console and exit the framework.",
        "help":     "Display this help menu with commands description.",
        "password": "Configure the authentication secret for incoming agent connections.",
        "kill":     "Terminate a specific active agent session using its PID.",
        "killall":  "Terminate all running listener jobs and active agent processes.",
        "jobs":     "List all active background listener jobs and connected agents.",
        "lhost":    "Configure the local listening host IP address.",
        "lport":    "Configure the local listening port number.",
        "run":      "Launch the listener service using the current configurations.",
        "select":   "Interact directly with a specified active agent session.",
        "set":      "Assign a value to a specific configuration variable.",
        "build":    "Generate a standard reverse shell payload source code."
    }
    
    for icmd, idesc in Modules.items():
        print('{:<12} {}'.format(icmd, idesc))
    print("\n\033[0m")

HelpCommands = ["back", "exit", "help", "kill", "killall", "lhost", "lport", "jobs", "run", "select", "set", "password", "build"]

def HelpCommandCompletion(text, state):
    matches = [cmd for cmd in HelpCommands if cmd.startswith(text)]
    if state < len(matches):
        return matches[state]
    return None
