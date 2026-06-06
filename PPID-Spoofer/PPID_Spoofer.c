#include <stdio.h>
#include <Windows.h>

#pragma warning(disable:4996)

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("[!] Usage error - required arguments missing\n");
		printf("	Format : Application.exe <ParentProcessID>\n");
		printf("	Example : notepad.exe 4562");
		return -1;
	}
	
	char WinDir[MAX_PATH];
	char CurrentDir[MAX_PATH];
	HANDLE hProcess = NULL;
	HANDLE hParentProcess = NULL;

	STARTUPINFOEX SiEx;
	PROCESS_INFORMATION Pi;
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEX));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEX);

	size_t sProcThread = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST lProcThreadList = NULL;

	// ------------------------------------------------

	if (!GetEnvironmentVariableA("windir", WinDir, MAX_PATH))
	{
		return -1;
	}
	sprintf(CurrentDir, "%s\\System32", WinDir);
	
	// -----------------------------------------------

	printf("[!] The system directory is set as the new process’s current directory : %s\n", CurrentDir);

	// ----------------------------------------------

	
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sProcThread);


	lProcThreadList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sProcThread);


	if(!InitializeProcThreadAttributeList(lProcThreadList, 1, NULL, &sProcThread))
	{
		
		return -1;
	}

	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, atoi(argv[2]));

	UpdateProcThreadAttribute(lProcThreadList,
		NULL,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&hParentProcess,
		sizeof(HANDLE),
		NULL,
		NULL);

	SiEx.lpAttributeList = lProcThreadList;


	// ----------------------------------------------

	CreateProcessA(NULL,
		argv[1],
		NULL,
		NULL,
		0,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		CurrentDir,
		&SiEx.StartupInfo,
		&Pi);


	DeleteProcThreadAttributeList(lProcThreadList);
	CloseHandle(hParentProcess);
	printf("Created process ID: %d\n", Pi.dwProcessId);

	return 0;
}
