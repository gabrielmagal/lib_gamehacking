#include <Windows.h>
#include <string>
#include <iostream>
#include <time.h>
#include <tlhelp32.h>
#include "LibraryGameHacking.h"

GameHacking gameHacking;

#pragma region Tools
MODULEINFO Tools::GetModuleInfo(const char* szModule) {
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandleA(szModule);
	if (hModule != 0) GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}

bool Tools::checkName(const char* name) {
	char filename[MAX_PATH];
	GetModuleFileNameA(0, filename, MAX_PATH);
	std::string search = filename;
	int found = search.find(name);
	if (found > 0) return true;
	return false;
}


void Tools::waterMark() {
	setlocale(LC_ALL, "pt-br.UTF-8");
	wprintf(L"╔══╗───╔═══╗╔═══╗─╔╗╔═══╗────╔══╗─╔╗─╔╗─────╔═╦═╗──────────────\n");
	wprintf(L"║═╦╝╔╦╗║╔═╗║║╔═╗║╔╝║║╔═╗║╔═╦╗║╔╗║╔╝║─║╚╗╔══╗║║║║║╔═╗─╔═╗╔═╗─╔╗─\n");
	wprintf(L"║╔╝─║╔╝╚╝╔╝║╚╝╔╝║║╬║║║║║║║║║║║╔╗║╚╗║─║╔╣╚══╝║║║║║║╬╚╗║╬║║╬╚╗║╚╗\n");
	wprintf(L"╚╝──╚╝─╔╗╚╗║╔╗╚╗║╚═╝║║║║║╚╩═╝╚══╝─║║─╚═╝────╚╩═╩╝╚══╝╠╗║╚══╝╚═╝\n");
	wprintf(L"───────║╚═╝║║╚═╝║───║╚═╝║────────╔╝╚╗────────────────╚═╝───────\n");
	wprintf(L"───────╚═══╝╚═══╝───╚═══╝────────╝──╚──────────────────────────\n\n");
}


bool Tools::vecCmpValueExistArr(DWORD val, vector<DWORD> vec) {
	for (int i = 1; i < vec.size(); i++) 
		if (vec[i] == val) return true;
	return false;
}


void Tools::vecSaveValuesArr(DWORD varLog, vector <DWORD>&varSave, bool optLogMsg) {
	if (!vecCmpValueExistArr(varLog, varSave)) {
		varSave.push_back(varLog);
		if(optLogMsg)  printf_s("New Value: 0x%f\n", varLog);
	}
}

#pragma endregion

#pragma region MemoryMgr
void MemoryMgr::logValuesAddress(DWORD address) {
	vector<DWORD> valuesSaved;
	while (TRUE) {
		Tools::vecSaveValuesArr(*(DWORD*)(address), valuesSaved, true);
		Sleep(10);
	}
}

void MemoryMgr::memEdit(DWORD addr, const char arrBytes[], UINT size) {
	DWORD oldProtect;
	VirtualProtect((LPVOID)(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void*)(addr), arrBytes, size);
	VirtualProtect((LPVOID)(addr), size, oldProtect, &oldProtect);
}


LPVOID MemoryMgr::allocWriteEx(HANDLE hProcess, LPVOID pType, DWORD size) {
	LPVOID Alloc = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(Alloc) WriteProcessMemory(hProcess, Alloc, pType, size, 0);
	return Alloc;
}



DWORD MemoryMgr::returnPointer(DWORD address, UINT offset[], int size) {
	DWORD base = *(DWORD*)(address);
	if (base == 0) return 0;
	for (int i = 0; i < size; i++) {
		if (i == (size - 1)) return (DWORD)(base + offset[i]);
		if (*(DWORD*)(base + offset[i]) != 0) base = *(DWORD*)(base + offset[i]);
		else return 0;
	}
	return 0;
}


DWORD MemoryMgr::returnPointerMod(const char* mod, DWORD addBase, UINT offset[], int size) {
	DWORD base = (*(DWORD*)((DWORD)(GetModuleHandleA(mod)) + addBase));
	for (int i = 0; i < size; i++) {
		if (i == (size - 1))  return (DWORD)(base + offset[i]);
		if (*(DWORD*)(base + offset[i]) != 0) base = *(DWORD*)(base + offset[i]);
		else return 0;
	}
	return 0;
}


DWORD MemoryMgr::FindPatternModule(const char* module, const unsigned char pattern[], const char mask[]) {
	UINT found = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	MODULEINFO mInfo = Tools::GetModuleInfo(module);
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	for (int i = 0; i < (DWORD)mInfo.SizeOfImage; i++)
	{
		if (mask[found] == '?' || *(BYTE*)(base + i) == pattern[found]) {
			if (mask[found + 1] == '\0') {
				return ((base + i) - (strlen(mask) - 1));
			}
			found++;
		}
		else found = 0;
	}
	return 0;
}


DWORD MemoryMgr::FindPatternStartAddress(const unsigned char pattern[], const char mask[], DWORD startAddress, DWORD endAddress, UINT posScan)  {
	UINT addList = 0, found = 0;
	for (int i = 0; i < (endAddress - startAddress); i++) {
		if (mask[found] == '?' || *(BYTE*)(startAddress + i) == pattern[found]) {
			if (mask[found + 1] == '\0') {
				if (addList == (posScan - 1))
					return (startAddress + i) - (strlen(mask) - 1);
				addList++;
				found = 0;
			}
			else found++;
		}
		else found = 0;
	}
	return 0;
}

#pragma endregion


#pragma region PEHeader
void PEHeader::eraseEx(HMODULE hProcess, LPVOID lpStartAddress) {
	char zero[4096] = { '\0' };
	DWORD protect;
	VirtualProtectEx(hProcess, lpStartAddress, 4096, PAGE_EXECUTE_READWRITE, &protect);
	WriteProcessMemory(hProcess, lpStartAddress, &zero, 4096, 0);
	VirtualProtectEx(hProcess, lpStartAddress, 4096, protect, &protect);
}


void PEHeader::randomEx(HMODULE hProcess, LPVOID lpStartAddress) {
	srand(time_t(0));
	char zero[4096] = { '\0' };
	for (int i = 0; i < 4096; i++) zero[i] = rand() % 256;
	DWORD protect;
	VirtualProtectEx(hProcess, lpStartAddress, 4096, PAGE_EXECUTE_READWRITE, &protect);
	WriteProcessMemory(hProcess, lpStartAddress, &zero, 4096, 0);
	VirtualProtectEx(hProcess, lpStartAddress, 4096, protect, &protect);
}


void PEHeader::fakeEx(HMODULE hProcess, LPVOID lpStartAddress) {
	DWORD protect;
	VirtualProtectEx(hProcess, lpStartAddress, 4096, PAGE_EXECUTE_READWRITE, &protect);
	HINSTANCE hKernel32 = GetModuleHandleA("Kernel32.dll");
	if (hKernel32) WriteProcessMemory(hProcess, lpStartAddress, hKernel32, 4096, 0);
	VirtualProtectEx(hProcess, lpStartAddress, 4096, protect, &protect);
}


void peHeaderMgr(HANDLE hProcess, HANDLE hLoadThread, DWORD peModify, DWORD closeOnInject) {
	DWORD exitCode = 0;
	GetExitCodeThread(hLoadThread, &exitCode);
	gameHacking.logMsg.consoleLog(false, "exitCodeThread: 0x%X", exitCode);
	switch (peModify) {
		case 1: gameHacking.peHeader.eraseEx(reinterpret_cast<HMODULE>(hProcess), reinterpret_cast<LPVOID>(exitCode));
		case 2: gameHacking.peHeader.randomEx(reinterpret_cast<HMODULE>(hProcess), reinterpret_cast<LPVOID>(exitCode));
		case 3: gameHacking.peHeader.fakeEx(reinterpret_cast<HMODULE>(hProcess), reinterpret_cast<LPVOID>(exitCode));
	}

	if (closeOnInject == 1) exit(0);
}

#pragma endregion


#pragma region MethodInjection
void MethodInjection::standardA(LPCSTR path, const std::string& processName, DWORD peModify, DWORD closeOnInject, BOOL log) {
	DWORD pId = gameHacking.processProperties.findProcessId(processName);

	if (pId) hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

	if (hProcess == 0) {
		gameHacking.logMsg.consoleLog(false, "Fail to open process!");
		return;
	}

	lpParameter = gameHacking.memoryMgr.allocWriteEx(hProcess, (LPVOID)path, strlen(path) + 1);

	if (lpParameter == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}

	HINSTANCE hKernel32 = GetModuleHandleA("Kernel32.dll");
	if (hKernel32) lpStartAddress = reinterpret_cast<DWORD>(GetProcAddress(hKernel32, "LoadLibraryA"));

	if (lpStartAddress) hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, 0);

	if (!hThread) {
		gameHacking.logMsg.consoleLog(false, "Failed to create thread in process!");
		return;
	}

	if (log) {
		gameHacking.logMsg.consoleLog(false, "pId: 0x%X", pId);
		gameHacking.logMsg.consoleLog(false, "hProcess: 0x%X", hProcess);
		gameHacking.logMsg.consoleLog(false, "lpParameter: 0x%X", lpParameter);
		gameHacking.logMsg.consoleLog(false, "lpStartAddress: 0x%X", lpStartAddress);
		gameHacking.logMsg.consoleLog(false, "hThread: 0x%X", hThread);
	}

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		peHeaderMgr(hProcess, hThread, peModify, closeOnInject);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, lpParameter, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}
	else {
		gameHacking.logMsg.consoleLog(false, "LoadLibraryA failure injection!");
		return;
	}
	gameHacking.logMsg.consoleLog(true, "LoadLibraryA successfully injection!");
}


void MethodInjection::standardW(LPCWSTR path, const std::string& processName, DWORD peModify, DWORD closeOnInject, BOOL log) {
	DWORD pId = gameHacking.processProperties.findProcessId(processName);

	if (pId) hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

	if (hProcess == 0) {
		gameHacking.logMsg.consoleLog(false, "Fail to open process!");
		return;
	}

	lpParameter = gameHacking.memoryMgr.allocWriteEx(hProcess, (LPVOID)path, (wcslen(path) * 2) + 1);

	if (lpParameter == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}
	
	HINSTANCE hKernel32 = GetModuleHandleA("Kernel32.dll");
	if (hKernel32) lpStartAddress = reinterpret_cast<DWORD>(GetProcAddress(hKernel32, "LoadLibraryW"));

	if (lpStartAddress) hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, 0);

	if (!hThread) {
		gameHacking.logMsg.consoleLog(false, "Failed to create thread in process!");
		return;
	}

	if (log) {
		gameHacking.logMsg.consoleLog(false, "pId: 0x%X", pId);
		gameHacking.logMsg.consoleLog(false, "hProcess: 0x%X", hProcess);
		gameHacking.logMsg.consoleLog(false, "lpParameter: 0x%X", lpParameter);
		gameHacking.logMsg.consoleLog(false, "lpStartAddress: 0x%X", lpStartAddress);
		gameHacking.logMsg.consoleLog(false, "hThread: 0x%X", hThread);
	}

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		peHeaderMgr(hProcess, hThread, peModify, closeOnInject);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, lpParameter, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}
	else {
		gameHacking.logMsg.consoleLog(false, "LoadLibraryW failure injection!");
		return;
	}
	gameHacking.logMsg.consoleLog(true, "LoadLibraryW successfully injection!");
}


void createRemote_LdrLoadDll(Pmystr crl) {
	crl->pLdrLoadDll(0, 0, crl->moduleFileName, &crl->hdn);
}


void createRemote_LdrLoadDLL_End() { }


void MethodInjection::ldrLoadll(LPCWSTR path, const std::string& processName, DWORD peModify, DWORD closeOnInject, BOOL log) {
	DWORD pId = gameHacking.processProperties.findProcessId(processName);

	if (pId) hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

	if (hProcess == 0) {
		gameHacking.logMsg.consoleLog(false, "Fail to open process!");
		return;
	}

	LPVOID pStrEx = gameHacking.memoryMgr.allocWriteEx(hProcess, (LPVOID)path, lstrlenW(path) * 2);

	if (pStrEx == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}

	UNICODE_STRING dll = { (USHORT)(lstrlenW(path) * sizeof(WCHAR)), (USHORT)(lstrlenW(path) * sizeof(WCHAR) + sizeof(WCHAR)), reinterpret_cast<PWSTR>(pStrEx) };

	LPVOID pType = gameHacking.memoryMgr.allocWriteEx(hProcess, &dll, sizeof(dll));

	if (pType == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}

	HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");

	mystr myStruct;
	LdrLoad ldrLoadDll;

	if (hNtdll) {
		ldrLoadDll = reinterpret_cast<LdrLoad>(GetProcAddress(hNtdll, "LdrLoadDll"));
		myStruct = { reinterpret_cast<PUNICODE_STRING>(pType), ldrLoadDll, 0};
	}

	lpParameter = gameHacking.memoryMgr.allocWriteEx(hProcess, &myStruct, sizeof(myStruct));

	if (lpParameter == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}

	lpStartAddress = reinterpret_cast<DWORD>(gameHacking.memoryMgr.allocWriteEx(hProcess, createRemote_LdrLoadDll, reinterpret_cast<DWORD>((createRemote_LdrLoadDLL_End))- reinterpret_cast<DWORD>((createRemote_LdrLoadDll))));
	
	if (lpStartAddress == 0) {
		gameHacking.logMsg.consoleLog(false, "Failed to alloc memory into process!");
		return;
	}
	
	hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, 0);

	if (!hThread) {
		gameHacking.logMsg.consoleLog(false, "Failed to create thread in process!");
		return;
	}

	if (log) {
		gameHacking.logMsg.consoleLog(false, "pId: 0x%X", pId);
		gameHacking.logMsg.consoleLog(false, "hProcess: 0x%X", hProcess);
		gameHacking.logMsg.consoleLog(false, "pStrEx: 0x%X", pStrEx);
		gameHacking.logMsg.consoleLog(false, "Len: 0x%X, MaxLen: 0x%X, Buff: 0x%X", lstrlenW(path) * sizeof(WCHAR), lstrlenW(path) * sizeof(WCHAR) + sizeof(WCHAR), (PWSTR)pStrEx);
		gameHacking.logMsg.consoleLog(false, "pType: 0x%X", pType);
		gameHacking.logMsg.consoleLog(false, "myStruct: 0x%X", myStruct);
		gameHacking.logMsg.consoleLog(false, "lpParameter: 0x%X", lpParameter);
		gameHacking.logMsg.consoleLog(false, "lpStartAddress: 0x%X", reinterpret_cast<DWORD>(createRemote_LdrLoadDLL_End) - reinterpret_cast<DWORD>(createRemote_LdrLoadDll));
		gameHacking.logMsg.consoleLog(false, "hThread: %x", hThread);
	}

	LPVOID AllocatedMem[4] = { pStrEx , pType, lpParameter, (LPVOID)lpStartAddress };

	for (int i = 0; i < 4; i++) { if (hProcess) VirtualFreeEx(hProcess, AllocatedMem[i], 0, MEM_RELEASE); }

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		peHeaderMgr(hProcess, hThread, peModify, closeOnInject);
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
	else {
		gameHacking.logMsg.consoleLog(false, "LdrLoadll failure injection!");
		return;
	}

	gameHacking.logMsg.consoleLog(true, "LdrLoadll successfully injection!");
}

#pragma region KIM LdrLoadDll
/*
void MethodInjection::LdrLoadll(LPCWSTR Path, DWORD pid, DWORD peModify, DWORD closeOnInject) {
	HANDLE hProcess		= OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID pStrEx		= AllocWrite(hProcess, (LPVOID)Path, lstrlenW(Path) * 2);
	LPVOID pType		= AllocWrite(hProcess, (LPVOID)(new UNICODE_STRING{(USHORT)(lstrlenW(Path) * sizeof(WCHAR)), (USHORT)(lstrlenW(Path) * sizeof(WCHAR) + sizeof(WCHAR)), (PWSTR)pStrEx }), sizeof(UNICODE_STRING));
	LPVOID pStruct		= AllocWrite(hProcess, (LPVOID)(new mystr{(PUNICODE_STRING)pType, (LdrLoad)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll") }), sizeof(mystr));
	LPVOID pFunc		= AllocWrite(hProcess, CreateRemote_LdrLoadDll, (DWORD)(CreateRemote_LdrLoadDLL_End)-(DWORD)(CreateRemote_LdrLoadDll));
	HANDLE hLoadThread	= CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pFunc, pStruct, 0, 0);
	WaitForSingleObject(hLoadThread, INFINITE);
	PEHeaderMgr(hProcess, hLoadThread, peModify, closeOnInject);
	CloseHandle(hLoadThread);
	CloseHandle(hProcess);
	LPVOID AllocatedMem[4] = { pStrEx , pType, pStruct, pFunc};
	for(int i = 0; i < 4; i++) VirtualFreeEx(hProcess, AllocatedMem[i], 0, MEM_RELEASE);
	gameHacking.logMsg.consoleLog(false, "LdrLoadll Injetado com Sucesso!");
}
*/
#pragma endregion
#pragma endregion


#pragma region ProcessProperties
DWORD ProcessProperties::findProcessId(const std::string& processName) {
	PROCESSENTRY32 processInfo = PROCESSENTRY32();
	processInfo.dwSize = sizeof(processInfo);
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		gameHacking.logMsg.consoleLog(false, "Invalid Handle!");
		return 0;
	}
	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}
	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processesSnapshot);
	gameHacking.logMsg.consoleLog(false, "Process not found!");
	return 0;
}


BOOL ProcessProperties::enableDebugPrivilege(BOOL fEnable) {
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		TOKEN_PRIVILEGES tp = TOKEN_PRIVILEGES();
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(0, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), 0, 0);
		CloseHandle(hToken);
		return true;
	}
	gameHacking.logMsg.consoleLog(false, "Problems opening process!");
	return false;
}

#pragma endregion


#pragma region LogMsg
int LogMsg::consoleLog(bool freezeLog, char const* const _Format, ...) {
	int _Result;
	va_list _ArgList;
	va_start(_ArgList, _Format);
	_Result = _vfprintf_l(stdout, _Format, NULL, _ArgList);
	va_end(_ArgList);
	printf("\n");
	if (freezeLog) char c = getchar();
	return _Result;
}


void LogMsg::msgBoxA(const char* msg, void* adr, const char op) {
	char buff[255] = { 0 };
	switch (op) {
		case 'x': sprintf(buff, "%s: 0x%X", msg, *reinterpret_cast<DWORD*>(adr));
		case 'd': sprintf(buff, "%s: %d", msg, *reinterpret_cast<DWORD*>(adr));
		case 'u': sprintf(buff, "%s: %d", msg, *reinterpret_cast<USHORT*>(adr));
		case 'f': sprintf(buff, "%s: %f", msg, *reinterpret_cast<PFLOAT>(adr));
		case 's': sprintf(buff, "%s: %s", msg, reinterpret_cast<PCHAR>(adr));
	}
	MessageBoxA(0, buff, 0, 0);
}


void LogMsg::msgBoxW(wchar_t* msg, void* adr, const char op) {
	wchar_t buff[255] = { 0 };
	switch (op) {
		case 'x': swprintf(buff, sizeof(wchar_t), L"%ls: 0x%X", msg, *reinterpret_cast<DWORD*>(adr));
		case 'd': swprintf(buff, sizeof(wchar_t), L"%ls: %d", msg, *reinterpret_cast<DWORD*>(adr));
		case 'u': swprintf(buff, sizeof(wchar_t), L"%ls: %d", msg, *reinterpret_cast<USHORT*>(adr));
		case 'f': swprintf(buff, sizeof(wchar_t), L"%ls: %f", msg, *reinterpret_cast<PFLOAT>(adr));
		case 's': swprintf(buff, sizeof(wchar_t), L"%ls: %s", msg, reinterpret_cast<wchar_t*>(adr));
	}
	MessageBoxW(0, reinterpret_cast<LPCWSTR>(buff), 0, 0);
}

#pragma endregion


#pragma region SetPropertiesConsole
void ConsoleProperties::hide() {
	ShowWindow(GetConsoleWindow(), SW_HIDE);
}


void ConsoleProperties::show() {
	ShowWindow(GetConsoleWindow(), SW_SHOW);
}


bool ConsoleProperties::isVisible() {
	return IsWindowVisible(GetConsoleWindow()) != false;
}


void ConsoleProperties::open_console(const std::string title) {
	AllocConsole();
	FILE* street;
	freopen_s(&street, "CONIN$", "r", stdin);
	freopen_s(&street, "CONOUT$", "w", stdout);
	freopen_s(&street, "CONOUT$", "w", stderr);
	SetConsoleTitle(title.c_str());
}

#pragma endregion


#pragma region AntiDebugger
bool AntiDebugger::RemoteDebuggerPresent(HANDLE hProcess, bool closeProcess) {
	BOOL bDebuggerPresent;
	if (CheckRemoteDebuggerPresent(hProcess, &bDebuggerPresent) && bDebuggerPresent && closeProcess) ExitProcess(-1);
	return bDebuggerPresent;
}

bool AntiDebugger::DebuggerPresentCurrentProcess(bool closeProcess) {
	return AntiDebugger::RemoteDebuggerPresent(GetCurrentProcess(), closeProcess);
}
#pragma endregion
