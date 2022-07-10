#include <Windows.h>
#include <string>
#include <iostream>
#include <time.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <locale>
using namespace std;

typedef struct _UNICODE_STRING {
	USHORT length;
	USHORT maximumLength;
	PWSTR  buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef NTSTATUS(NTAPI* LdrLoad)(IN PWCHAR pathToFile, IN ULONG flags, IN PUNICODE_STRING moduleFileName, OUT PHANDLE moduleHandle);

typedef struct mystr {
	PUNICODE_STRING moduleFileName;
	LdrLoad   pLdrLoadDll;
	HANDLE  hdn;
} *Pmystr;


class Tools {
public:
	static MODULEINFO GetModuleInfo(const char* szModule);
	static bool checkName(const char* name);
	static void waterMark();
	static bool vecCmpValueExistArr(DWORD val, vector<DWORD> vec);
	static void vecSaveValuesArr(DWORD varLog, vector <DWORD>& varSave, bool optLogMsg = false);
};


class MemoryMgr {
public:
	static void logValuesAddress(DWORD address);
	static void memEdit(DWORD addr, const char arrBytes[], UINT size);
	static LPVOID allocWriteEx(HANDLE hProcess, LPVOID pType, DWORD size);
	static DWORD returnPointer(DWORD address, UINT offset[], int size);
	static DWORD returnPointerMod(const char* mod, DWORD addBase, UINT offset[], int size);
	static DWORD FindPatternModule(const char* module, const unsigned char pattern[], const char mask[]);
	static DWORD FindPatternStartAddress(const unsigned char pattern[], const char mask[], DWORD startAddress, DWORD endAddress, UINT posScan = 1);
};


class PEHeader {
public:
	void eraseEx(HMODULE hProcess, LPVOID lpStartAddress);
	void randomEx(HMODULE hProcess, LPVOID lpStartAddress);
	void fakeEx(HMODULE hProcess, LPVOID lpStartAddress);
};


class MethodInjection {
public:
	HANDLE hProcess = 0, hThread = 0;
	LPVOID lpParameter = 0;
	DWORD lpStartAddress = 0;
	void standardA(LPCSTR path, const std::string& processName, DWORD peModify = 0, DWORD closeOnInject = 0, BOOL log = false);
	void standardW(LPCWSTR path, const std::string& processName, DWORD peModify = 0, DWORD closeOnInject = 0, BOOL log = false);
	void ldrLoadll(LPCWSTR path, const std::string& processName, DWORD peModify = 0, DWORD closeOnInject = 0, BOOL log = false);
};


class ProcessProperties {
public:
	DWORD findProcessId(const std::string& processName);
	BOOL enableDebugPrivilege(BOOL fEnable);
};


class ConsoleProperties {
public:
	void hide();
	void show();
	bool isVisible();
	void open_console(const std::string title);
};


class LogMsg {
public:
	void msgBoxA(const char* msg, void* adr, const char op);
	void msgBoxW(wchar_t* msg, void* adr, const char op);
	int consoleLog(bool freezeLog, char const* const _Format, ...);
};


class AntiDebugger {
public:
	bool RemoteDebuggerPresent(HANDLE hProcess, bool closeProcess);
	bool DebuggerPresentCurrentProcess(bool closeProcess);
};


class GameHacking
{
public:
	Tools tools = Tools();
	MemoryMgr memoryMgr = MemoryMgr();
	PEHeader peHeader = PEHeader();
	MethodInjection methodInjection = MethodInjection();
	ProcessProperties processProperties = ProcessProperties();
	ConsoleProperties consoleProperties = ConsoleProperties();
	LogMsg logMsg = LogMsg();
	AntiDebugger antiDebugger = AntiDebugger();
};