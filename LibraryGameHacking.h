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


class MemoryMgr {
public:
	LPVOID allocWriteEx(HANDLE hProcess, LPVOID pType, DWORD size);
	DWORD returnPointer(const char* module, DWORD addBase, BYTE offset[], int size);
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
	MemoryMgr memoryMgr = MemoryMgr();
	PEHeader peHeader = PEHeader();
	MethodInjection methodInjection = MethodInjection();
	ProcessProperties processProperties = ProcessProperties();
	ConsoleProperties consoleProperties = ConsoleProperties();
	LogMsg logMsg = LogMsg();
	AntiDebugger antiDebugger = AntiDebugger();
};