#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

typedef LRESULT(__stdcall*CallWindowProcWTemplate)(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

CallWindowProcWTemplate OriginalCallWindowProcW = 0;

LRESULT ReplacementCallWindowProcW(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	CREATESTRUCTW* CreateStruct = 0;

	CreateStruct = (CREATESTRUCTW*)lParam;

	if (Msg == 0x81) {
		if (CreateStruct->lpszName) {
			if (_wcsicmp(CreateStruct->lpszName, L"Authentication Required") == 0) {
				return S_OK;
			}
		}
	}

	return OriginalCallWindowProcW(lpPrevWndFunc, hWnd, Msg, wParam, lParam);
}

BOOLEAN ReplaceIATEntry() {
	PIMAGE_DOS_HEADER DosHeader = 0;
	PIMAGE_NT_HEADERS64 NtHeaders = 0;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = 0;
	PIMAGE_THUNK_DATA64 ThunkData = 0;
	PIMAGE_IMPORT_BY_NAME ImportByName = 0;
	HMODULE user32 = 0;
	PULONG64 ProcessModules = 0;
	DWORD dwProcessModulesSize = 0;
	DWORD dwNumberOfModules = 0;
	DWORD dwOldProtect = 0;
	char* LibraryName = 0;

	K32EnumProcessModules(GetCurrentProcess(), 0, 0, &dwProcessModulesSize);
	if (dwProcessModulesSize == 0) {
		printf("[-] Error %d enumerating process modules in current process\n", GetLastError());
		return FALSE;
	}

	ProcessModules = (PULONG64)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwProcessModulesSize);
	if (ProcessModules == 0) {
		printf("[-] Error %d allocating process modules buffer\n", GetLastError());
		return FALSE;
	}

	dwNumberOfModules = dwProcessModulesSize / sizeof(HMODULE);

	if (!K32EnumProcessModules(GetCurrentProcess(), (HMODULE*)ProcessModules, dwProcessModulesSize, &dwProcessModulesSize)) {
		printf("[-] Error %d enumerating modules loaded in the current process\n", GetLastError());
		
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessModules);
		return FALSE;
	}

	user32 = GetModuleHandleA("user32.dll");
	OriginalCallWindowProcW = (CallWindowProcWTemplate)GetProcAddress(user32, "CallWindowProcW");

	for (ULONG i = 0; i < dwNumberOfModules; i++) {
		printf("[+] Starting enumeration for 0x%llx\n", (ULONG64)ProcessModules[i]);

		DosHeader = (PIMAGE_DOS_HEADER)ProcessModules[i];
		NtHeaders = (PIMAGE_NT_HEADERS)(ProcessModules[i] + DosHeader->e_lfanew);

		ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ProcessModules[i] + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
		while (ImportDescriptor->Name != 0) {
			LibraryName = (char*)(ProcessModules[i] + ImportDescriptor->Name);

			if (_stricmp(LibraryName, "user32.dll") == 0) {
				printf("[+] Found reference to user32.dll\n");

				ThunkData = (PIMAGE_THUNK_DATA64)(ProcessModules[i] + ImportDescriptor->FirstThunk);
				while (ThunkData->u1.Function != 0) {
					if (ThunkData->u1.Function == (ULONG64)OriginalCallWindowProcW) {
						printf("[+] Found CallWindowProcW\n");
						VirtualProtect(&ThunkData->u1.Function, sizeof(ThunkData->u1.Function), PAGE_READWRITE, &dwOldProtect);
						ThunkData->u1.Function = (ULONGLONG)ReplacementCallWindowProcW;
						VirtualProtect(&ThunkData->u1.Function, sizeof(ThunkData->u1.Function), dwOldProtect, &dwOldProtect);
					}
					
					ThunkData++;
				}
			}

			ImportDescriptor++;
		}
	}
}

BOOL DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID Reserved) {
	HWND hAuthWindow = 0;
	HWND hMinitab = 0;
	HANDLE hStdStream = INVALID_HANDLE_VALUE;
	FILE* fp = 0;

	if (dwReason != DLL_PROCESS_ATTACH)
		return TRUE;

	if (GetConsoleWindow() == 0) {
		if (AllocConsole() == 0) {
			MessageBoxA(0, "Unable to allocate console", "Unable to allocate console", MB_OK);
			return FALSE;
		}
	}

	hStdStream = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hStdStream == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "Unable to open handle to console in", "Unable to open handle to console in", MB_OK);

	}
	SetStdHandle(STD_INPUT_HANDLE, hStdStream);
	freopen_s(&fp, "CONIN$", "r", stdin);

	hStdStream = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hStdStream == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "Unable to open handle to console out", "Unable to open handle to console out", MB_OK);
	}

	SetStdHandle(STD_OUTPUT_HANDLE, hStdStream);
	SetStdHandle(STD_ERROR_HANDLE, hStdStream);

	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONOUT$", "w", stderr);

	ReplaceIATEntry();

	HWND hWnd = FindWindowW(0, L"Authentication Required");
	if (hWnd == 0) {
		printf("[-] Error %d finding window\n", GetLastError());
		return 0;
	}
	printf("[+] Found window with HWND 0x%llx\n", (ULONG64)hWnd);

	ShowWindow(hWnd, SW_HIDE);

	hWnd = FindWindowW(0, L"Minitab - Untitled");
	if (hWnd == 0) {
		printf("[-] Error %d finding main minitab window\n", GetLastError());
		return 0;
	}
	printf("[+] Found main minitab window with HWND 0x%llx\n", (ULONG64)hWnd);
	EnableWindow(hWnd, TRUE);
	SetActiveWindow(hWnd);

	return TRUE;
}
