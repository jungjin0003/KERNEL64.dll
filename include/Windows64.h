#ifndef _WINDOWS64_
#define _WINDOWS64_

#include <minwindef.h>
#include <minwinbase.h>

#define WOW64API        __stdcall
#define DECLARE_IMPORT  __declspec(dllimport)
#define NULL64          ((PTR64)0)

typedef DWORD32 PTR32;
typedef DWORD64 PTR64;
typedef ULONG64 SIZE_T64, *PSIZE_T64;
typedef PTR64 HANDLE64;
typedef PTR64 HMODULE64;
typedef PTR64 FARPROC64;

/*
    typedef DWORD64 (WINAPI *PTHREAD_START_ROUTINE64)(PTR64 lpParameter)
*/
typedef PTR64 PTHREAD_START_ROUTINE64;
typedef PTHREAD_START_ROUTINE64 LPTHREAD_START_ROUTINE64;

DECLARE_IMPORT PTR64 WOW64API X64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_IMPORT NTSTATUS WOW64API NtX64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_IMPORT PTR64 WOW64API VirtualAllocEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_IMPORT PTR64 WOW64API VirtualAlloc64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_IMPORT BOOL WOW64API VirtualProtectEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_IMPORT BOOL WOW64API VirtualProtect64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_IMPORT SIZE_T64 WOW64API VirtualQueryEx64(HANDLE hProcess, PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_IMPORT SIZE_T64 WOW64API VirtualQuery64(PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_IMPORT BOOL WOW64API ReadProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead);
DECLARE_IMPORT BOOL WOW64API WriteProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten);
DECLARE_IMPORT HMODULE64 WOW64API GetModuleHandleW64(LPCWSTR lpModuleName);
DECLARE_IMPORT HMODULE64 WOW64API GetModuleHandleA64(LPCSTR lpModuleName);
DECLARE_IMPORT HMODULE64 WOW64API LoadLibraryW64(LPCWSTR lpLibFileName);
DECLARE_IMPORT HMODULE64 WOW64API LoadLibraryA64(LPCSTR lpLibFileName);
DECLARE_IMPORT BOOL WOW64API FreeLibrary64(HMODULE64 hLibModule);
DECLARE_IMPORT FARPROC64 WOW64API GetProcAddress64(HMODULE64 hModule64, LPCSTR lpProcName);
DECLARE_IMPORT HANDLE CreateRemoteThreadEx64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
DECLARE_IMPORT HANDLE CreateRemoteThread64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLARE_IMPORT HANDLE CreateThread64(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

#endif