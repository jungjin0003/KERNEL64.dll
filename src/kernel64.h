#ifndef _KERNEL64_
#define _KERNEL64_

#include <windows.h>
#include <minwindef.h>
#include <winternl.h>
#include <ntstatus.h>

#define WOW64API        __stdcall
#define DECLARE_EXPORT  __declspec(dllexport)
#define DECLARE_NAKED   __declspec(naked)
#define NULL64          ((PTR64)0)

typedef DWORD32 PTR32;
typedef DWORD64 PTR64;
typedef ULONG64 SIZE_T64, *PSIZE_T64;
typedef PTR64 HANDLE64;
typedef PTR64 HMODULE64;
typedef PTR64 FARPROC64;

#pragma pack(push, 4)
typedef struct _UNICODE_STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    ULONG32 Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;
#pragma pack(pop)

#pragma pack(push, 8)
typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    PTR64 DllBase;
    PTR64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY64 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    BOOLEAN Initialized;
    PTR64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    PTR64 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    PTR64 ShutdownThreadId;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _PEB64
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    BYTE Padding0[4];
    HANDLE64 Mutant;
    PTR64 ImageBaseAddress;
    PTR64 Ldr;
    PTR64 ProcessParameters;
    PTR64 SubSystemData;
    PTR64 ProcessHeap;
    PTR64 FastPebLock;
    PTR64 AtlThunkSListPtr;
    PTR64 IFEOKey;
    ULONG CrossProcessFlags;
    BYTE Padding1[4];
    union
    {
        PTR64 KernelCallbackTable;
        PTR64 UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PTR64 ApiSetMap;
    ULONG TlsExpansionCounter;
    BYTE Padding2[4];
    PTR64 TlsBitmap;
    ULONG TlsBitmapBits[2];
    PTR64 ReadOnlyShareMemoryBase;
    PTR64 SharedData;
    PTR64 ReadOnlyStaticServerData;
    PTR64 AnsiCodePageData;
    PTR64 OemCodePageData;
    PTR64 UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    PTR64 HeapSegmentReserved;
    PTR64 HeapSegmentCommit;
    PTR64 HeapDeCommitTotalFreeThreshold;
    PTR64 HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PTR64 ProcessHeaps;
    PTR64 GdiSharedHandleTable;
    PTR64 ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    BYTE Padding3[4];
    PTR64 LoaderLock;
    ULONG OSMajorVerson;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    BYTE Padding4[4];
    PTR64 ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[0x3C];
    PTR64 PostProcessInitRoutine;
    PTR64 TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[0x20];
    ULONG SessionId;
    BYTE Padding5[4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PTR64 pShimData;
    PTR64 AppCompatInfo;
    UNICODE_STRING64 CSDVersion;
    PTR64 ActivationContextData;
    PTR64 ProcessAssemblyStorageMap;
    PTR64 SystemDefaultActivationContextData;
    PTR64 SystemAssemblyStorageMap;
    PTR64 MinimumStackCommit;
    PTR64 SparePointers[4];
    ULONG SpareUlongs[5];
    PTR64 WerRegistrationData;
    PTR64 WerShipAssertPtr;
    PTR64 pUnused;
    PTR64 pImageHeaderHash;
    ULONG TracingFlags;
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    ULONG TppWorkerpListLock;
    LIST_ENTRY64 TppWorkerpList;
    PTR64 WaitOnAddressHashTable[0x80];
    PTR64 TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibiltyMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    PTR64 LeapSecondData;
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB64, *PPEB64;
#pragma pack(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtWow64AllocateVirtualMemory64(HANDLE ProcessHandle, PTR64 *BaseAddress, ULONG64 ZeroBits, PULONG64 RegionSize, ULONG AllocationType, ULONG Protect);
NTSYSCALLAPI NTSTATUS NTAPI NtWow64ReadVirtualMemory64(HANDLE ProcessHandle, PTR64 BaseAddress, PVOID Buffer, SIZE_T64 BufferSize, PSIZE_T64 NumberOfBytesRead);
NTSYSCALLAPI NTSTATUS NTAPI NtWow64WriteVirtualMemory64(HANDLE ProcessHandle, PTR64 BaseAddress, PVOID Buffer, SIZE_T64 BufferSize, PSIZE_T64 NumberOfBytesWritten);

DECLARE_EXPORT PTR64 WOW64API X64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_EXPORT NTSTATUS WOW64API NtX64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_EXPORT PTR64 WOW64API VirtualAllocEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_EXPORT PTR64 WOW64API VirtualAlloc64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_EXPORT BOOL WOW64API VirtualProtectEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_EXPORT BOOL WOW64API VirtualProtect64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_EXPORT SIZE_T64 WOW64API VirtualQueryEx64(HANDLE hProcess, PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_EXPORT SIZE_T64 WOW64API VirtualQuery64(PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_EXPORT BOOL WOW64API ReadProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, PTR64 lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead);
DECLARE_EXPORT BOOL WOW64API WriteProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, PTR64 lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten);
DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleW64(LPCWSTR lpModuleName);
DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleA64(LPCSTR lpModuleName);
DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryW64(LPCWSTR lpLibFileName);
DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryA64(LPCSTR lpLibFileName);
DECLARE_EXPORT FARPROC64 WOW64API GetProcAddress64(HMODULE64 hModule64, LPCSTR lpProcName);

#endif