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

/*
    typedef DWORD64 (WINAPI *PTHREAD_START_ROUTINE64)(PTR64 lpParameter)
*/
typedef PTR64 PTHREAD_START_ROUTINE64;
typedef PTHREAD_START_ROUTINE64 LPTHREAD_START_ROUTINE64;

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in SE_SAFE_OPEN_PROMPT_RESULTS
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in USHORT // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeSupportedMachines, // since 24H2
    PsAttributeSveVectorLength, // PPS_PROCESS_CREATION_SVE_VECTOR_LENGTH
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

// private
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

// begin_rev

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)

typedef struct _PS_ATTRIBUTE64
{
    PTR64 Attribute;
    SIZE_T64 Size;
    union
    {
        PTR64 Value;
        PTR64 ValuePtr;
    };
    PTR64 ReturnLength;
} PS_ATTRIBUTE64, *PPS_ATTRIBUTE64;

typedef struct _PS_ATTRIBUTE_LIST64
{
    SIZE_T64 TotalLength;
    PS_ATTRIBUTE64 Attributes[1];
} PS_ATTRIBUTE_LIST64, *PPS_ATTRIBUTE_LIST64;

typedef struct _PROC_THREAD_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    ULONG_PTR Value;
} PROC_THREAD_ATTRIBUTE, *PPROC_THREAD_ATTRIBUTE;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    ULONG PresentFlags;
    ULONG AttributeCount;
    ULONG LastAttribute;
    ULONG Reserved;
    PPROC_THREAD_ATTRIBUTE ExtendedFlagsAttribute;
    PROC_THREAD_ATTRIBUTE Attributes[1];
} PROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

typedef struct _CLIENT_ID64
{
    HANDLE64 UniqueProcess;
    HANDLE64 UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

typedef struct _SECTION_IMAGE_INFORMATION 
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    ULONG MaximumStackSize;
    ULONG CommittedStackSize;
    ULONG SubSystemType;
    union 
    {
        struct 
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union
    {
        struct
        {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    UCHAR ImageFlags;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

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

NTSYSCALLAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProccessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTSYSCALLAPI NTSTATUS NTAPI NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

DECLARE_EXPORT PTR64 WOW64API X64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_EXPORT NTSTATUS WOW64API NtX64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...);
DECLARE_EXPORT PTR64 WOW64API VirtualAllocEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_EXPORT PTR64 WOW64API VirtualAlloc64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect);
DECLARE_EXPORT BOOL WOW64API VirtualProtectEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_EXPORT BOOL WOW64API VirtualProtect64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLARE_EXPORT SIZE_T64 WOW64API VirtualQueryEx64(HANDLE hProcess, PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_EXPORT SIZE_T64 WOW64API VirtualQuery64(PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength);
DECLARE_EXPORT BOOL WOW64API ReadProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead);
DECLARE_EXPORT BOOL WOW64API WriteProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten);
DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleW64(LPCWSTR lpModuleName);
DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleA64(LPCSTR lpModuleName);
DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryW64(LPCWSTR lpLibFileName);
DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryA64(LPCSTR lpLibFileName);
DECLARE_EXPORT BOOL WOW64API FreeLibrary64(HMODULE64 hLibModule);
DECLARE_EXPORT FARPROC64 WOW64API GetProcAddress64(HMODULE64 hModule64, LPCSTR lpProcName);
DECLARE_EXPORT HANDLE CreateRemoteThreadEx64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
DECLARE_EXPORT HANDLE CreateRemoteThread64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLARE_EXPORT HANDLE CreateThread64(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, PTR64 lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

#endif