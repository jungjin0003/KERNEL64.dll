#include "kernel64.h"
#include <stddef.h>
#include <libloaderapi.h>

#define ntdll_RtlSetLastWin32Error(ntstatus)
#define kernelbase_BaseSetLastNTError(ntstatus)
#define MemoryBasicInformation 0

HANDLE hSelf;
HMODULE64 Ntdll64;

#ifdef _MSC_VER
#define R8 0
#define R9 1
#define R10 2
#define R11 3
#define R12 4
#define R13 5
#define R14 6
#define R15 7
#define EMIT(x) __asm __emit x
/* 
Upgrade addressing mode 32bit to 64bit
Like EAX to RAX
*/
#define REX_W   EMIT(0x48) __asm
#define PUSH(r) EMIT(0x41) EMIT(0x50 + r)
#define POP(r)  EMIT(0x41) EMIT(0x58 + r)
#define SwitchX64() __asm { \
    EMIT(0x6A) EMIT(0x33)                                   /* push     0x33                */ \
    EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)  /* call     $+5                 */ \
    EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)             /* and      dword [esp], 0x05   */ \
    EMIT(0xCB)                                              /* retf                         */ \
}
#define SwitchX86() __asm { \
    EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)                                  /* call     $+5                     */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(0x23) EMIT(0x00) EMIT(0x00) EMIT(0x00) /* mov      dword ptr [rsp+4], 0x23 */ \
    EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D)                                             /* add      dword ptr [rsp], 0x0D   */ \
    EMIT(0xCB)                                                                              /* ref                              */ \
}

__declspec(naked) PTR64 WINAPI RtlGetCurrentPeb64()
{
    SwitchX64();

    __asm 
    {
        EMIT(0x65) EMIT(0x48) EMIT(0x8B) EMIT(0x04) EMIT(0x25) EMIT(0x30) EMIT(0x00) EMIT(0x00) EMIT(0x00)  // mov rax, qword ptr gs:[0x30]
        REX_W mov edx, dword ptr [eax+0x60]
        mov eax, edx
        REX_W shr edx, 0x32
    }

    SwitchX86();

    __asm 
    {
        ret
    }
}

unsigned char __read64byte(unsigned long long address)
{
    unsigned char ret;

    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov al, byte ptr [eax]
        mov [ret], al
    }

    SwitchX86();

    return ret;
}

unsigned short __read64word(unsigned long long address)
{
    unsigned short ret;

    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov ax, word ptr [eax]
        mov [ret], ax
    }

    SwitchX86();

    return ret;
}

unsigned long __read64dword(unsigned long long address)
{
    unsigned long ret;

    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov eax, dword ptr [eax]
        mov [ret], eax
    }

    SwitchX86();

    return ret;
}

unsigned long long __read64qword(unsigned long long address)
{
    union
    {
        struct
        {
            unsigned long LowPart;
            unsigned long HighPart;
        };
        unsigned long long Data;
    } ret;

    SwitchX64();

    __asm 
    {
        REX_W mov ecx, dword ptr [ebp+0x08]
        REX_W mov ecx, dword ptr [ecx]
        REX_W mov [ret.LowPart], ecx
    }

    SwitchX86();

    return ret.Data;
}

DECLARE_EXPORT DECLARE_NAKED PTR64 WOW64API X64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...)
{
    __asm 
    {
        push ebp
        mov ebp, esp
        SwitchX64();
        REX_W and esp, 0xFFFFFFF0
        PUSH(R8)
        PUSH(R9)
        PUSH(R10)
        PUSH(R11)
        PUSH(R12)
        PUSH(R13)
        PUSH(R14)
        PUSH(R15)
        mov ecx, [NumberOfParameter]
        REX_W test ecx, ecx
        je $+17
        EMIT(0xFF) EMIT(0xC9) // dec ecx
        push dword ptr [ebp+0x14+ecx*8]
        jmp $-15
        REX_W mov ecx, dword ptr [esp]
        REX_W mov edx, dword ptr [esp+0x08]
        EMIT(0x4C) EMIT(0x8B) EMIT(0x44) EMIT(0x24) EMIT(0x10) // mov r8, qword ptr [esp+0x10]
        EMIT(0x4C) EMIT(0x8B) EMIT(0x4C) EMIT(0x24) EMIT(0x18) // mov r9, qword ptr [esp+0x18]
        REX_W call dword ptr [ebp+0x08]
        REX_W mov edx, eax
        REX_W shr edx, 0x32
        mov ecx, [NumberOfParameter]
        shl ecx, 0x03
        REX_W add esp, ecx
        POP(R15)
        POP(R14)
        POP(R13)
        POP(R12)
        POP(R11)
        POP(R10)
        POP(R9)
        POP(R8)
        SwitchX86();
        leave
        ret
    }
}

DECLARE_EXPORT DECLARE_NAKED NTSTATUS WOW64API NtX64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...)
{
    __asm { jmp X64Call }
}
#elif __GNUC__
#define EMIT(x) ".byte " #x "\n\t"
#define REX_W ".byte 0x48\n\t"
#define PUSH(r) ".byte 0x41, " #r "\n\t"
#define POP(r) ".byte 0x41, " #r "\n\t"
#define PUSH_R8 PUSH(0x50)
#define PUSH_R9 PUSH(0x51)
#define PUSH_R10 PUSH(0x52)
#define PUSH_R11 PUSH(0x53)
#define PUSH_R12 PUSH(0x54)
#define PUSH_R13 PUSH(0x55)
#define PUSH_R14 PUSH(0x56)
#define PUSH_R15 PUSH(0x57)
#define POP_R8 POP(0x58)
#define POP_R9 POP(0x59)
#define POP_R10 POP(0x5A)
#define POP_R11 POP(0x5B)
#define POP_R12 POP(0x5C)
#define POP_R13 POP(0x5D)
#define POP_R14 POP(0x5E)
#define POP_R15 POP(0x5F)
#define SwitchX64() __asm__ __volatile__ ( \
    ".byte 0x6A, 0x33\n\t"                      /* push     0x33                */ \
    ".byte 0xE8, 0x00, 0x00, 0x00, 0x00\n\t"    /* call     $+5                 */ \
    ".byte 0x83, 0x04, 0x24, 0x05\n\t"          /* and      dword [esp], 0x05   */ \
    ".byte 0xCB\n\t"                            /* retf                         */ \
)
#define SwitchX86() __asm__ __volatile__ ( \
    ".byte 0xE8, 0x00, 0x00, 0x00, 0x00\n\t"                    /* call     $+5                     */ \
    ".byte 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00\n\t"  /* mov      dword ptr [rsp+4], 0x23 */ \
    ".byte 0x83, 0x04, 0x24, 0x0D\n\t"                          /* add      dword ptr [rsp], 0x0D   */ \
    ".byte 0xCB\n\t"                                            /* retf                             */ \
)

__declspec(naked) PTR64 WINAPI RtlGetCurrentPeb64()
{
    SwitchX64();

    __asm__ __volatile__ (
        ".byte 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00\n\t"    // mov rax, qword ptr gs:[0x30]
        ".byte 0x48\n\t" "mov edx, dword ptr [eax+0x60]\n\t"                // mov rdx, qword ptr ds:[rax+0x60]
        "mov eax, edx\n\t"                                                  // mov eax, edx
        ".byte 0x48\n\t" "shr edx, 0x32\n\t"                                // shr rdx, 0x32
    );

    SwitchX86();

    __asm__ __volatile__ (
        "ret\n\t"                                                           // ret
    );
}

unsigned char __read64byte(unsigned long long address)
{
    unsigned char ret;
    
    SwitchX64();
    
    __asm__ __volatile__ (
        ".byte 0x48, 0x8B, 0x45, 0x08\n\t"
        "mov al, byte ptr [eax]\n\t"
        "mov %[ret], al\n\t"
        : [ret] "=m" (ret)
        :
    );

    SwitchX86();

    return ret;
}

unsigned short __read64word(unsigned long long address)
{
    unsigned short ret;
    
    SwitchX64();
    
    __asm__ __volatile__ (
        ".byte 0x48, 0x8B, 0x45, 0x08\n\t"
        "mov ax, word ptr [eax]\n\t"
        "mov %[ret], ax\n\t"
        : [ret] "=m" (ret)
        :
    );

    SwitchX86();

    return ret;
}

unsigned long __read64dword(unsigned long long address)
{
    unsigned long ret;
    
    SwitchX64();
    
    __asm__ __volatile__ (
        ".byte 0x48, 0x8B, 0x45, 0x08\n\t"
        "mov eax, dword ptr [eax]\n\t"
        "mov %[ret], eax\n\t"
        : [ret] "=m" (ret)
        :
    );

    SwitchX86();

    return ret;
}

unsigned long long __read64qword(unsigned long long address)
{
    unsigned long long ret;
    
    SwitchX64();
    
    __asm__ __volatile__ (
        ".byte 0x48, 0x8B, 0x4D, 0x08\n\t"
        ".byte 0x48\n\t" "mov ecx, dword ptr [ecx]\n\t"
        ".byte 0x48\n\t" "mov %[ret], ecx\n\t"
        : [ret] "=X" (*(unsigned long *)&ret)
        :
    );

    SwitchX86();

    return ret;
}

DECLARE_EXPORT DECLARE_NAKED PTR64 WOW64API X64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...)
{
    __asm__ __volatile__ (
        "push ebp\n\t"
        "mov ebp, esp\n\t"
    );
    SwitchX64();
    __asm__ __volatile__ (
        REX_W "and esp, 0xFFFFFFF0\n\t"
        PUSH_R8
        PUSH_R9
        PUSH_R10
        PUSH_R11
        PUSH_R12
        PUSH_R13
        PUSH_R14
        PUSH_R15
        "mov ecx, %[NumberOfParameter]\n\t"
        REX_W "test ecx, ecx\n\t"
        "je $+17\n\t"
        EMIT(0xFF) EMIT(0xC9) // dec ecx
        "push dword ptr [ebp+0x14+ecx*8]\n\t"
        "jmp $-15\n\t"
        REX_W "mov ecx, dword ptr [esp]\n\t"
        REX_W "mov edx, dword ptr [esp+0x08]\n\t"
        EMIT(0x4C) EMIT(0x8B) EMIT(0x44) EMIT(0x24) EMIT(0x10) // mov r8, qword ptr [esp+0x10]
        EMIT(0x4C) EMIT(0x8B) EMIT(0x4C) EMIT(0x24) EMIT(0x18) // mov r9, qword ptr [esp+0x18]
        REX_W "call dword ptr [ebp+0x08]\n\t"
        REX_W "mov edx, eax\n\t"
        REX_W "shr edx, 0x32\n\t"
        "mov ecx, %[NumberOfParameter]\n\t"
        "shl ecx, 0x03\n\t"
        REX_W "add esp, ecx\n\t"
        POP_R15
        POP_R14
        POP_R13
        POP_R12
        POP_R11
        POP_R10
        POP_R9
        POP_R8
        : [NumberOfParameter] "=X" (NumberOfParameter)
        :
    );
    SwitchX86();
    __asm__ __volatile__ (
        "leave\n\t"
        "ret\n\t"
    );
}

DECLARE_EXPORT DECLARE_NAKED NTSTATUS WOW64API NtX64Call(PTR64 lpProcAddress, DWORD NumberOfParameter, ...)
{   
    __asm__ __volatile__ (
        "jmp %[X64Call]"
        : [X64Call] "=X" (X64Call)
        :
    );
}
#endif

DECLARE_EXPORT PTR64 WOW64API VirtualAllocEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect)
{
    static FARPROC64 NtAllocateVirtualMemoryEx;
    if (NtAllocateVirtualMemoryEx == NULL64)
        NtAllocateVirtualMemoryEx = GetProcAddress64(Ntdll64, "NtAllocateVirtualMemoryEx");

    NTSTATUS ntstatus;
    PTR64 BaseAddress = lpAddress;
    SIZE_T64 RegionSize = dwSize;

    MEM_EXTENDED_PARAMETER ExtParameter = { 0 };
    struct
    {
        PTR64 LowestStartingAddress;
        PTR64 HighestEndingAddress;
        SIZE_T Alignment; 
    } MemAddrRequire = { 0 };

    ExtParameter.Type = 1;
    ExtParameter.Pointer = &MemAddrRequire;
    MemAddrRequire.LowestStartingAddress = 0;
    MemAddrRequire.HighestEndingAddress = 0x00007FFFFFFEFFFF;
    MemAddrRequire.Alignment = 0;

    ntstatus = NtX64Call(NtAllocateVirtualMemoryEx, 7, (HANDLE64)hProcess, (PTR64)&BaseAddress, (PTR64)&RegionSize, (DWORD64)(flAllocationType & 0xFFFFFFC0), (DWORD64)flProtect, (PTR64)&ExtParameter, (DWORD64)1);

    if (!NT_SUCCESS(ntstatus))
        BaseAddress = NULL64;

    kernelbase_BaseSetLastNTError(ntstatus);

    return BaseAddress;
}

DECLARE_EXPORT PTR64 WOW64API VirtualAlloc64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect)
{
    return VirtualAllocEx64(hSelf, lpAddress, dwSize, flAllocationType, flProtect);
}

DECLARE_EXPORT BOOL WOW64API VirtualProtectEx64(HANDLE hProcess, PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    static FARPROC64 NtProtectVirtualMemory;
    static FARPROC64 RtlFlushSecureMemoryCache;
    if (NtProtectVirtualMemory == NULL64)
        NtProtectVirtualMemory = GetProcAddress64(Ntdll64, "NtProtectVirtualMemory");

    if (RtlFlushSecureMemoryCache == NULL64)
        RtlFlushSecureMemoryCache = GetProcAddress64(Ntdll64, "RtlFlushSecureMemoryCache");

    NTSTATUS ntstatus;
    ntstatus = NtX64Call(NtProtectVirtualMemory, 5, (HANDLE64)(LONG)hProcess, (PTR64)&lpAddress, (PTR64)&dwSize, (DWORD64)flNewProtect, (PTR64)lpflOldProtect);

    if (ntstatus == STATUS_INVALID_PAGE_PROTECTION && hProcess == (HANDLE)-1 && (BOOLEAN)X64Call(RtlFlushSecureMemoryCache, 2, lpAddress, dwSize))
        ntstatus = NtX64Call(NtProtectVirtualMemory, 5, hProcess, (PTR64)&lpAddress, (PTR64)&dwSize, (DWORD64)flNewProtect, (PTR64)lpflOldProtect);

    kernelbase_BaseSetLastNTError(ntstatus);

    return NT_SUCCESS(ntstatus);
}

DECLARE_EXPORT BOOL WOW64API VirtualProtect64(PTR64 lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    return VirtualProtectEx64((HANDLE)-1, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

DECLARE_EXPORT SIZE_T64 WOW64API VirtualQueryEx64(HANDLE hProcess, PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength)
{
    static FARPROC64 NtQueryVirtualMemory;
    if (NtQueryVirtualMemory == NULL64)
        NtQueryVirtualMemory = GetProcAddress64(Ntdll64, "NtQueryVirtualMemory");

    SIZE_T ReturnLength = 0;

    NTSTATUS ntstatus;
    ntstatus = NtX64Call(NtQueryVirtualMemory, 6, (HANDLE64)hProcess, lpAddress, (DWORD64)MemoryBasicInformation, (PTR64)lpBuffer, dwLength, (PTR64)&ReturnLength);
    kernelbase_BaseSetLastNTError(ntstatus);
    return ReturnLength;
}

DECLARE_EXPORT SIZE_T64 WOW64API VirtualQuery64(PTR64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength)
{
    return VirtualQueryEx64((HANDLE)-1, lpAddress, lpBuffer, dwLength);
}

DECLARE_EXPORT BOOL WOW64API ReadProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead)
{
    NTSTATUS ntstatus;
    SIZE_T64 NumberOfBytesRead;

    ntstatus = NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, &NumberOfBytesRead);

    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = NumberOfBytesRead;

    kernelbase_BaseSetLastNTError(ntstatus);

    return NT_SUCCESS(ntstatus);
}

DECLARE_EXPORT BOOL WOW64API WriteProcessMemory64(HANDLE hProcess, PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten)
{
    NTSTATUS ntstatus;
    SIZE_T64 NumberOfBytesWritten;

    ntstatus = NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, &NumberOfBytesWritten);

    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = NumberOfBytesWritten;

    kernelbase_BaseSetLastNTError(ntstatus);

    return NT_SUCCESS(ntstatus);
}

BOOL WOW64API ReadMemory64(PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead)
{
    return ReadProcessMemory64(hSelf, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WOW64API WriteMemory64(PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten)
{
    return WriteProcessMemory64(hSelf, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleW64(LPCWSTR lpModuleName)
{
    HMODULE64 hModule64 = NULL64;
    PTR64 PebBaseAddress = RtlGetCurrentPeb64();

    PTR64 PebLdrData = NULL64;

    if (ReadMemory64(PebBaseAddress + offsetof(PEB64, Ldr), &PebLdrData, 8, NULL) == FALSE)
        return hModule64;

    PTR64 LdrDataTableEntry = PebLdrData + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);

    UNICODE_STRING64 UnicodeString = { 0 };

    for (LPWSTR ModuleName = NULL; ReadMemory64(LdrDataTableEntry, &LdrDataTableEntry, 8, NULL) && PebLdrData + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList) != LdrDataTableEntry; free(ModuleName))
    {
        if (ReadMemory64(LdrDataTableEntry + offsetof(LDR_DATA_TABLE_ENTRY64, BaseDllName), &UnicodeString, sizeof(UNICODE_STRING64), NULL) == FALSE)
            return hModule64;

        ModuleName = malloc(UnicodeString.Length + 2);

        if (ReadMemory64(UnicodeString.Buffer, ModuleName, UnicodeString.Length + 2, NULL) == FALSE)
            return hModule64;

        if (wcsicmp(lpModuleName, ModuleName))
            continue;

        if (ReadMemory64(LdrDataTableEntry + offsetof(LDR_DATA_TABLE_ENTRY64, DllBase), &hModule64, sizeof(HMODULE64), NULL) == FALSE)
            continue;

        free(ModuleName);
        break;
    }

    return hModule64;
}

DECLARE_EXPORT HMODULE64 WOW64API GetModuleHandleA64(LPCSTR lpModuleName)
{
    HMODULE64 hModule64 = NULL64;
    LPWSTR ModuleName = NULL;
    int ModuleNameLength = 0;

    if (!lpModuleName)
        return __read64qword(RtlGetCurrentPeb64() + offsetof(PEB64, ImageBaseAddress));

    ModuleNameLength = MultiByteToWideChar(CP_ACP, 0, lpModuleName, -1, NULL, 0);
    ModuleName = calloc(ModuleNameLength, sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, lpModuleName, -1, ModuleName, ModuleNameLength);
    hModule64 = GetModuleHandleW64(ModuleName);
    free(ModuleName);
    return hModule64;
}

int __cdecl strcmp64(PTR64 _Str1, PTR64 _Str2)
{
    char ch1, ch2;

    for (int i = 0;; i++)
    {
        ch1 = __read64byte(_Str1 + i);
        ch2 = __read64byte(_Str2 + i);

        if (ch1 > ch2)
            return 1;
        else if (ch1 < ch2)
            return -1;
        else if (ch1 == '\0' || ch2 == '\0')
            return 0;
    }
}

DECLARE_EXPORT FARPROC64 WOW64API GetProcAddress64(HMODULE64 hModule64, LPCSTR lpProcName)
{
    hModule64 = hModule64 == NULL64 ? __read64qword(RtlGetCurrentPeb64() + offsetof(PEB64, ImageBaseAddress)) : hModule64;

    PTR64 ExportDirectoryPointer = hModule64 + __read64dword(hModule64 + __read64dword(hModule64 + offsetof(IMAGE_DOS_HEADER, e_lfanew)) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    if (ExportDirectoryPointer == hModule64)
        return NULL64;

    IMAGE_EXPORT_DIRECTORY ExportDirectory;
    ReadMemory64(ExportDirectoryPointer, &ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);

    if (lpProcName <= 0xFFFF)
    {
        WORD Index = (WORD)lpProcName - ExportDirectory.Base;
        return hModule64 + __read64dword(hModule64 + ExportDirectory.AddressOfFunctions + Index * 4);
    }

    PTR64 ProcName = NULL64;

    for (int i = 0; i < ExportDirectory.NumberOfNames; i++)
    {
        ProcName = hModule64 + __read64dword(hModule64 + ExportDirectory.AddressOfNames + i * 4);
        if (strcmp64(ProcName, lpProcName) == 0)
        {
            WORD Index = __read64word(hModule64 + ExportDirectory.AddressOfNameOrdinals + i * 2);
            return hModule64 + __read64dword(hModule64 + ExportDirectory.AddressOfFunctions + Index * 4);
        }
    }

    return NULL64;
}

DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryW64(LPCWSTR lpLibFileName)
{
    static FARPROC64 LdrLoadDll;
    if (LdrLoadDll == NULL64)
        LdrLoadDll = GetProcAddress64(Ntdll64, "LdrLoadDll");

    HMODULE64 hModule64 = NULL64;

    if (!lpLibFileName)
        return hModule64;

    UNICODE_STRING64 UnicodeString = { 0 };
    UnicodeString.Buffer = lpLibFileName;
    UnicodeString.Length = wcslen(lpLibFileName) * sizeof(wchar_t);
    UnicodeString.MaximumLength = UnicodeString.Length + sizeof(wchar_t);

    NTSTATUS ntstatus = NtX64Call(LdrLoadDll, 4, NULL64, NULL64, (PTR64)&UnicodeString, (PTR64)&hModule64);

    kernelbase_BaseSetLastNTError(ntstatus);

    return hModule64;
}

DECLARE_EXPORT HMODULE64 WOW64API LoadLibraryA64(LPCSTR lpLibFileName)
{
    HMODULE64 hModule64 = NULL64;
    LPWSTR LibFileName = NULL;
    int LibFileNameLength = 0;
    
    if (!lpLibFileName)
        return hModule64;

    LibFileNameLength = MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, NULL, 0);
    LibFileName = calloc(LibFileNameLength, sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, lpLibFileName, -1, LibFileName, LibFileNameLength);
    hModule64 = LoadLibraryW64(LibFileName);
    free(LibFileName);
    return hModule64;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstance);
        hSelf = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        Ntdll64 = GetModuleHandleA64("ntdll.dll");

        if (hSelf == NULL)
            return FALSE;
        break;
    case DLL_PROCESS_DETACH:
        CloseHandle(hSelf);
        break;
    }

    return TRUE;
}