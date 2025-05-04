#include "kernel64.h"
#include <stddef.h>
#include <libloaderapi.h>

#define ntdll_RtlSetLastWin32Error(ntstatus)
#define kernelbase_BaseSetLastNTError(ntstatus)
#define kernelbase_byte_101C55A4 FALSE
#define ProcessImageInformation 0x25
#define ProcessProtectionInformation 0x3D
#define TEB_ClientId_OFFSET32 0x20
#define TEB_ActivationContextStackPointer_OFFSET64 0x2C8
#define TEB_SubProcessTag_OFFSET32 0xF60
#define TEB_SubProcessTag_OFFSET64 0x1720
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

void __write64byte(unsigned long long address, unsigned char data)
{
    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov cl, data
        mov byte ptr [eax], cl
    }

    SwitchX86();
}

void __write64word(unsigned long long address, unsigned short data)
{
    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov cx, data
        mov word ptr [eax], cx
    }

    SwitchX86();
}

void __write64dword(unsigned long long address, unsigned long data)
{
    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        mov ecx, data
        mov dword ptr [eax], ecx
    }

    SwitchX86();
}

void __write64qword(unsigned long long address, unsigned long long data)
{
    SwitchX64();

    __asm 
    {
        REX_W mov eax, dword ptr [ebp+0x08]
        REX_W mov ecx, dword ptr [ebp+0x10]
        REX_W mov dword ptr [eax], ecx
    }

    SwitchX86();
}

DECLARE_EXPORT DECLARE_NAKED POINTER64(ULONG_PTR) WOW64API X64Call(POINTER64(LPVOID) lpProcAddress, DWORD NumberOfParameter, ...)
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

DECLARE_EXPORT DECLARE_NAKED NTSTATUS WOW64API NtX64Call(POINTER64(LPVOID) lpProcAddress, DWORD NumberOfParameter, ...)
{
    __asm { jmp X64Call }
}

DECLARE_NAKED VOID WOW64API BaseThreadInitThunk(LPVOID lpParameter)
{
    /*
    NTSTATUS v3; // eax
    __int64 result; // rax

    if ( !a1 )
    {
        v3 = a2(a3);
        RtlExitUserThread(v3);
        __debugbreak();
    }
    if ( (RtlGetSuiteMask() & 0x10) == 0 || (result = BasepInitializeTermsrvFpns(), (int)result >= 0) )
        result = 0i64;
    return result;
    */
    __asm
    {
        push 0x27F
        push [Ntdll64+0x04]
        push [Ntdll64]
        call GetProcAddress64
        mov ecx, dword ptr [ebp+0x08]
        mov ebp, 0x00000000
        mov esp, dword ptr fs:[0x04]
        push edx
        push eax
        mov eax, ecx
        sub esp, 0x10
        mov esi, eax
        mov edi, esp
        mov ecx, 0x04
        rep movsd
        push eax
        call free
        add esp, 0x04
        SwitchX64();
        REX_W pop eax
        REX_W mov ecx, dword ptr [esp]
        call eax
        REX_W mov edx, eax
        REX_W mov ecx, 0xFFFFFFFE EMIT(0xFF) EMIT(0xFF) EMIT(0xFF) EMIT(0xFF)
        REX_W mov eax, dword ptr [esp+0x08]
        REX_W sub esp, 0x10
        call eax
    }
    __debugbreak();
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

NTSTATUS WINAPI BasepConvertWin32AttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, char a2, DWORD *a3, int a4, DWORD *a5, BYTE *a6, DWORD *a7, int a8, int a9, DWORD *a10, DWORD *a11, DWORD *a12, DWORD *a13, int a14, int a15, DWORD *a16, PPS_ATTRIBUTE64 AttributeList, int *NumberOfPsAttribute)
{
    ULONG ProcessedAttributes = 0;

    if (lpAttributeList->LastAttribute > lpAttributeList->AttributeCount)
        return STATUS_INVALID_PARAMETER;

    for (int i = 0; i < lpAttributeList->LastAttribute; i++)
    {
        PPROC_THREAD_ATTRIBUTE Attribute = &lpAttributeList->Attributes[i];
        ULONG AttributeMask = 1 << Attribute->Attribute;
        ULONG AttributeSize = 0;

        if ((AttributeMask & lpAttributeList->PresentFlags) == 0 || (ProcessedAttributes & AttributeMask) != 0 || (a2 && (Attribute->Attribute & 0x10000) == 0))
            return STATUS_INVALID_PARAMETER;

        BOOLEAN ProcessFlag = TRUE;
        switch (Attribute->Attribute)
        {
        case 0x20004:
            if (Attribute->Size != 2)
                return STATUS_INVALID_PARAMETER;
            AttributeSize = 131085;
            break;
        
        case 0x2000B:
            if (Attribute->Size != 4 && Attribute->Value > 8 && Attribute->Value != -1)
                return STATUS_INVALID_PARAMETER;

            NTSTATUS ntstatus;
            BYTE ProcessInformation = 0;
            switch (Attribute->Value)
            {
            case 0: ProcessInformation = 97; break;
            case 1: ProcessInformation = 82; break;
            case 2: ProcessInformation = 81; break;
            case 3: ProcessInformation = 49; break;
            case 4: ProcessInformation = 65; break;
            case 5: ProcessInformation = 98; break;
            case 6: ProcessInformation = 33; break;
            case 7: ProcessInformation = 18; break;
            case 8: ProcessInformation = -127; break;
            default:
                ntstatus = NtQueryInformationProcess((HANDLE)-1, ProcessProtectionInformation, &ProcessInformation, 1, NULL);
                if (!NT_SUCCESS(ntstatus))
                    return ntstatus;
            }

            AttributeList[*NumberOfPsAttribute + 1].Attribute = 0;
            AttributeList[*NumberOfPsAttribute].Size = 393233;
            AttributeList[*NumberOfPsAttribute].Value = 1;
            AttributeList[*NumberOfPsAttribute].ReturnLength = ProcessInformation;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
        }

        if (ProcessFlag)
        {
            AttributeList[*NumberOfPsAttribute + 1].Attribute = 0;
            AttributeList[*NumberOfPsAttribute].Size = AttributeSize;
            AttributeList[*NumberOfPsAttribute].Value = Attribute->Size;
            AttributeList[*NumberOfPsAttribute++].ReturnLength = Attribute->Value;
        }
    }

    return STATUS_SUCCESS;
}

DECLARE_EXPORT POINTER64(LPVOID) WOW64API VirtualAllocEx64(HANDLE hProcess, POINTER64(LPVOID) lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect)
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

DECLARE_EXPORT POINTER64(LPVOID) WOW64API VirtualAlloc64(POINTER64(LPVOID) lpAddress, SIZE_T64 dwSize, DWORD flAllocationType, DWORD flProtect)
{
    return VirtualAllocEx64(hSelf, lpAddress, dwSize, flAllocationType, flProtect);
}

DECLARE_EXPORT BOOL WOW64API VirtualProtectEx64(HANDLE hProcess, POINTER64(LPVOID) lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
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

DECLARE_EXPORT BOOL WOW64API VirtualProtect64(POINTER64(LPVOID) lpAddress, SIZE_T64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    return VirtualProtectEx64((HANDLE)-1, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

DECLARE_EXPORT SIZE_T64 WOW64API VirtualQueryEx64(HANDLE hProcess, POINTER64(LPCVOID) lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength)
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

DECLARE_EXPORT SIZE_T64 WOW64API VirtualQuery64(POINTER64(LPCVOID) lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, SIZE_T64 dwLength)
{
    return VirtualQueryEx64((HANDLE)-1, lpAddress, lpBuffer, dwLength);
}

DECLARE_EXPORT BOOL WOW64API ReadProcessMemory64(HANDLE hProcess, POINTER64(LPCVOID) lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead)
{
    static FARPROC64 NtReadVirtualMemory;
    if (NtReadVirtualMemory == NULL64)
        NtReadVirtualMemory = GetProcAddress64(Ntdll64, "NtReadVirtualMemory");

    NTSTATUS ntstatus;
    SIZE_T64 NumberOfBytesRead;

    ntstatus = NtX64Call(NtReadVirtualMemory, 5, hProcess == (HANDLE)-1 ? (HANDLE64)hSelf : (HANDLE64)hProcess, lpBaseAddress, (PTR64)lpBuffer, nSize, (PTR64)&NumberOfBytesRead);

    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = NumberOfBytesRead;

    kernelbase_BaseSetLastNTError(ntstatus);

    return NT_SUCCESS(ntstatus);
}

DECLARE_EXPORT BOOL WOW64API WriteProcessMemory64(HANDLE hProcess, POINTER64(LPVOID) lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten)
{
    static FARPROC64 NtWriteVirtualMemory;
    if (NtWriteVirtualMemory == NULL64)
        NtWriteVirtualMemory = GetProcAddress64(Ntdll64, "NtWriteVirtualMemory");

    NTSTATUS ntstatus;
    SIZE_T64 NumberOfBytesWritten;

    ntstatus = NtX64Call(NtWriteVirtualMemory, 5, hProcess == (HANDLE)-1 ? (HANDLE64)hSelf : (HANDLE64)hProcess, lpBaseAddress, (PTR64)lpBuffer, nSize, (PTR64)&NumberOfBytesWritten);

    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = NumberOfBytesWritten;

    kernelbase_BaseSetLastNTError(ntstatus);

    return NT_SUCCESS(ntstatus);
}

BOOL WOW64API ReadMemory64(PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesRead)
{
    BOOL bResult = TRUE;
    SIZE_T64 NumberOfBytesRead = 0;

    __try
    {
        for (int i = 0; i < nSize / 8; i++, NumberOfBytesRead += 8)
            *(DWORD64 *)((ULONG_PTR)lpBuffer + i * 8) = __read64qword(lpBaseAddress + i * 8);
        
        while (NumberOfBytesRead < nSize)
        {
            BYTE RemainLength = nSize - NumberOfBytesRead;
            if (RemainLength >= 4)
            {
                *(DWORD *)((ULONG_PTR)lpBuffer + NumberOfBytesRead) = __read64dword(lpBaseAddress + NumberOfBytesRead);
                NumberOfBytesRead += 4;
            }
            else if (RemainLength >= 2)
            {
                *(WORD *)((ULONG_PTR)lpBuffer + NumberOfBytesRead) = __read64word(lpBaseAddress + NumberOfBytesRead);
                NumberOfBytesRead += 2;
            }
            else if (RemainLength >= 1)
            {
                *(BYTE *)((ULONG_PTR)lpBuffer + NumberOfBytesRead) = __read64byte(lpBaseAddress + NumberOfBytesRead);
                NumberOfBytesRead += 1;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        bResult = FALSE;
    }

    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = NumberOfBytesRead;

    return bResult;
}

BOOL WOW64API WriteMemory64(PTR64 lpBaseAddress, LPVOID lpBuffer, SIZE_T64 nSize, SIZE_T64 *lpNumberOfBytesWritten)
{
    BOOL bResult = TRUE;
    SIZE_T64 NumberOfBytesWritten = 0;

    __try
    {
        for (int i = 0; i < nSize / 8; i++, NumberOfBytesWritten += 8)
            __write64qword(lpBaseAddress + i * 8, *(DWORD64 *)((ULONG_PTR)lpBuffer + i * 8));

        while (NumberOfBytesWritten < nSize)
        {
            BYTE RemainLength = nSize - NumberOfBytesWritten;
            if (RemainLength >= 4)
            {
                __write64dword(lpBaseAddress + NumberOfBytesWritten, *(DWORD *)((ULONG_PTR)lpBuffer + NumberOfBytesWritten));
                NumberOfBytesWritten += 4;
            }
            else if (RemainLength >= 2)
            {
                __write64word(lpBaseAddress + NumberOfBytesWritten, *(WORD *)((ULONG_PTR)lpBuffer + NumberOfBytesWritten));
                NumberOfBytesWritten += 2;
            }
            else if (RemainLength >= 1)
            {
                __write64byte(lpBaseAddress + NumberOfBytesWritten, *(BYTE *)((ULONG_PTR)lpBuffer + NumberOfBytesWritten));
                NumberOfBytesWritten += 1;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        bResult = FALSE;
    }

    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = NumberOfBytesWritten;

    return bResult;
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

    PVOID OldValue = NULL;
    if (Wow64DisableWow64FsRedirection(&OldValue) == FALSE)
        return hModule64;

    NTSTATUS ntstatus = NtX64Call(LdrLoadDll, 4, NULL64, NULL64, (PTR64)&UnicodeString, (PTR64)&hModule64);

    Wow64RevertWow64FsRedirection(OldValue);

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

DECLARE_EXPORT BOOL WOW64API FreeLibrary64(HMODULE64 hLibModule)
{
    static FARPROC64 LdrUnloadDll;
    if (LdrUnloadDll == NULL64)
        LdrUnloadDll = GetProcAddress64(Ntdll64, "LdrUnloadDll");

    NTSTATUS ntstatus;
    ntstatus = NtX64Call(LdrUnloadDll, 1, hLibModule);

    return NT_SUCCESS(ntstatus);
}

DECLARE_EXPORT HANDLE CreateRemoteThreadEx64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, POINTER64(LPVOID) lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
{
    static NTSTATUS (WINAPI *BaseFormatObjectAttributes)(POBJECT_ATTRIBUTES ObjectAttributes, LPSECURITY_ATTRIBUTES SecurityAttributes, PUNICODE_STRING UnicodeString, POBJECT_ATTRIBUTES *ObjectAttributesOut);
    static FARPROC64 NtCreateThreadEx;
    static FARPROC64 RtlAllocateActivationContextStack;
    static FARPROC64 RtlActivateActivationContextEx;
    static FARPROC64 RtlReleaseActivationContext;
    static FARPROC64 RtlFreeActivationContextStack;
    static FARPROC64 RtlQueryInformationActivationContext;
    if (BaseFormatObjectAttributes == NULL)
        BaseFormatObjectAttributes = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "BaseFormatObjectAttributes");

    if (NtCreateThreadEx == NULL64)
        NtCreateThreadEx = GetProcAddress64(Ntdll64, "NtCreateThreadEx");

    if (RtlAllocateActivationContextStack == NULL64)
        RtlAllocateActivationContextStack = GetProcAddress64(Ntdll64, "RtlAllocateActivationContextStack");

    if (RtlActivateActivationContextEx == NULL64)
        RtlActivateActivationContextEx = GetProcAddress64(Ntdll64, "RtlActivateActivationContextEx");

    if (RtlReleaseActivationContext == NULL64)
        RtlReleaseActivationContext = GetProcAddress64(Ntdll64, "RtlReleaseActivationContext");
    
    if (RtlFreeActivationContextStack == NULL64)
        RtlFreeActivationContextStack = GetProcAddress64(Ntdll64, "RtlFreeActivationContextStack");

    if (RtlQueryInformationActivationContext == NULL64)
        RtlQueryInformationActivationContext = GetProcAddress64(Ntdll64, "RtlQueryInformationActivationContext");

    NTSTATUS ntstatus = STATUS_SUCCESS;
    HANDLE64 ThreadHandle = NULL64;
    HANDLE Handle = NULL;

    if ((dwCreationFlags & 0xFFFEFFFB) != 0)
    {
        ntstatus = STATUS_INVALID_PARAMETER;
        kernelbase_BaseSetLastNTError(ntstatus);
        return ThreadHandle;
    }

    OBJECT_ATTRIBUTES DummyObjectAttributes = { 0 };
    POBJECT_ATTRIBUTES ObjectAttributes = NULL;
    ntstatus = BaseFormatObjectAttributes(&DummyObjectAttributes, lpThreadAttributes, 0, &ObjectAttributes);

    if (!NT_SUCCESS(ntstatus))
    {
        kernelbase_BaseSetLastNTError(ntstatus);
        return ThreadHandle;
    }

    CLIENT_ID64 ClientId = { 0 };
    PTR64 Teb = NULL64;
    BYTE AttributeList[sizeof(PS_ATTRIBUTE64) * 40 + 8];

    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[0].Size = sizeof(CLIENT_ID64);
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[0].ValuePtr = &ClientId;
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[0].ReturnLength = NULL64;
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[1].Attribute = PS_ATTRIBUTE_TEB_ADDRESS;
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[1].Size = sizeof(PTR64);
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[1].ValuePtr = &Teb;
    ((PPS_ATTRIBUTE_LIST64)AttributeList)->Attributes[1].ReturnLength = NULL64;

    DWORD NumberOfPsAttribute = 2;

    if (lpAttributeList)
    {
        ntstatus = BasepConvertWin32AttributeList(lpAttributeList, 1, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (PPS_ATTRIBUTE64)&AttributeList, &NumberOfPsAttribute);
        if (!NT_SUCCESS(ntstatus))
        {
            kernelbase_BaseSetLastNTError(ntstatus);
            return ThreadHandle;
        }
    }

    ((PPS_ATTRIBUTE_LIST64)AttributeList)->TotalLength = sizeof(PS_ATTRIBUTE64) * NumberOfPsAttribute + 8;

    BOOL IsCurrentProcess = TRUE;
    if (hProcess != (HANDLE)-1)
    {
        if (NT_SUCCESS(NtDuplicateObject((HANDLE)-1, hProcess, (HANDLE)-1, &Handle, 0x402, 0, 0)))
            hProcess = Handle;
        
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
        if (NT_SUCCESS(ntstatus))
        {
            if (pbi.UniqueProcessId != ((CLIENT_ID *)(PTR32)NtCurrentTeb() + TEB_ClientId_OFFSET32)->UniqueProcess)
            {
                SECTION_IMAGE_INFORMATION sii = { 0 };
                IsCurrentProcess = FALSE;
                ntstatus = NtQueryInformationProcess(hProcess, ProcessImageInformation, &sii, sizeof(SECTION_IMAGE_INFORMATION), NULL);
                if (NT_SUCCESS(ntstatus) && sii.SubSystemType - 2 > 1)
                    ntstatus = STATUS_UNSUCCESSFUL;
            }
        }
        if (!NT_SUCCESS(ntstatus))
        {
            if (Handle)
                NtClose(Handle);
            kernelbase_BaseSetLastNTError(ntstatus);
            return ThreadHandle;
        }
    }

    if (IsCurrentProcess)
    {
        PTR64 *temp = malloc(0x10);
        temp[0] = lpStartAddress;
        temp[1] = lpParameter;

        lpStartAddress = BaseThreadInitThunk;
        lpParameter = temp;
    }
    
    HANDLE64 ActivationContextInformation;
    if (IsCurrentProcess)
        ntstatus = NtX64Call(RtlQueryInformationActivationContext, 7, (DWORD64)1, NULL64, NULL64, (DWORD64)1, (PTR64)&ActivationContextInformation, (DWORD64)0x10, NULL64); // RtlQueryInformationActivationContext(1, NULL, NULL, 1, &ActivationContextInformation, sizeof(ActivationContextInformation), NULL);

    PTR64 Stack = NULL64;
    BOOLEAN ActivationFlag = FALSE;
    if (NT_SUCCESS(ntstatus))
    {
        ULONG Flag = FALSE;
        ULONG CreateFlags = (dwCreationFlags & CREATE_SUSPENDED) != 0;

        if (IsCurrentProcess && kernelbase_byte_101C55A4 || *(PVOID*)((PTR32)NtCurrentTeb() + TEB_SubProcessTag_OFFSET32) || ActivationContextInformation && TRUE)
            Flag = CreateFlags = 1;
        
        BOOLEAN IsSetStackSizeParamIsAReservation = (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) != 0;
        SIZE_T64 SizeOfStackCommit = IsSetStackSizeParamIsAReservation ? dwStackSize : 0;
        ntstatus = NtX64Call(NtCreateThreadEx, 11, (PTR64)&ThreadHandle, (DWORD64)0x1FFFFF, (PTR64)ObjectAttributes, (HANDLE64)hProcess, (PTR64)lpStartAddress, (PTR64)lpParameter, (DWORD64)CreateFlags, (DWORD64)0, SizeOfStackCommit, dwStackSize & -(SIZE_T64)IsSetStackSizeParamIsAReservation, (PTR64)&AttributeList);
        if (NT_SUCCESS(ntstatus))
        {
            if (!(*(PVOID*)((PTR32)NtCurrentTeb() + TEB_SubProcessTag_OFFSET32) || ActivationContextInformation && TRUE))
            {
                if (IsCurrentProcess && *(PVOID*)((PTR32)NtCurrentTeb() + TEB_SubProcessTag_OFFSET32))
                    *(PTR64 *)(Teb + TEB_SubProcessTag_OFFSET64) = *(PVOID*)((PTR32)NtCurrentTeb() + TEB_SubProcessTag_OFFSET32);

                ntstatus = NtX64Call(RtlAllocateActivationContextStack, 1, (PTR64)&Stack);
                if (NT_SUCCESS(ntstatus))
                {
                    *(PTR64 *)(Teb + TEB_ActivationContextStackPointer_OFFSET64) = Stack;

                    DWORD Cookie;
                    ntstatus = NtX64Call(RtlActivateActivationContextEx, 4, (DWORD64)1, Teb, ActivationContextInformation, (PTR64)&Cookie);

                    ActivationFlag = TRUE;
                }
            }
        }

        if (NT_SUCCESS(ntstatus))
        {
            if (lpThreadId)
                *lpThreadId = ClientId.UniqueThread;
            if (Flag && (dwCreationFlags & CREATE_SUSPENDED) == 0)
                ResumeThread((HANDLE)ThreadHandle);
        }
    }

    if (ActivationContextInformation)
        NtX64Call(RtlReleaseActivationContext, 1, ActivationContextInformation);

    if (Handle)
        NtClose(Handle);

    if (!NT_SUCCESS(ntstatus))
    {
        if (ActivationFlag && ActivationContextInformation)
            NtX64Call(RtlFreeActivationContextStack, 1, ActivationContextInformation);
        if (Stack)
            NtX64Call(RtlFreeActivationContextStack, 1, Stack);
        if (ThreadHandle)
        {
            NtTerminateThread((HANDLE)ThreadHandle, ntstatus);
            NtClose((HANDLE)ThreadHandle);
        }
        kernelbase_BaseSetLastNTError(ntstatus);
        ThreadHandle = NULL64;
    }

    return (HANDLE)ThreadHandle;
}

DECLARE_EXPORT HANDLE CreateRemoteThread64(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, POINTER64(LPVOID) lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    return CreateRemoteThreadEx64(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags & 0x10004, NULL, lpThreadId);
}

DECLARE_EXPORT HANDLE CreateThread64(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T64 dwStackSize, LPTHREAD_START_ROUTINE64 lpStartAddress, POINTER64(LPVOID) lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    return CreateRemoteThreadEx64((HANDLE)-1, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags & 0x10004, NULL, lpThreadId);
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