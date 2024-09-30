# KERNEL64.dll
64bit Function Support Library for Windows WoW64 Process

## Supported Windows Versions
|            OS | Version        | Supported |
|--------------:|:---------------|:---------:|
|    Windows XP |                |     X     |
| Windows Vista |                |     X     |
|     Windows 7 |                |     X     |
|     Windows 8 |                |     X     |
|    Windows 10 | 17134/1803     |     O     |
|    Windows 10 | 17763/1809     |     O     |
|    Windows 10 | 18362/1903     |     O     |
|    Windows 10 | 18363/1909     |     O     |
|    Windows 10 | 19041/2004     |     O     |
|    Windows 10 | 19042/20H2     |     O     |
|    Windows 10 | 19043/21H1     |     O     |
|    Windows 10 | 19044/21H2     |     O     |
|    Windows 10 | 19045/22H2     |     O     |
|    Windows 11 | 22000/21H2     |     O     |
|    Windows 11 | 22621/22H2     |     O     |
|    Windows 11 | 22631/23H2     |     O     |

## KERNEL64's API
KERNEL64 has an API that extends memory-related features available in the WoW64 process to x64 mode

### Origianl APIs
| API | Description |
|------:|:---------|
| X64Call | Used to call x64 architecture functions |
| NtX64Call | Used to invoke the NtXxx or ZwXxx function in the ntdll of x64. If it is optimized for functions that use syscall and does not use syscall, use X64Call |

### Extended APIs
|               Original | x64 Extenstions              | Reference Docs |
|-----------------------:|:-----------------------------|:--------------:|
|           VirtualAlloc | VirtualAlloc64               | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) |
|         VirtualAllocEx | VirtualAllocEx64             | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) |
|         VirtualProtect | VirtualProtect64             | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) |
|       VirtualProtectEx | VirtualProtectEx64           | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) |
|           VirtualQuery | VirtualQuery64               | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualquery) |
|         VirtualQueryEx | VirtualQueryEx64             | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) |
|      ReadProcessMemory | ReadProcessMemory64          | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) |
|     WriteProcessMemory | WriteProcessMemory64         | [LINK](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) |
|       GetModuleHandleA | GetModuleHandleA64           | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) |
|       GetModuleHandleW | GetModuleHandleW64           | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew) |
|           LoadLibraryA | LoadLibraryA64               | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) |
|           LoadLibraryW | LoadLibraryW64               | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) |
|            FreeLibrary | FreeLibrary64                | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary) |
|         GetProcAddress | GetProcAddress64             | [LINK](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) |

## Download DLL
[Click Here](https://github.com/jungjin0003/KERNEL64.dll/releases/latest)

## Authors
 - [CrazyHacker](https://github.com/jungjin0003) - **JungJin Kim** - <admin@crazyhacker.kr>