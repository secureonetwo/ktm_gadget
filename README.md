# KTM_GADGET
Instrument closed source software to use the Kernel Transaction Manager on 
Windows Vista through Windows 10. KTM_GADGET intercepts calls to many(!) 
file and registry API functions, see the caveat below.  If a program 
returns 0, all outstanding file and registry operations are committed. All 
other return values cause KTM_GADGET to roll back any file system or 
registry changes.

**Intercepted API**

* Kernel32.dll!CreateFileA
* Kernel32.dll!CreateFileW
* Kernel32.dll!FindFirstFileExA
* Kernel32.dll!FindFirstFileExW
* Kernel32.dll!GetLongPathNameA
* Kernel32.dll!GetLongPathNameW
* Kernel32.dll!CreateDirectoryExA
* Kernel32.dll!CreateDirectoryExW
* Kernel32.dll!GetFullPathNameA
* Kernel32.dll!GetFullPathNameW
* Kernel32.dll!SetFileAttributesA
* Kernel32.dll!SetFileAttributesW
* Kernel32.dll!GetFileAttributesExA
* Kernel32.dll!GetFileAttributesExW
* Kernel32.dll!GetCompressedFileSizeA
* Kernel32.dll!GetCompressedFileSizeW
* Kernel32.dll!DeleteFileA
* Kernel32.dll!DeleteFileW
* Kernel32.dll!CopyFileExA
* Kernel32.dll!CopyFileExW
* Kernel32.dll!MoveFileWithProgressA
* Kernel32.dll!MoveFileWithProgressW
* Kernel32.dll!CreateHardLinkA
* Kernel32.dll!CreateHardLinkW
* Kernel32.dll!FindFirstStreamW
* Kernel32.dll!FindFirstFileNameW
* Kernel32.dll!CreateSymbolicLinkA
* Kernel32.dll!CreateSymbolicLinkW
* Kernel32.dll!CreateProcessA
* Kernel32.dll!CreateProcessW
* Kernel32.dll!RemoveDirectoryW
* Kernel32.dll!RemoveDirectoryA
* Advapi32.dll!RegCreateKeyExA
* Advapi32.dll!RegCreateKeyExW
* Advapi32.dll!RegDeleteKeyExA
* Advapi32.dll!RegDeleteKeyExW
* Advapi32.dll!RegOpenKeyExA
* Advapi32.dll!RegOpenKeyExW

**Caveat**

KTM_GADGET doesn't support software that calls directly into ntdll. 
Functions including NtOpenFile will directly and completely bypass 
KTM_GADGET. This especially effects cmd.exe, which uses fancy low level 
system calls to implement some commands.

**License**
KTM_GADGET is released under the two-clause BSD license. KTM_DLL 
contains a gently modified version of libudis86, which is also licenced
under the two-clause BSD license.