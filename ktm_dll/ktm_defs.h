/* KTM_DLL
*
* Copyright (c) 2017
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
*     * Redistributions of source code must retain the above copyright notice,
*       this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright notice,
*       this list of conditions and the following disclaimer in the documentation
*       and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
* ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include<Windows.h>
#include<stdint.h>

typedef struct
{
	void * real_ptr;
	void * hook_ptr;
} PtrTable_t;

typedef HANDLE(WINAPI *KTM_CreateFileA_t)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);

typedef HANDLE(WINAPI *KTM_CreateFileW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);

typedef HANDLE(WINAPI *KTM_FindFirstFileExA_t)(
	_In_ LPCSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAA)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_Reserved_ LPVOID lpSearchFilter,
	_In_ DWORD dwAdditionalFlags
	);
typedef HANDLE(WINAPI *KTM_FindFirstFileExW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAW)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_Reserved_ LPVOID lpSearchFilter,
	_In_ DWORD dwAdditionalFlags
	);
typedef DWORD(WINAPI *KTM_GetLongPathNameA_t)(
	_In_ LPCSTR lpszShortPath,
	_Out_writes_to_opt_(cchBuffer, return +1) LPSTR lpszLongPath,
	_In_ DWORD cchBuffer
	);
typedef DWORD(WINAPI *KTM_GetLongPathNameW_t)(
	_In_ LPCWSTR lpszShortPath,
	_Out_writes_to_opt_(cchBuffer, return +1) LPWSTR lpszLongPath,
	_In_ DWORD cchBuffer
	);
typedef BOOL(WINAPI *KTM_CreateDirectoryExA_t)(
	_In_     LPCSTR lpTemplateDirectory,
	_In_     LPCSTR lpNewDirectory,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
typedef BOOL(WINAPI *KTM_CreateDirectoryExW_t)(
	_In_     LPCWSTR lpTemplateDirectory,
	_In_     LPCWSTR lpNewDirectory,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
typedef DWORD(WINAPI *KTM_GetFullPathNameA_t)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return +1) LPSTR lpBuffer,
	_Outptr_opt_ LPSTR * lpFilePart
	);
typedef DWORD(WINAPI *KTM_GetFullPathNameW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD nBufferLength,
	_Out_writes_to_opt_(nBufferLength, return +1) LPWSTR lpBuffer,
	_Outptr_opt_ LPWSTR * lpFilePart
	);
typedef BOOL(WINAPI *KTM_SetFileAttributesA_t)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes
	);
typedef BOOL(WINAPI *KTM_SetFileAttributesW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwFileAttributes
	);
typedef BOOL(WINAPI *KTM_GetFileAttributesExA_t)(
	_In_ LPCSTR lpFileName,
	_In_ GET_FILEEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FILE_ATTRIBUTE_DATA)) LPVOID lpFileInformation
	);
typedef BOOL(WINAPI *KTM_GetFileAttributesExW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ GET_FILEEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FILE_ATTRIBUTE_DATA)) LPVOID lpFileInformation
	);
typedef DWORD(WINAPI *KTM_GetCompressedFileSizeA_t)(
	_In_ LPCSTR lpFileName,
	_Out_opt_ LPDWORD lpFileSizeHigh
	);
typedef DWORD(WINAPI *KTM_GetCompressedFileSizeW_t)(
	_In_ LPCWSTR lpFileName,
	_Out_opt_ LPDWORD lpFileSizeHigh
	);
typedef BOOL(WINAPI *KTM_DeleteFileA_t)(
	_In_ LPCSTR lpFileName
	);
typedef BOOL(WINAPI *KTM_DeleteFileW_t)(
	_In_ LPCWSTR lpFileName
	);
typedef BOOL(WINAPI *KTM_CopyFileExA_t)(
	_In_        LPCSTR lpExistingFileName,
	_In_        LPCSTR lpNewFileName,
	_In_opt_    LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_    LPVOID lpData,
	_When_(pbCancel != NULL, _Pre_satisfies_(*pbCancel == FALSE))
	_Inout_opt_ LPBOOL pbCancel,
	_In_        DWORD dwCopyFlags
	);
typedef BOOL(WINAPI *KTM_CopyFileExW_t)(
	_In_        LPCWSTR lpExistingFileName,
	_In_        LPCWSTR lpNewFileName,
	_In_opt_    LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_    LPVOID lpData,
	_When_(pbCancel != NULL, _Pre_satisfies_(*pbCancel == FALSE))
	_Inout_opt_ LPBOOL pbCancel,
	_In_        DWORD dwCopyFlags
	);
typedef BOOL(WINAPI *KTM_MoveFileWithProgressA_t)(
	_In_     LPCSTR lpExistingFileName,
	_In_opt_ LPCSTR lpNewFileName,
	_In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_ LPVOID lpData,
	_In_     DWORD dwFlags
	);
typedef BOOL(WINAPI *KTM_MoveFileWithProgressW_t)(
	_In_     LPCWSTR lpExistingFileName,
	_In_opt_ LPCWSTR lpNewFileName,
	_In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_ LPVOID lpData,
	_In_     DWORD dwFlags
	);
typedef BOOL(WINAPI *KTM_CreateHardLinkA_t)(
	_In_       LPCSTR lpFileName,
	_In_       LPCSTR lpExistingFileName,
	_Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
typedef BOOL(WINAPI *KTM_CreateHardLinkW_t)(
	_In_       LPCWSTR lpFileName,
	_In_       LPCWSTR lpExistingFileName,
	_Reserved_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

typedef HANDLE(WINAPI *KTM_FindFirstStreamW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ STREAM_INFO_LEVELS InfoLevel,
	_Out_writes_bytes_(sizeof(WIN32_FIND_STREAM_DATA)) LPVOID lpFindStreamData,
	_Reserved_ DWORD dwFlags
	);
typedef HANDLE(WINAPI *KTM_FindFirstFileNameW_t)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwFlags,
	_Inout_ LPDWORD StringLength,
	_Out_writes_(*StringLength) PWSTR LinkName
	);
typedef BOOLEAN(APIENTRY *KTM_CreateSymbolicLinkA_t)(
	_In_ LPCSTR lpSymlinkFileName,
	_In_ LPCSTR lpTargetFileName,
	_In_ DWORD dwFlags
	);
typedef BOOLEAN(APIENTRY *KTM_CreateSymbolicLinkW_t)(
	_In_ LPCWSTR lpSymlinkFileName,
	_In_ LPCWSTR lpTargetFileName,
	_In_ DWORD dwFlags
	);
typedef LSTATUS(APIENTRY *KTM_RegCreateKeyExA_t)(
	_In_ HKEY hKey,
	_In_ LPCSTR lpSubKey,
	_Reserved_ DWORD Reserved,
	_In_opt_ LPSTR lpClass,
	_In_ DWORD dwOptions,
	_In_ REGSAM samDesired,
	_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_ PHKEY phkResult,
	_Out_opt_ LPDWORD lpdwDisposition
	);
typedef LSTATUS(APIENTRY *KTM_RegCreateKeyExW_t)(
	_In_ HKEY hKey,
	_In_ LPCWSTR lpSubKey,
	_Reserved_ DWORD Reserved,
	_In_opt_ LPWSTR lpClass,
	_In_ DWORD dwOptions,
	_In_ REGSAM samDesired,
	_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_ PHKEY phkResult,
	_Out_opt_ LPDWORD lpdwDisposition
	);
typedef LSTATUS(APIENTRY *KTM_RegDeleteKeyExA_t)(
	_In_ HKEY hKey,
	_In_ LPCSTR lpSubKey,
	_In_ REGSAM samDesired,
	_Reserved_ DWORD Reserved
	);
typedef LSTATUS(APIENTRY *KTM_RegDeleteKeyExW_t)(
	_In_ HKEY hKey,
	_In_ LPCWSTR lpSubKey,
	_In_ REGSAM samDesired,
	_Reserved_ DWORD Reserved
	);
typedef LSTATUS(APIENTRY *KTM_RegOpenKeyExA_t)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpSubKey,
	_In_opt_ DWORD ulOptions,
	_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult
	);
typedef LSTATUS(APIENTRY *KTM_RegOpenKeyExW_t)(
	_In_ HKEY hKey,
	_In_opt_ LPCWSTR lpSubKey,
	_In_opt_ DWORD ulOptions,
	_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult
	);
typedef BOOL(WINAPI *KTM_CreateProcessA_t)(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	);
typedef BOOL(WINAPI *KTM_CreateProcessW_t)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	);
typedef BOOL(WINAPI *KTM_RemoveDirectoryW_t)(
	_In_ LPCWSTR lpPathName
);
typedef BOOL(WINAPI *KTM_RemoveDirectoryA_t)(
	_In_ LPCSTR lpPathName
);
