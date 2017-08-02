/* KTM_DLL
*
* Copyright (c) 2017, SECUREONETWO
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

#include "ktm_dll.h"

void assert_transaction_valid()
{
	DWORD outcome;
	char * err_msg = NULL;
	int ret = GetTransactionInformation(_GLOBAL_TX_HANDLE, &outcome, 0, 0, NULL, 0, NULL);
	if (ret == FALSE)
	{
		err_msg = "ERROR, TRANSACTION HANDLE INVALID";
	}
	else
	{
		switch (outcome)
		{
		case TransactionOutcomeCommitted:
			err_msg = "ERROR, TRANSACTION ALREADY COMMITTED";
			break;
		case TransactionOutcomeAborted:
			err_msg = "ERROR, TRANSACTION ALREADY ROLLEDBACK";
			break;
		}
	}
	if (err_msg != NULL)
	{
		MessageBoxA(NULL, err_msg, "KTM", MB_OK | MB_ICONERROR);
		TerminateProcess(GetCurrentProcess(), 1);
	}
}

int inject_x64(HANDLE hProcess)
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		return PROCESSOR_ARCHITECTURE_INTEL;
	}
	else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		BOOL Wow64Process;
		IsWow64Process(hProcess, &Wow64Process);
		if (Wow64Process)
		{
			return PROCESSOR_ARCHITECTURE_INTEL;
		}
	}
	else
	{
		return 0;
	}
	return PROCESSOR_ARCHITECTURE_AMD64;
}


HANDLE WINAPI CreateFileA_imp(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, 
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (IN_TX)
	{
		return CreateFileA_real(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
			dwFlagsAndAttributes, hTemplateFile);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	USHORT CREATEFILE_MODE = TXFS_MINIVERSION_DEFAULT_VIEW;
	HANDLE ret = CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile,
		_GLOBAL_TX_HANDLE, &CREATEFILE_MODE, NULL);
	IN_TX = FALSE;
	return ret;
}
HANDLE WINAPI CreateFileW_imp(LPWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, 
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (IN_TX)
	{
		return CreateFileW_real(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
	assert_transaction_valid();
	IN_TX = TRUE;
	USHORT CREATEFILE_MODE = TXFS_MINIVERSION_DEFAULT_VIEW;
	HANDLE ret = CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, 
		_GLOBAL_TX_HANDLE, &CREATEFILE_MODE, NULL);
	IN_TX = FALSE;
	return ret;
}
HANDLE WINAPI FindFirstFileExA_imp(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, 
	DWORD dwAdditionalFlags)
{
	if (IN_TX)
	{
		return FindFirstFileExA_real(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	HANDLE ret = FindFirstFileTransactedA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
HANDLE WINAPI FindFirstFileExW_imp(LPWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, 
	DWORD dwAdditionalFlags)
{
	if (IN_TX)
	{
		return FindFirstFileExW_real(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	HANDLE ret = FindFirstFileTransactedW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetLongPathNameA_imp(LPCSTR lpszShortPath, LPSTR  lpszLongPath, DWORD cchBuffer)
{
	if (IN_TX)
	{
		return GetLongPathNameA_real(lpszShortPath, lpszLongPath, cchBuffer);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetLongPathNameTransactedA(lpszShortPath, lpszLongPath, cchBuffer, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetLongPathNameW_imp(LPWSTR lpszShortPath, LPWSTR  lpszLongPath, DWORD cchBuffer)
{
	if (IN_TX)
	{
		return GetLongPathNameW_real(lpszShortPath, lpszLongPath, cchBuffer);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetLongPathNameTransactedW(lpszShortPath, lpszLongPath, cchBuffer, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CreateDirectoryExA_imp(LPCSTR lpTemplateDirectory, LPCSTR lpNewDirectory, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	if (IN_TX)
	{
		return CreateDirectoryExA_real(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CreateDirectoryTransactedA(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CreateDirectoryExW_imp(LPWSTR lpTemplateDirectory, LPWSTR lpNewDirectory, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	if (IN_TX)
	{
		return CreateDirectoryExW_real(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CreateDirectoryTransactedW(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI RemoveDirectoryA_imp(LPCSTR lpPathName)
{
	if (IN_TX)
	{
		return RemoveDirectoryA_real(lpPathName);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = RemoveDirectoryTransactedA(lpPathName, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI RemoveDirectoryW_imp(LPCWSTR lpPathName)
{
	if (IN_TX)
	{
		return RemoveDirectoryW_real(lpPathName);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = RemoveDirectoryTransactedW(lpPathName, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetFullPathNameA_imp(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart)
{
	if (IN_TX)
	{
		return GetFullPathNameA_real(lpFileName, nBufferLength, lpBuffer, lpFilePart);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetFullPathNameTransactedA(lpFileName, nBufferLength, lpBuffer, lpFilePart, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetFullPathNameW_imp(LPWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
	if (IN_TX)
	{
		return GetFullPathNameW_real(lpFileName, nBufferLength, lpBuffer, lpFilePart);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetFullPathNameTransactedW(lpFileName, nBufferLength, lpBuffer, lpFilePart, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI SetFileAttributesA_imp(LPCSTR lpFileName, DWORD dwFileAttributes)
{
	if (IN_TX)
	{
		SetFileAttributesA_real(lpFileName, dwFileAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = SetFileAttributesTransactedA(lpFileName, dwFileAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI SetFileAttributesW_imp(LPWSTR lpFileName, DWORD dwFileAttributes)
{
	if (IN_TX)
	{
		return SetFileAttributesW_real(lpFileName, dwFileAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = SetFileAttributesTransactedW(lpFileName, dwFileAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI GetFileAttributesExA_imp(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
{
	if (IN_TX)
	{
		return GetFileAttributesExA_real(lpFileName, fInfoLevelId, lpFileInformation);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = GetFileAttributesTransactedA(lpFileName, fInfoLevelId, lpFileInformation, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI GetFileAttributesExW_imp(LPWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
{
	if (IN_TX)
	{
		return GetFileAttributesExW_real(lpFileName, fInfoLevelId, lpFileInformation);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = GetFileAttributesTransactedW(lpFileName, fInfoLevelId, lpFileInformation, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetCompressedFileSizeA_imp(LPCSTR lpFileName, LPDWORD lpFileSizeHigh)
{
	if (IN_TX)
	{
		return GetCompressedFileSizeA_real(lpFileName, lpFileSizeHigh);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetCompressedFileSizeTransactedA(lpFileName, lpFileSizeHigh, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
DWORD WINAPI GetCompressedFileSizeW_imp(LPWSTR lpFileName, LPDWORD lpFileSizeHigh)
{
	if (IN_TX)
	{
		return GetCompressedFileSizeW_real(lpFileName, lpFileSizeHigh);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	DWORD ret = GetCompressedFileSizeTransactedW(lpFileName, lpFileSizeHigh, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI DeleteFileA_imp(LPCSTR lpFileName)
{
	if (IN_TX)
	{
		return DeleteFileA_real(lpFileName);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = DeleteFileTransactedA(lpFileName, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI DeleteFileW_imp(LPWSTR lpFileName)
{
	if (IN_TX)
	{
		return DeleteFileW_real(lpFileName);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = DeleteFileTransactedW(lpFileName, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CopyFileExA_imp(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags)
{
	if (IN_TX)
	{
		return CopyFileExA_real(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CopyFileTransactedA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CopyFileExW_imp(LPWSTR lpExistingFileName, LPWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags)
{
	if (IN_TX)
	{
		return CopyFileExW_real(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CopyFileTransactedW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI MoveFileWithProgressA_imp(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, DWORD dwFlags)
{
	if (IN_TX)
	{
		return MoveFileWithProgressA_real(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = MoveFileTransactedA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI MoveFileWithProgressW_imp(LPWSTR lpExistingFileName, LPWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, DWORD dwFlags)
{
	if (IN_TX)
	{
		return MoveFileWithProgressW_real(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = MoveFileTransactedW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CreateHardLinkA_imp(LPCSTR lpFileName, LPCSTR lpExistingFileName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	if (IN_TX)
	{
		return CreateHardLinkA_real(lpFileName, lpExistingFileName, lpSecurityAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CreateHardLinkTransactedA(lpFileName, lpExistingFileName, lpSecurityAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOL WINAPI CreateHardLinkW_imp(LPWSTR lpFileName, LPWSTR lpExistingFileName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	if (IN_TX)
	{
		return CreateHardLinkW_real(lpFileName, lpExistingFileName, lpSecurityAttributes);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOL ret = CreateHardLinkTransactedW(lpFileName, lpExistingFileName, lpSecurityAttributes, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
HANDLE WINAPI FindFirstStreamW_imp(LPCWSTR lpFileName, STREAM_INFO_LEVELS InfoLevel, LPVOID lpFindStreamData, DWORD dwFlags)
{
	if (IN_TX)
	{
		return FindFirstStreamW_real(lpFileName, InfoLevel, lpFindStreamData, dwFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	HANDLE ret = FindFirstStreamTransactedW(lpFileName, InfoLevel, lpFindStreamData, dwFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
HANDLE WINAPI FindFirstFileNameW_imp(LPCWSTR lpFileName, DWORD dwFlags, LPDWORD StringLength, PWSTR LinkName)
{
	if (IN_TX)
	{
		return FindFirstFileNameW_real(lpFileName, dwFlags, StringLength, LinkName);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	HANDLE ret = FindFirstFileNameTransactedW(lpFileName, dwFlags, StringLength, LinkName, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOLEAN APIENTRY CreateSymbolicLinkA_imp(LPCSTR lpSymlinkFileName, LPCSTR lpTargetFileName, DWORD dwFlags)
{
	if (IN_TX)
	{
		return CreateSymbolicLinkA_real(lpSymlinkFileName, lpTargetFileName, dwFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOLEAN ret = CreateSymbolicLinkTransactedA(lpSymlinkFileName, lpTargetFileName, dwFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
BOOLEAN APIENTRY CreateSymbolicLinkW_imp(LPWSTR lpSymlinkFileName, LPWSTR lpTargetFileName, DWORD dwFlags)
{
	if (IN_TX)
	{
		return CreateSymbolicLinkW_real(lpSymlinkFileName, lpTargetFileName, dwFlags);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	BOOLEAN ret = CreateSymbolicLinkTransactedW(lpSymlinkFileName, lpTargetFileName, dwFlags, _GLOBAL_TX_HANDLE);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegCreateKeyExA_imp(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
	PHKEY phkResult, LPDWORD lpdwDisposition)
{
	if (IN_TX)
	{
		return RegCreateKeyExA_real(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegCreateKeyTransactedA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegCreateKeyExW_imp(HKEY hKey, LPWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult, LPDWORD lpdwDisposition)
{
	if (IN_TX)
	{
		return RegCreateKeyExW_real(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegCreateKeyTransactedW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegDeleteKeyExA_imp(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
	if (IN_TX)
	{
		return RegDeleteKeyExA_real(hKey, lpSubKey, samDesired, Reserved);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegDeleteKeyTransactedA(hKey, lpSubKey, samDesired, Reserved, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegDeleteKeyExW_imp(HKEY hKey, LPWSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
	if (IN_TX)
	{
		return RegDeleteKeyExW_real(hKey, lpSubKey, samDesired, Reserved);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegDeleteKeyTransactedW(hKey, lpSubKey, samDesired, Reserved, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegOpenKeyExA_imp(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	if (IN_TX)
	{
		return RegOpenKeyExA_real(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegOpenKeyTransactedA(hKey, lpSubKey, ulOptions, samDesired, phkResult, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}
LSTATUS APIENTRY RegOpenKeyExW_imp(HKEY hKey, LPWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	if (IN_TX)
	{
		return RegOpenKeyExW_real(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	}
	IN_TX = TRUE;
	assert_transaction_valid();
	LSTATUS ret = RegOpenKeyTransactedW(hKey, lpSubKey, ulOptions, samDesired, phkResult, _GLOBAL_TX_HANDLE, NULL);
	IN_TX = FALSE;
	return ret;
}


BOOL WINAPI CreateProcessA_imp(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, 
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	void *entry_point = LoadLibraryA;
	sb_str_t * inject_name = NULL;
	sb_str_t * new_mp_hdl = NULL;
	char pid[16] = { 0 };

	IN_TX = TRUE;
	// Process
	if (CreateProcessA_real(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) == FALSE)
	{
		IN_TX = FALSE;
		return FALSE;
	}

	_itoa_s(lpProcessInformation->dwProcessId, pid, sizeof(pid) - 1, 10);

	// Detect type
	int pid_type = inject_x64(lpProcessInformation->hProcess);
	if (pid_type == PROCESSOR_ARCHITECTURE_INTEL)
	{
		inject_name = mp_32;
	}
	else if (pid_type == PROCESSOR_ARCHITECTURE_AMD64)
	{
		inject_name = mp_64;
	}
	else
	{
		goto error;
	}

	// Generate handle path name
	new_mp_hdl = (sb_str_t*)sb_new(SB_STR_ASCII, 0);
	sb_append(new_mp_hdl, sb_cstr(mp_64), sb_elements(mp_64));
	sb_replace(new_mp_hdl, "_64.dll", 7, "_", 1, SB_WHENCE_END);
	sb_append(new_mp_hdl, pid, sizeof(pid));

	// Handle
	HANDLE target_handle;
	if (DuplicateHandle(GetCurrentProcess(), _GLOBAL_TX_HANDLE, lpProcessInformation->hProcess, &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS) == FALSE)
	{
		goto error;
	}

	HANDLE IPC_HANDLE = CreateFileA_real(sb_cstr(new_mp_hdl), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	DWORD ipc_out = 0;
	if (IPC_HANDLE == INVALID_HANDLE_VALUE)
	{
		goto error;
	}
	if (WriteFile(IPC_HANDLE, &target_handle, sizeof(target_handle), &ipc_out, NULL) == FALSE ||
		FlushFileBuffers(IPC_HANDLE) == FALSE)
	{
		CloseHandle(IPC_HANDLE);
		DeleteFileA_real(sb_cstr(new_mp_hdl));
		goto error;
	}

	// Inject DLL name
	void *tmp_buf = VirtualAllocEx(lpProcessInformation->hProcess, NULL, sb_bytes(inject_name) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (tmp_buf == NULL)
	{
		goto error;
	}

	if (WriteProcessMemory(lpProcessInformation->hProcess, tmp_buf, sb_cstr(inject_name), sb_bytes(inject_name) + 1, NULL) == FALSE ||
		CreateRemoteThread(lpProcessInformation->hProcess, NULL, 1024, (LPTHREAD_START_ROUTINE)entry_point, tmp_buf, 0, NULL) == INVALID_HANDLE_VALUE)
	{
		goto error;
	}

	if (!(dwCreationFlags&CREATE_SUSPENDED))
	{
		ResumeThread(lpProcessInformation->hThread);
	}
	IN_TX = FALSE;
	free(new_mp_hdl);
	return TRUE;

error:
	if (new_mp_hdl)
	{
		free(new_mp_hdl);
	}
	IN_TX = FALSE;
	TerminateProcess(lpProcessInformation->hProcess, 0);
	return FALSE;

}
BOOL WINAPI CreateProcessW_imp(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, 
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	void *entry_point = LoadLibraryA;
	sb_str_t * inject_name = NULL;
	sb_str_t * new_mp_hdl = NULL;
	char pid[16] = { 0 };

	IN_TX = TRUE;
	// Process
	if (CreateProcessW_real(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) == FALSE)
	{
		IN_TX = FALSE;
		return FALSE;
	}
	_itoa_s(lpProcessInformation->dwProcessId, pid, sizeof(pid) - 1, 10);

	// Detect type
	int pid_type = inject_x64(lpProcessInformation->hProcess);
	if (pid_type == PROCESSOR_ARCHITECTURE_INTEL)
	{
		inject_name = mp_32;
	}
	else if (pid_type == PROCESSOR_ARCHITECTURE_AMD64)
	{
		inject_name = mp_64;
	}
	else
	{
		goto error;
	}

	// Generate handle path name
	new_mp_hdl = (sb_str_t*)sb_new(SB_STR_ASCII, 0);
	sb_append(new_mp_hdl, sb_cstr(mp_64), sb_elements(mp_64));
	sb_replace(new_mp_hdl, "_64.dll", 7, "_", 1, SB_WHENCE_END);
	sb_append(new_mp_hdl, pid, sizeof(pid));

	// Handle
	HANDLE target_handle;
	if (DuplicateHandle(GetCurrentProcess(), _GLOBAL_TX_HANDLE, lpProcessInformation->hProcess, &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS) == FALSE)
	{
		goto error;
	}

	HANDLE IPC_HANDLE = CreateFileA_real(sb_cstr(new_mp_hdl), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	DWORD ipc_out = 0;
	if (IPC_HANDLE == INVALID_HANDLE_VALUE)
	{
		goto error;
	}
	if (WriteFile(IPC_HANDLE, &target_handle, sizeof(target_handle), &ipc_out, NULL) == FALSE ||
		FlushFileBuffers(IPC_HANDLE) == FALSE)
	{
		CloseHandle(IPC_HANDLE);
		DeleteFileA_real(sb_cstr(new_mp_hdl));
		goto error;
	}

	// Inject DLL name
	void *tmp_buf = VirtualAllocEx(lpProcessInformation->hProcess, NULL, sb_bytes(inject_name) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (tmp_buf == NULL)
	{
		goto error;
	}

	if (WriteProcessMemory(lpProcessInformation->hProcess, tmp_buf, sb_cstr(inject_name), sb_bytes(inject_name) + 1, NULL) == FALSE ||
		CreateRemoteThread(lpProcessInformation->hProcess, NULL, 1024, (LPTHREAD_START_ROUTINE)entry_point, tmp_buf, 0, NULL) == INVALID_HANDLE_VALUE)
	{
		goto error;
	}

	if (!(dwCreationFlags&CREATE_SUSPENDED))
	{
		ResumeThread(lpProcessInformation->hThread);
	}
	IN_TX = FALSE;
	free(new_mp_hdl);
	return TRUE;

error:
	if (new_mp_hdl)
	{
		free(new_mp_hdl);
	}
	IN_TX = FALSE;
	TerminateProcess(lpProcessInformation->hProcess, 0);
	return FALSE;
}

NTSTATUS NTAPI ZwCreateFile_imp(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     void              *ObjectAttributes,
	_Out_    void              *IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_opt_ PVOID              EaBuffer,
	_In_     ULONG              EaLength
)
{
	RtlSetCurrentTransaction_real(_GLOBAL_TX_HANDLE);

	NTSTATUS ret = ZwCreateFile_real(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	RtlSetCurrentTransaction_real(0);

	return ret;
}

HANDLE _GLOBAL_TX_HANDLE;
__declspec(thread) BOOL IN_TX = FALSE;
sb_str_t * mp_64 = NULL;
sb_str_t * mp_32 = NULL;
sb_str_t * mp_hdl = NULL;
KTM_ZwCreateFile_t ZwCreateFile_real = NULL;
KTM_RtlSetCurrentTransaction_t RtlSetCurrentTransaction_real = NULL;

PtrTable_t PtrTable[] =
{
	{ &ZwCreateFile_real, ZwCreateFile_imp },
	{ &CreateProcessA_real, CreateProcessA_imp },
	{ &CreateProcessW_real, CreateProcessW_imp },
	{ NULL,NULL },
	//{ NULL,NULL },
	//{ &CreateFileA_real, CreateFileA_imp },
	//{ &CreateFileW_real, CreateFileW_imp },
	//{ &FindFirstFileExA_real, FindFirstFileExA_imp },
	//{ &FindFirstFileExW_real, FindFirstFileExW_imp },
	//{ &GetLongPathNameA_real, GetLongPathNameA_imp },
	//{ &GetLongPathNameW_real, GetLongPathNameW_imp },
	//{ &CreateDirectoryExA_real, CreateDirectoryExA_imp },
	//{ &CreateDirectoryExW_real, CreateDirectoryExW_imp },
	//{ &GetFullPathNameA_real, GetFullPathNameA_imp },
	//{ &GetFullPathNameW_real, GetFullPathNameW_imp },
	//{ &SetFileAttributesA_real, SetFileAttributesA_imp },
	//{ &SetFileAttributesW_real, SetFileAttributesW_imp },
	//{ &GetFileAttributesExA_real, GetFileAttributesExA_imp },
	//{ &GetFileAttributesExW_real, GetFileAttributesExW_imp },
	//{ &GetCompressedFileSizeA_real, GetCompressedFileSizeA_imp },
	//{ &GetCompressedFileSizeW_real, GetCompressedFileSizeW_imp },
	//{ &DeleteFileA_real, DeleteFileA_imp },
	//{ &DeleteFileW_real, DeleteFileW_imp },
	//{ &CopyFileExA_real, CopyFileExA_imp },
	//{ &CopyFileExW_real, CopyFileExW_imp },
	//{ &MoveFileWithProgressA_real, MoveFileWithProgressA_imp },
	//{ &MoveFileWithProgressW_real, MoveFileWithProgressW_imp },
	//{ &CreateHardLinkA_real, CreateHardLinkA_imp },
	//{ &CreateHardLinkW_real, CreateHardLinkW_imp },
	//{ &FindFirstStreamW_real, FindFirstStreamW_imp },
	//{ &FindFirstFileNameW_real, FindFirstFileNameW_imp },
	//{ &CreateSymbolicLinkA_real, CreateSymbolicLinkA_imp },
	//{ &CreateSymbolicLinkW_real, CreateSymbolicLinkW_imp },
	//{ &RegCreateKeyExA_real, RegCreateKeyExA_imp },
	//{ &RegCreateKeyExW_real, RegCreateKeyExW_imp },
	//{ &RegDeleteKeyExA_real, RegDeleteKeyExA_imp },
	//{ &RegDeleteKeyExW_real, RegDeleteKeyExW_imp },
	//{ &RegOpenKeyExA_real, RegOpenKeyExA_imp },
	//{ &RegOpenKeyExW_real, RegOpenKeyExW_imp },
	//{ &RemoveDirectoryW_real, RemoveDirectoryW_imp },
	//{ &RemoveDirectoryA_real, RemoveDirectoryA_imp },
};
