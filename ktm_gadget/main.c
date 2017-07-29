/* KTM_GADGET
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

#include<Windows.h>
#include<Ktmw32.h>
#include<txfw32.h>
#include<stdio.h>
#include<stdlib.h>
#include<tchar.h>
#include<strsafe.h>
#include<stdint.h>
#include<Shlwapi.h>

#include"sb.h"

static sb_str_t * temp_32 = NULL;
static sb_str_t * temp_64 = NULL;
static sb_str_t * temp_hdl = NULL;

BOOL del_temp_paths()
{
	return (DeleteFileA(sb_cstr(temp_32)) || !PathFileExistsA(sb_cstr(temp_32))) &&
		(DeleteFileA(sb_cstr(temp_64)) || !PathFileExistsA(sb_cstr(temp_64))) &&
		(DeleteFileA(sb_cstr(temp_hdl)) || !PathFileExistsA(sb_cstr(temp_hdl)));
}
#define FATAL(s, ...)	{printf(s, __VA_ARGS__); del_temp_paths(); exit(1);}


void usage(LPTSTR exec_path)
{
		_tprintf(TEXT("Usage: %s <command>\n")
			TEXT("Run a command in a transaction. If command returns any value other than 0, all changes are rolled back.\n"), exec_path);
	exit(0);
}

BOOL is_help(LPTSTR parameter)
{
	WCHAR * help_verbs[] = { TEXT("-h"), TEXT("--help"), TEXT("-?"), TEXT("/?"), TEXT("/h"), TEXT("/help") };
	for (int i = 0; i < sizeof(help_verbs) / sizeof(help_verbs[0]); i++)
	{
		if (lstrcmpi(parameter, help_verbs[i]) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}
void generate_temp_paths(sb_str_t ** name_64, sb_str_t ** name_32, sb_str_t ** temp_32, sb_str_t ** temp_64, sb_str_t ** temp_hdl)
{
	CHAR temp_path[MAX_PATH + 1] = { 0 };
	CHAR source_path[MAX_PATH + 1] = { 0 };
	CHAR source_name[MAX_PATH + 1] = { 0 };
	CHAR str_GUID[MAX_PATH + 1] = { 0 };
	GUID name_base_guid = { 0 };

	size_t tp_len = GetTempPathA(sizeof(temp_path) - 1, temp_path);
	size_t sn_len = GetModuleFileNameA(GetModuleHandle(NULL), source_name, sizeof(source_name) - 1);
	char * test;
	size_t sp_len = GetFullPathNameA(source_name, sizeof(source_path)-1, source_path, &test);
	if (test != 0)
	{
		test[0] = 0;
	}

	CoCreateGuid(&name_base_guid);
	size_t gd_len = snprintf(str_GUID, sizeof(str_GUID)-1, "%lx-%hx-%hx-%llx", name_base_guid.Data1, name_base_guid.Data2, name_base_guid.Data3, *(uint64_t*)(char*)name_base_guid.Data4);

	CHAR * name_template[] = {
		source_path,
		"\\",
		"ktm_dll_64.dll",
		""
	};
	*name_64 = sb_new_join(SB_STR_ASCII, "", 0, name_template, sizeof(name_template)/sizeof(name_template[0]));

	name_template[2] = "ktm_dll_32.dll";
	*name_32 = sb_new_join(SB_STR_ASCII, "", 0, name_template, sizeof(name_template) / sizeof(name_template[0]));

	name_template[0] = temp_path;
	name_template[2] = str_GUID;
	name_template[3] = "_32.dll";
	*temp_32 = sb_new_join(SB_STR_ASCII, "", 0, name_template, sizeof(name_template) / sizeof(name_template[0]));

	name_template[3] = "_64.dll";
	*temp_64 = sb_new_join(SB_STR_ASCII, "", 0, name_template, sizeof(name_template) / sizeof(name_template[0]));

	name_template[3] = "_";
	*temp_hdl = sb_new_join(SB_STR_ASCII, "", 0, name_template, sizeof(name_template) / sizeof(name_template[0]));

	if (CopyFileA(sb_cstr(*name_64), sb_cstr(*temp_64), TRUE) == FALSE ||
		CopyFileA(sb_cstr(*name_32), sb_cstr(*temp_32), TRUE) == FALSE)
	{
		FATAL("Could not copy DLL files %s and %s to %s and %s.\n", sb_cstr(*name_64), sb_cstr(*name_32), sb_cstr(*temp_64), sb_cstr(*temp_32));
	}

}

sb_str_t* parse_args(unsigned long flag, int argc, TCHAR ** argv)
{
	/*
	* Parse command line as follows:
	* |_ Zero parameters:
	* |  |_ Print help, exit
	* |_ One Parameter:
	* |  |_ Equals: "-h", "--help", "-?", "/?", "/h", "/help":
	* |  |  |_ Print help, exit
	* |  |_ Else:
	* |     |_ Launch that command in a transaction
	* |_ Else:
	*    |_  All parameters are command and parameters for transaction
	*/

	if (argc <= 1 ||
		argc == 2 && is_help(argv[1]))
	{
		usage(argv[0]);
		return NULL;
	}
	else
	{
		return sb_new_join(flag, TEXT(" "), sizeof(TCHAR), argv + 1, argc - 1);
	}
}

BOOL inject_x64(HANDLE hProcess)
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		return FALSE;
	}
	else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		BOOL Wow64Process;
		IsWow64Process(hProcess, &Wow64Process);
		if (Wow64Process)
		{
			return FALSE;
		}
	}
	else
	{
		FATAL("ERROR. Unsupported architecture %i.\n", si.wProcessorArchitecture);
	}
	return TRUE;
}

void inject_dll(PROCESS_INFORMATION *pi, HANDLE transaction, sb_str_t *temp_path, sb_str_t *temp_hdl)
{
	char pid[16] = { 0 };
	void *entry_point = LoadLibraryA;
	void *tmp_buf = VirtualAllocEx(pi->hProcess, NULL, sb_bytes(temp_path)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (tmp_buf == NULL)
	{
		FATAL("Cannot allocate memory.");
	}
	if (WriteProcessMemory(pi->hProcess, tmp_buf, sb_cstr(temp_path), sb_bytes(temp_path) + 1, NULL) == FALSE)
	{
		FATAL("Cannot write process memory.");
	}

	HANDLE target_handle;
	if (DuplicateHandle(GetCurrentProcess(), transaction, pi->hProcess, &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS) == FALSE)
	{
		TerminateProcess(pi->hProcess, 0);
		FATAL("Could not duplicate handle.\n");
	}
	_itoa_s(pi->dwProcessId, pid, sizeof(pid), 10);
	sb_append(temp_hdl, pid, sizeof(pid));

	HANDLE IPC_HANDLE = CreateFileA(sb_cstr(temp_hdl), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	DWORD ipc_out = 0;
	if (IPC_HANDLE == INVALID_HANDLE_VALUE || WriteFile(IPC_HANDLE, &target_handle, sizeof(target_handle), &ipc_out, NULL) == FALSE)
	{
		TerminateProcess(pi->hProcess, 0);
		FATAL("Could not write TX handle to IPC.\n");
	}

	if (FlushFileBuffers(IPC_HANDLE) == FALSE)
	{
		TerminateProcess(pi->hProcess, 0);
		FATAL("Could not flush TX handle to IPC.\n");
	}

	if (CreateRemoteThread(pi->hProcess, NULL, 1024, (LPTHREAD_START_ROUTINE)entry_point, tmp_buf, 0, NULL) == INVALID_HANDLE_VALUE)
	{
		TerminateProcess(pi->hProcess, 0);
		FATAL("Cannot create remote thread.");
	}

	ResumeThread(pi->hThread);
}

void create_suspended(sb_str_t *run_cmd, PROCESS_INFORMATION *ProcessInfo)
{
	STARTUPINFO StartupInfo = { 0 };
	StartupInfo.cb = sizeof(StartupInfo);
	if (CreateProcess(NULL, run_cmd->buffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, ProcessInfo) == FALSE)
	{
		FATAL("Could not start target process with either x86 or amd64 DLL.\n");
	}
}


int __cdecl _tmain(int argc, TCHAR ** argv)
{
#if _UNICODE
	unsigned long flag = SB_STR_UTF16;
#else
	unsigned long flag = SB_STR_ASCII;
#endif
	sb_str_t *run_cmd = NULL;
	LPTSTR dll_path = NULL;
	HANDLE transaction;

	run_cmd = parse_args(flag, argc, argv);

	// install ktm_dll_64.dll and ktm_dll_32.dll to a temp directory
	sb_str_t * name_64;
	sb_str_t * name_32;
	generate_temp_paths(&name_64, &name_32, &temp_32, &temp_64, &temp_hdl);

	transaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
	if (transaction == INVALID_HANDLE_VALUE)
	{
		FATAL("Could not create transaction.\n");
	}

	// Launch the process
	PROCESS_INFORMATION ProcessInfo = { 0 };

	create_suspended(run_cmd, &ProcessInfo);
	if (inject_x64(ProcessInfo.hProcess) == TRUE)
	{
		inject_dll(&ProcessInfo, transaction, temp_64, temp_hdl);
	}
	else
	{
		inject_dll(&ProcessInfo, transaction, temp_32, temp_hdl);
	}

	WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

	DWORD exit_code = 0, count_down = 30;
	GetExitCodeProcess(ProcessInfo.hProcess, &exit_code);
	
	while (del_temp_paths() == FALSE)
	{
		count_down--;
		if (count_down == 0)
		{
			RollbackTransaction(transaction);
			FATAL("Could not delete dll files after 20 seconds, is process still running?!\n");
		}

		// Editors note: I'm already aware that sleep(x) isn't a valid method of sleeping for a deterministic amount of time.
		Sleep(1000);
	}

	if (exit_code == 0)
	{
		if (CommitTransaction(transaction) == FALSE)
		{
			FATAL("WARNING! Could not commit transaction, everything is lost.\n");
		}
		else
		{
			printf("Transactions committed.\n");
		}
	}
	else
	{
		if (RollbackTransaction(transaction) == FALSE)
		{
			FATAL("WARNING! Could not roll back transaction. Nothing is lost, but in a bad way.\n");
		}
		else
		{
			printf("Transactions rolled back.\n");
		}
	}
	

	CloseHandle(transaction);
	
	return 0;
}
