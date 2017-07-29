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

#include <Shlwapi.h>
#include "ktm_dll.h"

void init_paths(HMODULE hModule)
{
	char suffix_a[] = "_64.dll";
	char suffix_b[] = "_32.dll";
	char suffix_c[] = "_";
	char pid[16] = { 0 };
	char path[MAX_PATH + 1] = { 0 };
	mp_64 = (sb_str_t*)sb_new(SB_STR_ASCII, 0);
	mp_32 = (sb_str_t*)sb_new(SB_STR_ASCII, 0);
	mp_hdl = (sb_str_t*)sb_new(SB_STR_ASCII, 0);

	GetModuleFileNameA(hModule, path, sizeof(path) - 1);
	sb_append(mp_64, path, sizeof(path));
	sb_append(mp_32, path, sizeof(path));

	sb_replace(mp_64, suffix_b, sizeof(suffix_b), suffix_a, sizeof(suffix_a), SB_WHENCE_END);
	sb_replace(mp_32, suffix_a, sizeof(suffix_a), suffix_b, sizeof(suffix_b), SB_WHENCE_END);

	sb_append(mp_hdl, sb_cstr(mp_64), sb_elements(mp_64));
	sb_replace(mp_hdl, suffix_a, sizeof(suffix_a), suffix_c, sizeof(suffix_c), SB_WHENCE_END);
	
	if (PathFileExistsA(sb_cstr(mp_64)) == FALSE ||
		PathFileExistsA(sb_cstr(mp_32)) == FALSE)
	{
		MessageBoxA(NULL, "COULD NOT FIND 32 AND 64 BIT DLLS.", "KTM", MB_OK | MB_ICONERROR);
		TerminateProcess(GetCurrentProcess(), 1);
	}
	_itoa_s(GetProcessId(GetCurrentProcess()), pid, sizeof(pid) - 1, 10);
	sb_append(mp_hdl, pid, sizeof(pid));
}

void open_handle()
{

	HANDLE f_hdl_h = CreateFileA(sb_cstr(mp_hdl), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (f_hdl_h == INVALID_HANDLE_VALUE)
	{
		int i = GetLastError();
		MessageBoxA(NULL, "COULD NOT OPEN HANDLE HANDLE.", sb_cstr(mp_hdl), MB_OK | MB_ICONERROR);
		TerminateProcess(GetCurrentProcess(), 1);
	}
	HANDLE hdl_h;
	DWORD bytes_read;
	if (ReadFile(f_hdl_h, &hdl_h, sizeof(hdl_h), &bytes_read, NULL) == FALSE)
	{
		MessageBoxA(NULL, "COULD NOT READ HANDLE HANDLE.", "KTM", MB_OK | MB_ICONERROR);
		TerminateProcess(GetCurrentProcess(), 1);
	}
	_GLOBAL_TX_HANDLE = hdl_h;
	CloseHandle(f_hdl_h);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	                       DWORD  ul_reason_for_call,
	                       LPVOID lpReserved
						 )
{
	PtrTable_t * ptrt_p;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			ptrt_p = PtrTable;

			init_paths(hModule);

			open_handle();

			if (patch_functions(ptrt_p) == 0)
			{
				MessageBoxA(NULL, "COULD NOT INJECT API.", "KTM", MB_OK | MB_ICONERROR);
				TerminateProcess(GetCurrentProcess(), 1);
			}
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
