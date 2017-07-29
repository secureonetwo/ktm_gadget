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

#include <Windows.h>
#include <txfw32.h>
#include <ktmw32.h>
#include "ktm_defs.h"
#include "sb.h"

#define KTM_DLL_API __declspec(dllexport)

extern HANDLE _GLOBAL_TX_HANDLE;
extern __declspec(thread) BOOL IN_TX;
extern sb_str_t * mp_64;
extern sb_str_t * mp_32;
extern sb_str_t * mp_hdl;

static KTM_CreateFileA_t CreateFileA_real = CreateFileA;
static KTM_CreateFileW_t CreateFileW_real = CreateFileW;
static KTM_FindFirstFileExA_t FindFirstFileExA_real = FindFirstFileExA;
static KTM_FindFirstFileExW_t FindFirstFileExW_real = FindFirstFileExW;
static KTM_GetLongPathNameA_t GetLongPathNameA_real = GetLongPathNameA;
static KTM_GetLongPathNameW_t GetLongPathNameW_real = GetLongPathNameW;
static KTM_CreateDirectoryExA_t CreateDirectoryExA_real = CreateDirectoryExA;
static KTM_CreateDirectoryExW_t CreateDirectoryExW_real = CreateDirectoryExW;
static KTM_GetFullPathNameA_t GetFullPathNameA_real = GetFullPathNameA;
static KTM_GetFullPathNameW_t GetFullPathNameW_real = GetFullPathNameW;
static KTM_SetFileAttributesA_t SetFileAttributesA_real = SetFileAttributesA;
static KTM_SetFileAttributesW_t SetFileAttributesW_real = SetFileAttributesW;
static KTM_GetFileAttributesExA_t GetFileAttributesExA_real = GetFileAttributesExA;
static KTM_GetFileAttributesExW_t GetFileAttributesExW_real = GetFileAttributesExW;
static KTM_GetCompressedFileSizeA_t GetCompressedFileSizeA_real = GetCompressedFileSizeA;
static KTM_GetCompressedFileSizeW_t GetCompressedFileSizeW_real = GetCompressedFileSizeW;
static KTM_DeleteFileA_t DeleteFileA_real = DeleteFileA;
static KTM_DeleteFileW_t DeleteFileW_real = DeleteFileW;
static KTM_CopyFileExA_t CopyFileExA_real = CopyFileExA;
static KTM_CopyFileExW_t CopyFileExW_real = CopyFileExW;
static KTM_MoveFileWithProgressA_t MoveFileWithProgressA_real = MoveFileWithProgressA;
static KTM_MoveFileWithProgressW_t MoveFileWithProgressW_real = MoveFileWithProgressW;
static KTM_CreateHardLinkA_t CreateHardLinkA_real = CreateHardLinkA;
static KTM_CreateHardLinkW_t CreateHardLinkW_real = CreateHardLinkW;
static KTM_FindFirstStreamW_t FindFirstStreamW_real = FindFirstStreamW;
static KTM_FindFirstFileNameW_t FindFirstFileNameW_real = FindFirstFileNameW;
static KTM_CreateSymbolicLinkA_t CreateSymbolicLinkA_real = CreateSymbolicLinkA;
static KTM_CreateSymbolicLinkW_t CreateSymbolicLinkW_real = CreateSymbolicLinkW;
static KTM_RegCreateKeyExA_t RegCreateKeyExA_real = RegCreateKeyExA;
static KTM_RegCreateKeyExW_t RegCreateKeyExW_real = RegCreateKeyExW;
static KTM_RegDeleteKeyExA_t RegDeleteKeyExA_real = RegDeleteKeyExA;
static KTM_RegDeleteKeyExW_t RegDeleteKeyExW_real = RegDeleteKeyExW;
static KTM_RegOpenKeyExA_t RegOpenKeyExA_real = RegOpenKeyExA;
static KTM_RegOpenKeyExW_t RegOpenKeyExW_real = RegOpenKeyExW;
static KTM_CreateProcessA_t CreateProcessA_real = CreateProcessA;
static KTM_CreateProcessW_t CreateProcessW_real = CreateProcessW;
static KTM_RemoveDirectoryW_t RemoveDirectoryW_real = RemoveDirectoryW;
static KTM_RemoveDirectoryA_t RemoveDirectoryA_real = RemoveDirectoryA;

static char * CreateFileA_name = "CreateFileA";
static char * CreateFileW_name = "CreateFileW";
static char * FindFirstFileExA_name = "FindFirstFileExA";
static char * FindFirstFileExW_name = "FindFirstFileExW";
static char * GetLongPathNameA_name = "GetLongPathNameA";
static char * GetLongPathNameW_name = "GetLongPathNameW";
static char * CreateDirectoryExA_name = "CreateDirectoryExA";
static char * CreateDirectoryExW_name = "CreateDirectoryExW";
static char * GetFullPathNameA_name = "GetFullPathNameA";
static char * GetFullPathNameW_name = "GetFullPathNameW";
static char * SetFileAttributesA_name = "SetFileAttributesA";
static char * SetFileAttributesW_name = "SetFileAttributesW";
static char * GetFileAttributesExA_name = "GetFileAttributesExA";
static char * GetFileAttributesExW_name = "GetFileAttributesExW";
static char * GetCompressedFileSizeA_name = "GetCompressedFileSizeA";
static char * GetCompressedFileSizeW_name = "GetCompressedFileSizeW";
static char * DeleteFileA_name = "DeleteFileA";
static char * DeleteFileW_name = "DeleteFileW";
static char * CopyFileExA_name = "CopyFileExA";
static char * CopyFileExW_name = "CopyFileExW";
static char * MoveFileWithProgressA_name = "MoveFileWithProgressA";
static char * MoveFileWithProgressW_name = "MoveFileWithProgressW";
static char * CreateHardLinkA_name = "CreateHardLinkA";
static char * CreateHardLinkW_name = "CreateHardLinkW";
static char * FindFirstStreamW_name = "FindFirstStreamW";
static char * FindFirstFileNameW_name = "FindFirstFileNameW";
static char * CreateSymbolicLinkA_name = "CreateSymbolicLinkA";
static char * CreateSymbolicLinkW_name = "CreateSymbolicLinkW";
static char * RegCreateKeyExA_name = "RegCreateKeyExA";
static char * RegCreateKeyExW_name = "RegCreateKeyExW";
static char * RegDeleteKeyExA_name = "RegDeleteKeyExA";
static char * RegDeleteKeyExW_name = "RegDeleteKeyExW";
static char * RegOpenKeyExA_name = "RegOpenKeyExA";
static char * RegOpenKeyExW_name = "RegOpenKeyExW";
static char * CreateProcessA_name = "CreateProcessA";
static char * CreateProcessW_name = "CreateProcessW";
static char * RemoveDirectoryW_name = "RemoveDirectoryW";
static char * RemoveDirectoryA_name = "RemoveDirectoryA";

extern PtrTable_t PtrTable[];
int patch_functions(PtrTable_t *patch_table);

