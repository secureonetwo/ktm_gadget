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

#include <stdint.h>
#include <Windows.h>
#include <txfw32.h>
#include <ktmw32.h>
#include "libudis86\udis86.h"
#include "ktm_dll.h"

void * decode_jump(ud_t *u, uint8_t * location)
{
	// Lifted from udis86
	uint8_t * base = 0;

	ud_set_input_buffer(u, location, 10);
	size_t len = ud_disassemble(u);

	// Sanity check
	if (len == 0 ||
		u->mnemonic != UD_Ijmp ||
		u->operand[0].type == UD_OP_REG ||
		u->operand[0].index != UD_NONE)
	{
		goto error;
	}

	if (u->operand[0].type == UD_OP_MEM)
	{
		// dereference memory

		if (u->operand[0].base == UD_R_RIP)
		{
			base = location + len;

			if (u->operand[0].index)
			{
				goto error;
			}
			if (u->operand[0].offset != 0)
			{
				int64_t v;
				switch (u->operand[0].offset) {
				case 8: v = u->operand[0].lval.sbyte;  break;
				case 16: v = u->operand[0].lval.sword;  break;
				case 32: v = u->operand[0].lval.sdword; break;
				}

				base += v;
			}
			else
			{
				goto error;
			}
			base = *(uint8_t**)base;
		}
		else if (u->operand[0].base == UD_NONE && u->operand[0].offset)
		{
			uint64_t v;

			/* unsigned mem-offset */
			switch (u->operand[0].offset) {
			case 16: v = u->operand[0].lval.uword;  break;
			case 32: v = u->operand[0].lval.udword; break;
			case 64: v = u->operand[0].lval.uqword; break;
			}
			base = *(uint8_t**)v;
		}
		else
		{
			goto error;
		}
	}
	else if (u->operand[0].type == UD_OP_IMM)
	{
		uint64_t v;
		switch (u->operand[0].size) {
		case 8: v = u->operand[0].lval.ubyte;  break;
		case 16: v = u->operand[0].lval.uword;  break;
		case 32: v = u->operand[0].lval.udword; break;
		case 64: v = u->operand[0].lval.uqword; break;
		}
		base = (uint8_t*)v;
	}
	else if (u->operand[0].type == UD_OP_CONST)
	{
		base = (uint8_t*)(size_t)u->operand[0].lval.udword;
	}
	else
	{
		goto error;
	}

	return base;

error:
	return NULL;
}

size_t calc_length(ud_t *u, uint8_t * location, size_t min_len
#ifdef _WIN64
	, int *reg_map
#endif
)
{
	size_t len = 0;
	ud_set_input_buffer(u, location, 64);
	while (len <= min_len)
	{
		len += ud_disassemble(u);
#ifdef _WIN64
		for (int i = 0; i < 4; i++)
		{
			if (u->operand[i].type == UD_NONE)
			{
				break;
			}
			if (u->operand[i].type == UD_OP_REG)
			{
				switch (u->operand[i].base)
				{
				case UD_R_AL:
				case UD_R_AH:
				case UD_R_AX:
				case UD_R_EAX:
				case UD_R_RAX:
					*reg_map |= 1;
					break;
				case UD_R_R10:
				case UD_R_R10B:
				case UD_R_R10D:
				case UD_R_R10W:
					*reg_map |= 2;
					break;
				case UD_R_R11:
				case UD_R_R11B:
				case UD_R_R11D:
				case UD_R_R11W:
					*reg_map |= 4;
					break;
				}
				switch (u->operand[i].index)
				{
				case UD_R_RAX:
					*reg_map |= 1;
					break;
				case UD_R_R10:
					*reg_map |= 2;
					break;
				case UD_R_R11:
					*reg_map |= 4;
					break;
				}
			}
		}
#endif
	}
	return len;
}

uint8_t * init_jumptable(size_t len)
{
	return (uint8_t *)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

int patch_functions(PtrTable_t *patch_table)
{
	DWORD JUNK_VARIABLE;
	int ret = 0;
	ud_t u;
	void * function_location;
	size_t amend_length;
	size_t jt_pos = 0;
	size_t jt_len = 4096;

	ud_init(&u);

	uint8_t * jumptable = init_jumptable(jt_len);

#ifdef _WIN64 
	uint8_t patch_template[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t patch_template_r10[] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2 };
	uint8_t patch_template_r11[] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 };
	uint8_t patch_template_rax[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
	UINT_PTR * patch_location = (UINT_PTR *)(patch_template + 2);
	ud_set_mode(&u, 64);
#else
	uint8_t patch_template[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	UINT_PTR * patch_location = (UINT_PTR *)(patch_template + 2);
	ud_set_mode(&u, 32);
#endif

	while (patch_table->hook_ptr)
	{
		int reg_map = 0;

		function_location = decode_jump(&u, *(uint8_t**)patch_table->real_ptr);
		if (function_location == 0)
		{
			function_location = *(uint8_t**)patch_table->real_ptr;
		}
		amend_length = calc_length(&u, (uint8_t*)function_location, sizeof(patch_template)
#ifdef _WIN64
			, &reg_map
#endif
		);

		size_t real_offset = jt_pos;
		// copy bytes to amend
		if (memcpy_s(jumptable + jt_pos, jt_len - jt_pos, function_location, amend_length) != 0)
		{
			// Error
			return 0;
		}
		jt_pos += amend_length;


#ifdef _WIN64
		uint8_t * pt_safe;
		if (!(reg_map & 0x1))
		{
			pt_safe = patch_template_rax;
		}
		else if (!(reg_map & 0x2))
		{
			pt_safe = patch_template_r10;
		}
		else if (!(reg_map & 0x4))
		{
			pt_safe = patch_template_r11;
		}
		else
		{
			return 0;
		}
		// copy jump to real function
		if (memcpy_s(patch_template, sizeof(patch_template), pt_safe, sizeof(patch_template)) != 0)
		{
			// Error
			return 0;
		}
#endif
		*patch_location = (UINT_PTR)((uint8_t*)function_location + amend_length);

		// copy jump to real function
		if (memcpy_s(jumptable + jt_pos, jt_len - jt_pos, patch_template, sizeof(patch_template)) != 0)
		{
			// Error
			return 0;
		}
		jt_pos += amend_length;

		// update real_ptr
		*(void**)patch_table->real_ptr = jumptable + real_offset;

		// update real function
		*patch_location = (UINT_PTR)patch_table->hook_ptr;

		if (VirtualProtect(function_location, amend_length, PAGE_EXECUTE_READWRITE, &JUNK_VARIABLE) == 0)
		{
			// error
			return 0;
		}

		if (memcpy_s(function_location, amend_length, patch_template, sizeof(patch_template)) != 0)
		{
			// Error
			return 0;
		}
		jt_pos += amend_length;

		if (VirtualProtect(function_location, amend_length, PAGE_EXECUTE_READ, &JUNK_VARIABLE) == 0)
		{
			// error
			return 0;
		}

		patch_table += 1;
	}

	return 1;
}
