/* String better
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

#pragma once

/* sb.h - string better
 *
 * C strings that suck less.
 * 
 * Features:
 * |_ UTF-16 and ASCII support in the same API.
 * |_ Overflow safe.
 * |_ Guaranteed NULL character.
 *
 * Usage notes:
 * |_ All functions take number of elements, excluding NULL element, not bytes.
 */

#include<stdint.h>
#include<malloc.h>
#include<string.h>
#include<memory.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SB_STR_ASCII	0
#define SB_STR_UTF16	1
#define SB_WHENCE_START	1	// only at offset=0
#define SB_WHENCE_ANY	2	// anywhere
#define SB_WHENCE_END	3	// only at offset=len(str)-len(find)

typedef struct {
	void *buffer;
	unsigned long allocated;	// Total allocation size
	unsigned long used;			// Number of bytes, not including null byte or bytes
	unsigned long flags;
} sb_str_t;

void * sb_new(unsigned long flags, unsigned long prealloc_chars);
void sb_free(void * sb_obj);
void sb_terminate(void * sb_obj);
int sb_resize(void * sb_obj, unsigned long req_chars);
void * sb_join(void * src_str, unsigned long max_len, void ** sb_objs, size_t count);
void * sb_new_join(unsigned long flags, void * src_str, unsigned long max_len, void ** str_list, size_t count);
void sb_replace(void * sb_obj, void * fnd_str, unsigned long fnd_len, void * rpl_str, unsigned long rpl_len, int whence);
void sb_truncate(void * sb_obj);

/* Append cstring from source to sb_obj. We choose the minimum of max_len or the first NULL character */
int sb_append(void * sb_obj, const void * src_str, unsigned long max_len);

static inline const unsigned long sb_bytes(const void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	return sb->used;
}
static inline const unsigned long sb_elements(const void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	if (sb->flags & SB_STR_UTF16)
	{
		return sb->used>>1;
	}
	else
	{
		return sb->used;
	}
	
}
static inline const char * sb_cstr(const void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	if (sb->used == 0)
	{
		return NULL;
	}
	return (const char*)sb->buffer;
}
static inline const short * sb_ustr(const void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	if (sb->used == 0)
	{
		return NULL;
	}
	return (const short*)sb->buffer;
}

static int sb_sprintf(void * sb_obj, void * fmt, ...)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	return 0;	//stub, have to figure out if this should truncate, or even take an sb_obj
}

#ifdef __cplusplus
}
#endif
