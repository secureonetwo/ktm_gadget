/* String better
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

#include "sb.h"

void * sb_new(unsigned long flags, unsigned long prealloc_chars)
{
	sb_str_t * sb = (sb_str_t *)calloc(1, sizeof(sb_str_t));
	if (sb == NULL)
	{
		return NULL;
	}
	sb->flags = flags;
	if (prealloc_chars)
	{
		prealloc_chars += 1;
		if (flags & SB_STR_UTF16)
		{
			prealloc_chars *= 2;
		}
		sb->allocated = prealloc_chars;
		sb->buffer = malloc(prealloc_chars);
		if (sb->buffer == NULL)
		{
			free(sb);
		}
	}
	return sb;
}

void sb_free(void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)calloc(1, sizeof(sb_str_t));
	free(sb->buffer);
	free(sb);
}

void sb_terminate(void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	if (sb->flags & SB_STR_UTF16)
	{
		((uint8_t*)sb->buffer)[sb->used] = 0;
		((uint8_t*)sb->buffer)[sb->used + 1] = 0;
	}
	else
	{
		((uint8_t*)sb->buffer)[sb->used] = 0;
	}
}
int sb_resize(void * sb_obj, unsigned long req_chars)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	req_chars += 1;
	if (sb->flags & SB_STR_UTF16)
	{
		req_chars *= 2;
	}
	if (req_chars > sb->allocated)
	{
		req_chars += sb->allocated;
	}
	sb->buffer = realloc(sb->buffer, req_chars);
	if (sb->buffer == NULL)
	{
		sb->used = 0;
		sb->allocated = 0;
		return 0;
	}
	sb->allocated = req_chars;
	if (req_chars < sb->used)
	{
		sb->used = req_chars;

	}
	return 1;
}

/* Append cstring from source to sb_obj. We choose the minimum of max_len or the first NULL character */
int sb_append(void * sb_obj, const void * src_str, unsigned long max_len)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	unsigned long copy_len = 0;
	if (sb->flags & SB_STR_UTF16)
	{
		copy_len = (unsigned long)wcsnlen_s(src_str, max_len);
		copy_len <<= 1;
	}
	else
	{
		copy_len = (unsigned long)strnlen_s(src_str, max_len);
	}

	if (sb_resize(sb, sb->used + copy_len) == 0)
	{
		return 0;
	}

	memcpy_s(((uint8_t*)sb->buffer) + sb->used, sb->allocated - sb->used, src_str, copy_len);
	sb->used += copy_len;
	sb_terminate(sb);
	return 1;
}
#include <Windows.h>

void * sb_join(void * src_str, unsigned long max_len, void ** sb_objs, size_t count)
{
	sb_str_t * sb_out;
	sb_str_t ** sb_ptr = (sb_str_t **)sb_objs;
	unsigned long flags = -1;
	unsigned long copy_len = 0;
	if (count == 0)
	{
		return NULL;
	}
	for (size_t i = 0; i < count; i++)
	{
		if (flags == -1)
		{
			flags = sb_ptr[i]->flags;
		}
		else
		{
			if (flags != sb_ptr[i]->flags)
			{
				return NULL;
			}
		}

		if (sb_ptr[i]->flags & SB_STR_UTF16)
		{
			copy_len += (unsigned long)wcsnlen_s(sb_ptr[i]->buffer, sb_ptr[i]->used);
		}
		else
		{
			copy_len += (unsigned long)strnlen_s(sb_ptr[i]->buffer, sb_ptr[i]->used);
		}
	}

	if (flags & SB_STR_UTF16)
	{
		copy_len += (unsigned long)(wcsnlen_s(src_str, max_len) * (count - 1));

	}
	else
	{
		copy_len += (unsigned long)(strnlen_s(src_str, max_len) * (count - 1));
	}

	sb_out = sb_new(flags, copy_len);
	if (sb_out == NULL)
	{
		return NULL;
	}

	for (size_t i = 0; i < count; i++)
	{
		if (sb_append(sb_out, sb_ptr[i]->buffer, sb_ptr[i]->used) == 0)
		{
			sb_free(sb_out);
			return NULL;
		}
		if ((i + 1) < count)
		{
			if (sb_append(sb_out, src_str, max_len) == 0)
			{
				sb_free(sb_out);
				return NULL;
			}
		}
	}
	return sb_out;
}

void * sb_new_join(unsigned long flags, void * src_str, unsigned long max_len, void ** str_list, size_t count)
{
	sb_str_t ** sb_str_list = calloc(count, sizeof(void*));
	unsigned long str_len = 0;
	for (size_t i = 0; i < count; i++)
	{
		sb_str_list[i] = sb_new(flags, 0);

		if (flags & SB_STR_UTF16)
		{
			str_len = (unsigned long)wcslen(str_list[i]);
		}
		else
		{
			str_len = (unsigned long)strlen(str_list[i]);
		}
		sb_append(sb_str_list[i], str_list[i], str_len);
	}
	sb_str_t *sb_out = sb_join(src_str, max_len, sb_str_list, count);
	for (size_t i = 0; i < count; i++)
	{
		sb_free(sb_str_list[i]);
	}
	free(sb_str_list);
	return sb_out;
}

void sb_replace(void * sb_obj, void * fnd_str, unsigned long fnd_len, void * rpl_str, unsigned long rpl_len, int whence)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	unsigned long rpl_bytes;
	unsigned long fnd_bytes;
	size_t hop_count = 1;

	if (sb->flags & SB_STR_UTF16)
	{
		fnd_len = (unsigned long)wcsnlen_s(fnd_str, fnd_len);
		rpl_len = (unsigned long)wcsnlen_s(rpl_str, rpl_len);
		if ((sb->used >> 1) < fnd_len)
		{
			return;
		}
		rpl_bytes = rpl_len << 1;
		fnd_bytes = fnd_len << 1;
		hop_count = 2;
	}
	else
	{
		fnd_len = (unsigned long)strnlen_s(fnd_str, fnd_len);
		rpl_len = (unsigned long)strnlen_s(rpl_str, rpl_len);
		if (sb->used < fnd_len)
		{
			return;
		}
		rpl_bytes = rpl_len;
		fnd_bytes = fnd_len;
	}
	long delta = rpl_bytes - fnd_bytes;
	size_t start = 0;
	if (whence == SB_WHENCE_END)
	{
		start = sb->used - fnd_bytes;
	}
	for (; start <= sb->used - fnd_bytes; start += hop_count)
	{
		if (memcmp(((uint8_t*)sb->buffer) + start, fnd_str, fnd_bytes) == 0)
		{
			if (delta < 0)
			{
				// shrink string
				memmove(((uint8_t*)sb->buffer) + start + rpl_bytes, ((uint8_t*)sb->buffer) + start + fnd_bytes, sb->used + delta - start);
			}
			else if (delta > 0)
			{
				// grow string
				sb_resize(sb, sb->used + delta);
				memmove(((uint8_t*)sb->buffer) + start + rpl_bytes, ((uint8_t*)sb->buffer) + start + fnd_bytes, sb->used + delta - start);
			}
			memcpy(((uint8_t*)sb->buffer) + start, rpl_str, rpl_bytes);
			sb->used += delta;
		}
		if (whence == SB_WHENCE_START)
		{
			break;
		}
	}
	sb_terminate(sb);
}

void sb_truncate(void * sb_obj)
{
	sb_str_t * sb = (sb_str_t *)sb_obj;
	sb->used = 0;
	sb_terminate(sb_obj);
}
