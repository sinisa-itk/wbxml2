/*
 * libwbxml, the WBXML Library.
 * Copyright (C) 2002-2008 Aymerick Jehanne <aymerick@jehanne.org>
 * Copyright (C) 2011 Michael Bell <michael.bell@opensync.org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 * LGPL v2.1: http://www.gnu.org/copyleft/lesser.txt
 * 
 * Contact: aymerick@jehanne.org
 * Home: http://libwbxml.aymerick.com
 */
 
/**
 * @file wbxml_buffers.c
 * @ingroup wbxml_buffers
 *
 * @author Aymerick Jehanne <aymerick@jehanne.org>
 * @date 02/03/12
 *
 * @brief Generic Buffers Functions
 *
 * @note Original idea: Kannel Project (http://www.kannel.org/)
 */

#include <limits.h>
#include <ctype.h>

#include "wbxml_buffers.h"
#include "wbxml_base64.h"
#include "stdio.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


/* Memory management define */
#define WBXML_BUFFER_SPLIT_BLOCK 20

/**
 * The Generic Buffer type
 */
struct WBXMLBuffer_s
{
    WB_UTINY *data;             /**< The data */
    WB_ULONG  len;              /**< Length of data in buffer */
    WB_ULONG  malloced;         /**< Length of buffer */
    WB_BOOL   is_static;        /**< Is it a static buffer ?  */

	WB_BOOL   is_file;          // < Is the buffer data stored in file ?
	// // WB_ULONG  file_len;			// this can be calculated ! Do we need this as cached value ???
	FILE    * file;
	WBXMLCharsetMIBEnum   charset; /**< Charset of contained data */
};


static WB_BOOL grow_buff(WBXMLBuffer *buffer, WB_ULONG size);
static WB_BOOL reserve_buff_size(WBXMLBuffer *buffer, WB_ULONG size);
static WB_BOOL insert_data(WBXMLBuffer *buffer, WB_ULONG pos, const WB_UTINY *data, WB_ULONG len);
WBXML_DECLARE(WB_BOOL) wbxml_buffer_get_chunk(unsigned char * result, WBXMLBuffer *buf, WB_ULONG pos, WB_ULONG len);
static WB_BOOL convert_to_memory_buffer(WBXMLBuffer *buffer);


/**********************************
 *    Public functions
 */

long int _file_size(FILE * file) {
	long int pos = ftell(file), ret = 0;
	int status = fseek(file, 0, SEEK_END);
	if(status != 0) {
		printf("\nError _file_size::fseek(file, 0, SEEK_END): %d \n", ferror(file));
	} else {
		ret = ftell(file);
	}
	fseek(file, pos, SEEK_SET);
	return ret;
}

WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_create_file(const char * path, const char * mode) {
	FILE * file = fopen(path, mode);
	WBXMLBuffer *buffer = NULL;

	if(file == NULL) return NULL;

	buffer = (WBXMLBuffer *) wbxml_malloc(sizeof(WBXMLBuffer));
	if (buffer == NULL) {
		fclose(file);
		return NULL;
	}

	buffer->is_static    = FALSE;
	buffer->is_file      = TRUE;
	buffer->file         = file;
	buffer->malloced     = 0;
	buffer->data         = NULL; // a big NO NO -> WBXML_UTINY_NULL_STRING;
	// // buffer->file_len     = _file_size(file);
	buffer->len          = 0;
	buffer->charset      = WBXML_CHARSET_UNKNOWN;

	return buffer;
}


WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_create_real(const WB_UTINY *data, WB_ULONG len, WB_ULONG malloc_block)
{
    WBXMLBuffer *buffer = NULL;

    buffer = (WBXMLBuffer *) wbxml_malloc(sizeof(WBXMLBuffer));
    if (buffer == NULL)
        return NULL;
    
    buffer->is_static    = FALSE;
	buffer->is_file      = FALSE;
	buffer->file         = NULL;
	// // buffer->file_len     = 0;
	buffer->charset      = WBXML_CHARSET_UNKNOWN;

    if ((len <= 0) || (data == NULL)) {        
        buffer->malloced = 0;
        buffer->len = 0;
        buffer->data = NULL;
    } 
    else {               
        if (len + 1 > malloc_block + 1)
            buffer->malloced = len + 1 + malloc_block;
        else
            buffer->malloced = malloc_block + 1;
        
        buffer->data = (WB_UTINY *) wbxml_malloc(buffer->malloced * sizeof(WB_UTINY));
        if (buffer->data == NULL) {
            wbxml_free(buffer);
            return NULL;
        }

        buffer->len = len;
        memcpy(buffer->data, data, len);
        buffer->data[len] = '\0';
    }

    return buffer;
}


WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_sta_create_real(const WB_UTINY *data, WB_ULONG len)
{
    WBXMLBuffer *buffer = NULL;
  
    buffer = (WBXMLBuffer *) wbxml_malloc(sizeof(WBXMLBuffer));
    if (buffer == NULL) {
        return NULL;
    }

    buffer->is_static    = TRUE;
    buffer->data         = (WB_UTINY *) data;
    buffer->len          = len;
	buffer->is_file      = FALSE;
	buffer->file         = NULL;
	// // buffer->file_len     = 0;
	buffer->charset      = WBXML_CHARSET_UNKNOWN;

    return buffer;
}


WBXML_DECLARE(void) wbxml_buffer_destroy(WBXMLBuffer *buffer)
{
    if (buffer != NULL) {
		if(buffer->is_file) {
			if(buffer->file != NULL) {
				fclose(buffer->file);
				buffer->file = NULL;
			}
			buffer->is_file = FALSE;
		}
		if (!buffer->is_static) {
            /* Free dynamic data */
            wbxml_free(buffer->data);
        }

        /* Free structure */
        wbxml_free(buffer);
    }
}


WBXML_DECLARE_NONSTD(void) wbxml_buffer_destroy_item(void *buff)
{
    wbxml_buffer_destroy((WBXMLBuffer *) buff);
}


WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_duplicate(WBXMLBuffer *buff)
{
    WBXMLBuffer *result = NULL;

    if (buff == NULL)
        return NULL;

    result = wbxml_buffer_create_real(wbxml_buffer_get_cstr(buff),
                                      wbxml_buffer_len(buff),  
                                      wbxml_buffer_len(buff));

    return result;
}


WBXML_DECLARE(WB_ULONG) wbxml_buffer_len(WBXMLBuffer *buffer)
{
    if (buffer == NULL)
        return 0;
    if (buffer->is_file == TRUE) {
		return _file_size(buffer->file);
	}
    return buffer->len;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_get_char(WBXMLBuffer *buffer, WB_ULONG pos, WB_UTINY *result)
{
    if ((buffer == NULL) || (pos >= wbxml_buffer_len(buffer)))
        return FALSE;
    if(buffer->is_file == TRUE) {
		int ret = 0;
		if ( 0 != fseek(buffer->file, pos, SEEK_SET) ) return FALSE;
		ret = fgetc(buffer->file);
		if (ret == EOF) return FALSE;
		*result = (WB_UTINY) ret;
		return TRUE;
	} else {
		*result = buffer->data[pos];
		return TRUE;
	}
}


WBXML_DECLARE(void) wbxml_buffer_set_char(WBXMLBuffer *buffer, WB_ULONG pos, WB_UTINY ch)
{
    if ((buffer != NULL) && !buffer->is_static && (pos < buffer->len))
        buffer->data[pos] = ch;
}


WBXML_DECLARE(WB_UTINY *) wbxml_buffer_get_cstr(WBXMLBuffer *buffer)
{
    if ((buffer == NULL) || (buffer->len == 0))
        return WBXML_UTINY_NULL_STRING;
        
    return buffer->data;
}
WBXML_DECLARE(WB_UTINY *) wbxml_buffer_get_entire_string(WBXMLBuffer *buffer) {
	if ((buffer == NULL) || ( wbxml_buffer_len(buffer) == 0))
		return WBXML_UTINY_NULL_STRING;
	if(buffer->is_file == TRUE) {
		int bytes_read;

		// read entire file into memory of this buffer
		fseek(buffer->file, 0, SEEK_SET);
		// // grow_buff(buffer, buffer->file_len +1);
		// // int bytes_read = fread(buffer->data, 1, buffer->file_len, buffer->file);
		reserve_buff_size(buffer, _file_size(buffer->file));
		bytes_read = fread(buffer->data, 1, _file_size(buffer->file), buffer->file);
		buffer->data[bytes_read] = 0; // terminate string
	}
	return buffer->data;
}
WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_extract_memory_subbuffer(WBXMLBuffer *buff, WB_ULONG pos, WB_ULONG len) {
	WBXMLBuffer * ret;
	WB_BOOL mem_success;

	ret = wbxml_buffer_create_real(NULL, 0, 100);
	if(ret == NULL) return NULL;

	mem_success = reserve_buff_size(ret, len);
	if(mem_success == FALSE) {
		wbxml_buffer_destroy(ret);
		return NULL;
	}
	if(buff->is_file) {
		fseek(buff->file, pos, SEEK_SET);
		fread(ret->data, 1, len, buff->file);
	} else {
		memcpy(ret->data, buff->data + pos, len);
	}
	ret->len = len;
	return ret;
}

#define MOVE_BUFFER_SIZE    4096
#define SEARCH_BUFFER_SIZE  4096
#define COMPARE_BUFFER_SIZE 4096

void file_data_copy(FILE * src, WB_ULONG src_pos, FILE * dst, WB_ULONG dst_pos, WB_ULONG len) {
	WB_ULONG written = 0;
	char move_buffer[MOVE_BUFFER_SIZE];
	
	fseek(src, src_pos, SEEK_SET);
	fseek(dst, dst_pos, SEEK_SET);
	
	while(written < len) {
		size_t bytes_read, bytes_written;
		// copy loop 
		int left = len - written;
		int to_read = MIN(MOVE_BUFFER_SIZE, left);

		// check for EOF
		if(feof(src)) {
			printf("\nERROR file_data_copy: EOF on pos:%d written:%d \n", src_pos + written, written);
			return;
		}

		bytes_read = fread(move_buffer, 1, to_read, src);
		bytes_written = fwrite(move_buffer, 1, bytes_read, dst);
		if(bytes_read != to_read || bytes_written != bytes_read) {
			printf("\nERROR file_data_copy: count mismatch seposed:%d read:%d written:%d pos:%d\n", to_read, bytes_read, bytes_written, written);
		}
		written += bytes_read;
	}
}
WBXML_DECLARE(WBXMLBuffer *) wbxml_buffer_extract_file_subbuffer(WBXMLBuffer *buff, WB_ULONG pos, WB_ULONG len, const char * path, const char * mode) {
	WBXMLBuffer * ret;
	ret = wbxml_buffer_create_file(path, mode);
	if(ret == NULL) return NULL;
	if(buff->is_file == TRUE) {
		// copy from file to file
		file_data_copy(buff->file, pos, ret->file, 0, len);
	} else {
		// write from memory to file
		int bytes_written = fwrite(buff->data + pos, 1, len, ret->file);
		if(bytes_written != len) {
			printf("\nError wbxml_buffer_extract_file_subbuffer(): bytes_written(%d) != len(%d)\n", bytes_written, len);
		}
	}
	return ret;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_insert(WBXMLBuffer *to, WBXMLBuffer *buffer, WB_ULONG pos)
{
    if ((to != NULL) && (buffer != NULL) && !to->is_static)
        return insert_data(to, pos, buffer->data, buffer->len);

    return FALSE;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_insert_cstr(WBXMLBuffer *to, WB_UTINY *str, WB_ULONG pos)
{
    if ((to != NULL) && (str != NULL) && !to->is_static)
        return insert_data(to, pos, str, WBXML_STRLEN(str));

    return FALSE;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_append(WBXMLBuffer *dest, WBXMLBuffer *buff)
{
    if ((dest == NULL) || dest->is_static)
        return FALSE;

    if (buff == NULL)
        return TRUE;

	if(dest->is_file == TRUE || buff->is_file == TRUE) {
		unsigned int len = wbxml_buffer_len(buff);
		unsigned int processed_len = 0;
		unsigned char chunk[MOVE_BUFFER_SIZE +1];

		while (processed_len < len) {
			int left = len - processed_len;
			int chunksize_to_take = MIN(left, MOVE_BUFFER_SIZE);
			if( FALSE == wbxml_buffer_get_chunk(chunk, buff, processed_len, chunksize_to_take) ) {
				printf("\nERROR: wbxml_buffer_append::wbxml_buffer_get_chunk << FALSE\n");
				return FALSE;
			}
			// append to dest buffer
			if(wbxml_buffer_append_data_real(dest, chunk, chunksize_to_take) == FALSE) return FALSE;
			processed_len += chunksize_to_take;
		}
		return TRUE;
	} else {
		return wbxml_buffer_append_data(dest, wbxml_buffer_get_cstr(buff), wbxml_buffer_len(buff));
	}
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_append_data_real(WBXMLBuffer *buffer, const WB_UTINY *data, WB_ULONG len)
{
    if ((buffer == NULL) || buffer->is_static)
        return FALSE;

    if ((data == NULL) || (len == 0))
        return TRUE;

	if(buffer->is_file) {
		int bytes_written = 0;
		fseek(buffer->file, 0, SEEK_END);
		bytes_written = fwrite((void*) data, 1, len, buffer->file);
		if(bytes_written != len) {
			printf("\nERROR: wbxml_buffer_append_data_real::fwrite << %d instead %d \n", bytes_written, len);
			return FALSE;
		}
		return TRUE;
	} else {
		return insert_data(buffer, buffer->len, data, len);
	}
}

WBXML_DECLARE(WB_BOOL) wbxml_buffer_append_cstr_real(WBXMLBuffer *buffer, const WB_UTINY *data)
{
    if ((buffer == NULL) || buffer->is_static) {
        return FALSE;
    }

    if (data == NULL)
        return TRUE;

    return wbxml_buffer_append_data(buffer, data, WBXML_STRLEN(data));
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_append_char(WBXMLBuffer *buffer, WB_UTINY ch)
{
    WB_UTINY c = ch;

    if ((buffer == NULL) || buffer->is_static)
        return FALSE;
	if(buffer->is_file == TRUE) {
		fseek(buffer->file, 0, SEEK_END);
		fputc(ch, buffer->file);
		return WBXML_OK;
	} else {
		return insert_data(buffer, buffer->len, &c, 1);
	}
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_append_mb_uint_32(WBXMLBuffer *buffer, WB_ULONG value)
{
    /**
     * A uintvar is defined to be up to 32 bits large
     * so it will fit in 5 octets (to handle continuation bits) 
     */
    WB_UTINY octets[5];
    WB_LONG i = 0, start = 0;

    if ((buffer == NULL) || buffer->is_static)
        return FALSE;

    /**
     * Handle last byte separately; it has no continuation bit,
     * and must be encoded even if value is 0. 
     */
    octets[4] = (WB_UTINY) (value & 0x7f);
    value >>= 7;

    for (i = 3; value > 0 && i >= 0; i--) {
        octets[i] = (WB_UTINY) (0x80 | (value & 0x7f));
        value >>= 7;
    }
    start = i + 1;

    return wbxml_buffer_append_data(buffer, octets + start, 5 - start);
}


WBXML_DECLARE(void) wbxml_buffer_delete(WBXMLBuffer *buffer, WB_ULONG pos, WB_ULONG len)
{
    if ((buffer == NULL) || buffer->is_static)
        return;

    if (pos > buffer->len)
        pos = buffer->len;
        
    if (pos + len > buffer->len)
        len = buffer->len - pos;
        
    if (len > 0) {
        memmove(buffer->data + pos, buffer->data + pos + len,
                buffer->len - pos - len);
                
        buffer->len -= len;
        buffer->data[buffer->len] = '\0';
    }
}


WBXML_DECLARE(void) wbxml_buffer_shrink_blanks(WBXMLBuffer *buffer)
{
    WB_ULONG i = 0, j = 0, end = 0;
    WB_UTINY ch = 0;
    
    if ((buffer == NULL) || buffer->is_static)
        return;
        
    end = wbxml_buffer_len(buffer);

    for (i = 0; i < end; i++) 
    {
        if (wbxml_buffer_get_char(buffer, i, &ch) && isspace(ch)) 
        {
            /* Replace space by a whitespace */
            if (ch != ' ')
                wbxml_buffer_set_char(buffer, i, ' ');           

            /* Remove all following spaces */
            j = i = i + 1;
            while (wbxml_buffer_get_char(buffer, j, &ch) && isspace(ch))
                j++;

            if (j - i > 1)
                wbxml_buffer_delete(buffer, i, j - i);
        }
    }
}


WBXML_DECLARE(void) wbxml_buffer_strip_blanks(WBXMLBuffer *buffer)
{
    WB_ULONG start = 0, end = 0, len = 0;
    WB_UTINY ch = 0;

    if ((buffer == NULL) || buffer->is_static)
        return;

    /* Remove whitespaces at beginning of buffer... */
    while (wbxml_buffer_get_char(buffer, start, &ch) && 
           isspace(ch) && 
           start <= wbxml_buffer_len(buffer))
    {
        start ++;
    }

    if (start > 0)
        wbxml_buffer_delete(buffer, 0, start);

    /* ... and at the end */
    if ((len = wbxml_buffer_len(buffer)) > 0) {
        end = len = len - 1;
        while (wbxml_buffer_get_char(buffer, end, &ch) &&
            isspace(ch)) 
        {
            end--;
        }
        wbxml_buffer_delete(buffer, end + 1, len - end);
    }
}

WBXML_DECLARE(void) wbxml_buffer_no_spaces(WBXMLBuffer *buffer)
{
    WB_ULONG i = 0, j = 0, end = 0;
    WB_UTINY ch = 0;
    
    if ((buffer == NULL) || buffer->is_static)
        return;
        
    while (i < wbxml_buffer_len(buffer))
    {
        if (wbxml_buffer_get_char(buffer, i, &ch) && isspace(ch)) 
        {
             wbxml_buffer_delete(buffer, i, 1);
        } else {
             i++;
        }
    }
}

WBXML_DECLARE(WB_LONG) wbxml_buffer_compare(WBXMLBuffer *buff1, WBXMLBuffer *buff2)
{
    WB_LONG ret = 0, len = 0;

    if ((buff1 == NULL) || (buff2 == NULL)) {
        if ((buff1 == NULL) && (buff2 == NULL))
            return 0;

        if (buff1 == NULL)
            return -1;
        else
            return 1;
    }

    if (buff1->len < buff2->len)
        len = buff1->len;
    else
        len = buff2->len;

    if (len == 0) 
    {
        if (buff1->len == 0 && buff2->len > 0)
            return -1;
        if (buff1->len > 0 && buff2->len == 0)
            return 1;
        return 0;
    }

    if ((ret = memcmp(buff1->data, buff2->data, len)) == 0) 
    {
        if (buff1->len < buff2->len)
            ret = -1;
        else {
            if (buff1->len > buff2->len)
                ret = 1;
        }
    }

    return ret;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_get_chunk(unsigned char * result, WBXMLBuffer *buf, WB_ULONG pos, WB_ULONG len) {
	if( wbxml_buffer_len(buf) - pos < len ) return FALSE;
	if(buf->is_file) {
		size_t bytes_read;
		
		fseek(buf->file, pos, SEEK_SET);
		bytes_read = fread(result, 1, len, buf->file);
		if(bytes_read != len) return FALSE;
		return TRUE;
	} else {
		memcpy(result, buf->data + pos, len);
		return TRUE;
	}
}
WB_BOOL convert_to_memory_buffer(WBXMLBuffer *buffer) {
	if(buffer->is_file == TRUE) {
		int bytes_read;

		// read entire file into memory of this buffer
		fseek(buffer->file, 0, SEEK_SET);
		// // grow_buff(buffer, buffer->file_len +1);
		// // int bytes_read = fread(buffer->data, 1, buffer->file_len, buffer->file);
		reserve_buff_size(buffer, _file_size(buffer->file));
		bytes_read = fread(buffer->data, 1, _file_size(buffer->file), buffer->file);
		buffer->data[bytes_read] = 0; // terminate string
		// close file
		fclose(buffer->file);
		buffer->file = NULL;
		buffer->is_file = FALSE;
	}
	return TRUE;
}

WBXML_DECLARE(WB_BOOL) wbxml_buffer_compare_chunk(WBXMLBuffer *buff1, WB_ULONG pos1, WBXMLBuffer *buff2, WB_ULONG pos2, WB_ULONG len) {
	if ((buff1 == NULL) || (buff2 == NULL)) {
		return FALSE;
	}
	if(len <= 0) return FALSE; // ? undefined ?

	// check for boundaries
	if( wbxml_buffer_len(buff1) - pos1 < len ) return FALSE;
	if( wbxml_buffer_len(buff2) - pos2 < len ) return FALSE;

	if( buff1->is_file == TRUE || buff2->is_file == TRUE ) {
		// compare in chunks
		unsigned int processed_len = 0;
		unsigned char chunk1[COMPARE_BUFFER_SIZE], chunk2[COMPARE_BUFFER_SIZE];
		while (processed_len < len) {
			int left = len - processed_len;
			int chunksize_to_take = MIN(left, COMPARE_BUFFER_SIZE);
			if(    FALSE == wbxml_buffer_get_chunk(chunk1, buff1, pos1 + processed_len, chunksize_to_take) 
				|| FALSE == wbxml_buffer_get_chunk(chunk2, buff2, pos2 + processed_len, chunksize_to_take) ) {
					printf("\nERROR: wbxml_buffer_compare_chunk::wbxml_buffer_get_chunk << FALSE\n");
					return FALSE;
			}
			// compare chunks
			if(memcmp(chunk1, chunk2, chunksize_to_take) != 0) return FALSE;
			processed_len += chunksize_to_take;
		}
		return TRUE;
	} else {
		return memcmp(buff1->data + pos1, buff2->data + pos2, len) == 0 ? TRUE : FALSE;
	}

}


WBXML_DECLARE(WB_LONG) wbxml_buffer_compare_cstr(WBXMLBuffer *buff, const WB_TINY *str)
{
    WB_LONG ret = 0, len = 0;

    if ((buff == NULL) || (str == NULL)) {
        if ((buff == NULL) && (str == NULL))
            return 0;

        if (buff == NULL)
            return -1;
        else
            return 1;
    }

    if (buff->len < WBXML_STRLEN(str))
        len = buff->len;
    else
        len = WBXML_STRLEN(str);

    if (len == 0) 
    {
        if (buff->len == 0 && WBXML_STRLEN(str) > 0)
            return -1;
        if (buff->len > 0 && WBXML_STRLEN(str) == 0)
            return 1;
        return 0;
    }

    if ((ret = memcmp(buff->data, str, len)) == 0) 
    {
        if (buff->len < WBXML_STRLEN(str))
            ret = -1;
        else {
            if (buff->len > WBXML_STRLEN(str))
                ret = 1;
        }
    }

    return ret;
}


WBXML_DECLARE(WBXMLList *) wbxml_buffer_split_words_real(WBXMLBuffer *buff)
{
    WB_UTINY *p = NULL;
    WBXMLList *list = NULL;
    WBXMLBuffer *word = NULL;
    WB_ULONG i = 0, start = 0, end = 0;

    if ((list = wbxml_list_create()) == NULL)
        return NULL;

    p = buff->data;
    i = 0;
    while (TRUE)
    {
        while (i < buff->len && isspace(*p)) {
            ++p;
            ++i;
        }
        start = i;

        while (i < buff->len && !isspace(*p)) {
            ++p;
            ++i;
        }
        end = i;

        if (start == end)
            break;

        if((word = wbxml_buffer_create(buff->data + start, end - start, WBXML_BUFFER_SPLIT_BLOCK)) == NULL) {
            wbxml_list_destroy(list, wbxml_buffer_destroy_item);
            return NULL;
        }

        wbxml_list_append(list, word);
    }

    return list;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_search_char(WBXMLBuffer *to, WB_UTINY ch, WB_ULONG pos, WB_ULONG *result)
{
    WB_UTINY *p = NULL;

    if (to == NULL)
        return FALSE;

	if (pos >= wbxml_buffer_len(to))
		return FALSE;

	if(to->is_file == TRUE) {
		WB_ULONG start_of_search_chunk = pos;
		WB_UTINY * found_char_pointer = NULL;

		while(start_of_search_chunk < wbxml_buffer_len(to)) {
			size_t   bytes_read;
			WB_ULONG left = wbxml_buffer_len(to) - start_of_search_chunk;
			int      to_read = MIN(SEARCH_BUFFER_SIZE, left);
			WB_UTINY search_buffer[SEARCH_BUFFER_SIZE];
			
			fseek(to->file, start_of_search_chunk, SEEK_SET);
			bytes_read = fread(search_buffer, 1, to_read, to->file);
			found_char_pointer = (WB_UTINY *) memchr(search_buffer, ch, bytes_read);
			if(found_char_pointer != NULL) {
				int offset = found_char_pointer - search_buffer;
				*result = start_of_search_chunk + offset;
				return TRUE;
			}
			// char not found in this chunk
			start_of_search_chunk += bytes_read;
		}
		return FALSE;
	} else {
		// we know that buffer is in memory so we can use buffer structure internals here.
		if ((p = (WB_UTINY *) memchr(to->data + pos, ch, to->len - pos)) == NULL)
			return FALSE;

		if (result != NULL)
			*result = p - to->data;

		return TRUE;
	}
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_search(WBXMLBuffer *to, WBXMLBuffer *search, WB_ULONG pos, WB_ULONG *result)
{
    WB_UTINY first = 0;

    if ((to == NULL) || (search == NULL))
        return FALSE;

    if (result != NULL)
        *result = 0;

    /* Always "find" an empty string */
// //	if (search->len == 0)
    if (wbxml_buffer_len(search) == 0) {
		*result = pos;
        return TRUE;
	}

    /* Check if 'search' is greater than 'to' */
    if (wbxml_buffer_len(search) > wbxml_buffer_len(to))
        return FALSE;

    /* We are searching for one char */
    if (wbxml_buffer_len(search) == 1) {
		unsigned char search_char = 0;
		wbxml_buffer_get_char(search, 0, &search_char); // not checking result status because of same check above.
		// // return wbxml_buffer_search_char(to, search->data[0], pos, result);
        return wbxml_buffer_search_char(to, search_char, pos, result);
	}

    /* For each occurrence of search's first character in to, then check if the rest of needle follows.
     * Stop if there are no more occurrences, or if the rest of 'search' can't possibly fit in 'to'. */
    first = search->data[0];
    while ((wbxml_buffer_search_char(to, first, pos, &pos)) && 
           (wbxml_buffer_len(to) - pos >= wbxml_buffer_len(search))) 
    {
		if (TRUE == wbxml_buffer_compare_chunk(to, pos, search, 0, wbxml_buffer_len(search))) {
			if (result != NULL) {
				*result = pos;
			}
			return TRUE;
		}
        // // if (memcmp(to->data + pos, search->data, search->len) == 0) {
        // //     if (result != NULL)
        // //         *result = pos;
        // //     return TRUE;
        // // }
        pos++;
    }

    return FALSE;    
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_search_cstr(WBXMLBuffer *to, WB_UTINY *search, WB_ULONG pos, WB_ULONG *result)
{
    WB_UTINY first = 0;

    if ((to == NULL) || (search == NULL))
        return FALSE;

    if (result != NULL)
        *result = 0;

    /* Always "find" an empty string */
    if (WBXML_STRLEN(search) == 0)
        return TRUE;

    /* Check if 'search' is greater than 'to' */
    if (WBXML_STRLEN(search) > to->len)
        return FALSE;

    /* We are searching for one char */
    if (WBXML_STRLEN(search) == 1)
        return wbxml_buffer_search_char(to, search[0], pos, result);

    /* For each occurrence of search's first character in to, then check if the rest of needle follows.
     * Stop if there are no more occurrences, or if the rest of 'search' can't possibly fit in 'to'. */
    first = search[0];
    while ((wbxml_buffer_search_char(to, first, pos, &pos)) && 
           (to->len - pos >= WBXML_STRLEN(search))) 
    {
        if (memcmp(to->data + pos, search, WBXML_STRLEN(search)) == 0) {
            if (result != NULL)
                *result = pos;
            return TRUE;
        }
        pos++;
    }

    return FALSE;
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_contains_only_whitespaces(WBXMLBuffer *buffer)
{
    WB_ULONG i = 0;

    if (buffer == NULL)
        return FALSE;

    for (i=0; i<buffer->len; i++) {
        if (!isspace(*(buffer->data + i)))
            return FALSE;
    }

    return TRUE;
}


WBXML_DECLARE(void) wbxml_buffer_hex_to_binary(WBXMLBuffer *buffer)
{
    WB_UTINY *p = NULL;
    WB_ULONG i = 0, len = 0;

    if ((buffer == NULL) || buffer->is_static)
        return;

    p = buffer->data;
    len = wbxml_buffer_len(buffer);

    /* Convert ascii data to binary values */
    for (i = 0; i < len; i++, p++) {
        if (*p >= '0' && *p <= '9')
            *p -= '0';
        else if (*p >= 'a' && *p <= 'f')
            *p = (WB_UTINY) (*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F')
            *p = (WB_UTINY) (*p - 'A' + 10);
        else {
            /* Bad Bad ! There should be only digits in the buffer ! */
            *p = 0;
        }
    }

    /* De-hexing will compress data by factor of 2 */
    len = wbxml_buffer_len(buffer) / 2;

    for (i = 0; i < len; i++)
        buffer->data[i] = (WB_UTINY) (buffer->data[i * 2] * 16 | buffer->data[i * 2 + 1]);

    buffer->len = len;
    buffer->data[len] = '\0';
}


WBXML_DECLARE(WB_BOOL) wbxml_buffer_binary_to_hex(WBXMLBuffer *buffer, WB_BOOL uppercase)
{
    WB_UTINY *hexits = NULL;
    WB_LONG i = 0;

	if( convert_to_memory_buffer(buffer) == FALSE ) {
		printf("\nERROR: wbxml_buffer_binary_to_hex::convert_to_memory_buffer << FALSE \n");
		return FALSE;
	}

    if ((buffer == NULL) || buffer->is_static)
        return FALSE;

    if (wbxml_buffer_len(buffer) == 0)
        return TRUE;

    hexits = (WB_UTINY *)(uppercase ? "0123456789ABCDEF" : "0123456789abcdef");

    /* Grows the Buffer size by 2 */
    grow_buff(buffer, buffer->len * 2);

    /* In-place modification must be done back-to-front to avoid
     * overwriting the data while we read it.  Even the order of
     * the two assignments is important, to get i == 0 right. 
     */
    for (i = buffer->len - 1; i >= 0; i--) {
        buffer->data[i * 2 + 1] = hexits[buffer->data[i] % 16];
        buffer->data[i * 2] = hexits[(buffer->data[i] / 16) & 0xf];
    }

    buffer->len = buffer->len * 2;
    buffer->data[buffer->len] = '\0';

    return TRUE;
}

WBXML_DECLARE(WBXMLError) wbxml_buffer_decode_base64(WBXMLBuffer *buffer)
{
    WB_UTINY   *result = NULL;
    WB_LONG     len    = 0;
    WBXMLError  ret    = WBXML_OK;
    
    if (buffer == NULL) {
        return WBXML_ERROR_INTERNAL;
    }

    wbxml_buffer_no_spaces(buffer);
    
    if ((len = wbxml_base64_decode((const WB_UTINY *) wbxml_buffer_get_cstr(buffer),
                                   wbxml_buffer_len(buffer), &result)) <= 0)
    {
        return WBXML_ERROR_B64_DEC;
    }
    
    /* Reset buffer */
    wbxml_buffer_delete(buffer, 0, wbxml_buffer_len(buffer));
    
    /* Set binary data */
    if (!wbxml_buffer_append_data(buffer, result, len)) {
        ret = WBXML_ERROR_NOT_ENOUGH_MEMORY;
    }
    
    wbxml_free(result);
    
    return ret;
}

WBXML_DECLARE(WBXMLError) wbxml_buffer_encode_base64(WBXMLBuffer *buffer)
{
    WB_UTINY   *result = NULL;
    WBXMLError  ret    = WBXML_OK;
    
    if (buffer == NULL) {
        return WBXML_ERROR_INTERNAL;
    }
    
    if ((result = wbxml_base64_encode((const WB_UTINY *) wbxml_buffer_get_cstr(buffer),
                                      wbxml_buffer_len(buffer))) == NULL)
    {
        return WBXML_ERROR_B64_ENC;
    }
    
    /* Reset buffer */
    wbxml_buffer_delete(buffer, 0, wbxml_buffer_len(buffer));
    
    /* Set data */
    if (!wbxml_buffer_append_cstr(buffer, result)) {
        ret = WBXML_ERROR_NOT_ENOUGH_MEMORY;
    }
    
    wbxml_free(result);
    
    return ret;
}

WBXML_DECLARE(void) wbxml_buffer_remove_trailing_zeros(WBXMLBuffer **buffer)
{
    WB_UTINY ch = 0;

    if ((buffer == NULL) || (*buffer == NULL))
        return;

    while ((*buffer)->len > 0) {
        if (wbxml_buffer_get_char(*buffer, wbxml_buffer_len(*buffer) - 1, &ch) && (ch == '\0'))
            wbxml_buffer_delete(*buffer, wbxml_buffer_len(*buffer) - 1, 1);
        else
            return;
    }
}


/**********************************
 *    Private functions
 */

/**
 * @brief Add space for at least 'size' octets
 * @param buffer The buffer
 * @param size The size to add
 * @return TRUE is space successfully reserved, FALSE is size was negative, buffer was NULL or if not enough memory
 */
static WB_BOOL grow_buff(WBXMLBuffer *buffer, WB_ULONG size)
{
    if ((buffer == NULL) || buffer->is_static)
        return FALSE;

	if(buffer->is_file == TRUE) return TRUE;
        
    /* Make room for the invisible terminating NUL */
    size++; 

    if ((buffer->len + size) > buffer->malloced) {
        if ((buffer->malloced * 2) < (buffer->len + size))
            buffer->malloced = buffer->len + size;
        else
            buffer->malloced *= 2;
            
        buffer->data = wbxml_realloc(buffer->data, buffer->malloced);
        if (buffer->data == NULL)
            return FALSE;
    }

    return TRUE;
}
/**
 * @brief Add space if needed for specified total-size
 * @param buffer The buffer
 * @param size The size to add
 * @return TRUE is space successfully reserved, FALSE is size was negative, buffer was NULL or if not enough memory
 * @warning This function is always used for memory storage of buffer, even in case of file sorage buffer.
 */
static WB_BOOL reserve_buff_size(WBXMLBuffer *buffer, WB_ULONG total_size) {
	total_size++; // just in case you forgot to include terminating zero.
	if (total_size > buffer->malloced) {
		if ((buffer->malloced * 2) < total_size) buffer->malloced = total_size;
		else buffer->malloced *= 2;
		buffer->data = (WB_UTINY *) wbxml_realloc(buffer->data, buffer->malloced);
		if (buffer->data == NULL) return FALSE;
	}
	return TRUE;
}


/**
 * @brief Insert data into a Generic Buffer
 * @param buffer The Generic Buffer
 * @param pos Position in Generic Buffer where to insert data
 * @param data Data to insert
 * @param len Data length
 * @return TRUE is data inserted, FALSE if not
 */
static WB_BOOL insert_data(WBXMLBuffer *buffer, WB_ULONG pos, const WB_UTINY *data, WB_ULONG len)
{
    if ((buffer == NULL) || buffer->is_static || (len == 0) || (pos > buffer->len))
        return FALSE;

    if (!grow_buff(buffer, len))
        return FALSE;

    if (buffer->len > pos) {    
        /* Only if neccessary */
        memmove(buffer->data + pos + len, buffer->data + pos, buffer->len - pos);
    }

    memcpy(buffer->data + pos, data, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';

    return TRUE;
}
