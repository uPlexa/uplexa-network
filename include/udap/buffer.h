#ifndef UDAP_BUFFER_H_
#define UDAP_BUFFER_H_
#include <udap/common.h>
#include <udap/mem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * buffer.h
 *
 * generic memory buffer
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t byte_t;

/**
  udap_buffer_t represents a region of memory that is ONLY
  valid in the current scope.

  make sure to follow the rules:

  ALWAYS copy the contents of the buffer if that data is to be used outside the
  current scope.

  ALWAYS pass a udap_buffer_t * if you plan on modifying the data associated
  with the buffer

  ALWAYS pass a udap_buffer_t * if you plan on advancing the stream position

  ALWAYS pass a udap_buffer_t if you are doing a read only operation that does
  not modify the buffer

  ALWAYS pass a udap_buffer_t if you don't want to advance the stream position

  ALWAYS bail out of the current operation if you run out of space in a buffer

  ALWAYS assume the pointers in the buffer are stack allocated memory
  (yes even if you know they are not)

  NEVER malloc() the pointers in the buffer when using it

  NEVER realloc() the pointers in the buffer when using it

  NEVER free() the pointers in the buffer when using it

  NEVER use udap_buffer_t ** (double pointers)

  NEVER use udap_buffer_t ** (double pointers)

  ABSOLUTELY NEVER USE DOUBLE POINTERS.

 */
typedef struct udap_buffer_t
{
  /// starting memory address
  byte_t *base;
  /// memory address of stream position
  byte_t *cur;
  /// max size of buffer
  size_t sz;
} udap_buffer_t;

/// how much room is left in buffer
size_t
udap_buffer_size_left(udap_buffer_t buff);

/// write a chunk of data size "sz"
bool
udap_buffer_write(udap_buffer_t *buff, const void *data, size_t sz);

/// write multiple strings
bool
udap_buffer_writef(udap_buffer_t *buff, const char *fmt, ...);

/// read buffer upto character delimiter
size_t
udap_buffer_read_until(udap_buffer_t *buff, char delim, byte_t *result,
                        size_t resultlen);
/// compare buffers, true if equal else false
bool
udap_buffer_eq(udap_buffer_t buff, const char *data);

#ifdef __cplusplus
}
#endif

#endif
