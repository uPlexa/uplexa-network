#ifndef UDAP_BENCODE_H
#define UDAP_BENCODE_H
#include <udap/buffer.h>
#include <udap/common.h>
#include <udap/proto.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * bencode.h
 *
 * helper functions for handling bencoding
 * https://en.wikipedia.org/wiki/Bencode for more information on the format
 * we utilize udap_buffer which provides memory management
 */

#ifdef __cplusplus
extern "C" {
#endif

bool
bencode_write_bytestring(udap_buffer_t* buff, const void* data, size_t sz);

bool
bencode_write_int(udap_buffer_t* buff, int i);

bool
bencode_write_uint16(udap_buffer_t* buff, uint16_t i);

bool
bencode_write_int64(udap_buffer_t* buff, int64_t i);

bool
bencode_write_uint64(udap_buffer_t* buff, uint64_t i);

bool
bencode_write_sizeint(udap_buffer_t* buff, size_t i);

bool
bencode_start_list(udap_buffer_t* buff);

bool
bencode_start_dict(udap_buffer_t* buff);

bool
bencode_end(udap_buffer_t* buff);

bool
bencode_write_version_entry(udap_buffer_t* buff);

bool
bencode_read_integer(struct udap_buffer_t* buffer, uint64_t* result);

bool
bencode_read_string(udap_buffer_t* buffer, udap_buffer_t* result);

struct dict_reader
{
  /// makes passing data into on_key easier
  udap_buffer_t* buffer;
  /// not currently used, maybe used in the future to pass additional
  /// information to on_key
  void* user;
  /**
   * called when we got a key string, return true to continue iteration
   * called with null key on done iterating
   */
  bool (*on_key)(struct dict_reader*, udap_buffer_t*);
};

bool
bencode_read_dict(udap_buffer_t* buff, struct dict_reader* r);

struct list_reader
{
  /// makes passing data into on_item easier
  udap_buffer_t* buffer;
  /// not currently used, maybe used in the future to pass additional
  /// information to on_item
  void* user;
  /**
   * called with true when we got an element, return true to continue iteration
   * called with false on iteration completion
   */
  bool (*on_item)(struct list_reader*, bool);
};

bool
bencode_read_list(udap_buffer_t* buff, struct list_reader* r);

#ifdef __cplusplus
}
#endif
#endif
