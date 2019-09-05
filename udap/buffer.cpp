#include <udap/buffer.h>
#include <stdarg.h>
#include <stdio.h>

extern "C" {

size_t
udap_buffer_size_left(udap_buffer_t buff)
{
  size_t diff = buff.cur - buff.base;
  if(diff > buff.sz)
    return 0;
  else
    return buff.sz - diff;
}

bool
udap_buffer_writef(udap_buffer_t* buff, const char* fmt, ...)
{
  int written;
  ssize_t sz = udap_buffer_size_left(*buff);
  va_list args;
  va_start(args, fmt);
  written = vsnprintf((char*)buff->cur, sz, fmt, args);
  va_end(args);
  if(written <= 0)
    return false;
  if(sz < written)
    return false;
  buff->cur += written;
  return true;
}

bool
udap_buffer_write(udap_buffer_t* buff, const void* data, size_t sz)
{
  size_t left = udap_buffer_size_left(*buff);
  if(left >= sz)
  {
    memcpy(buff->cur, data, sz);
    buff->cur += sz;
    return true;
  }
  return false;
}

size_t
udap_buffer_read_until(udap_buffer_t* buff, char delim, byte_t* result,
                        size_t resultsize)
{
  size_t read = 0;

  while(*buff->cur != delim && resultsize
        && (buff->cur != buff->base + buff->sz))
  {
    *result = *buff->cur;
    buff->cur++;
    result++;
    resultsize--;
    read++;
  }

  if(udap_buffer_size_left(*buff))
    return read;
  else
    return 0;
}

bool
udap_buffer_eq(udap_buffer_t buf, const char* str)
{
  while(*str && buf.cur != (buf.base + buf.sz))
  {
    if(*buf.cur != *str)
      return false;
    buf.cur++;
    str++;
  }
  return *str == 0;
}
}
