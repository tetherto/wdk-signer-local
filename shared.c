
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "binding.h"

#ifdef __ANDROID__
#include <android/log.h>
#endif

// Helper to safely copy string to buffer and update size
int
safe_copy_string(const char *src, char *dest, size_t *dest_size) {
  if (dest == NULL || dest_size == NULL || *dest_size == 0) {
    return -1;
  }

  size_t src_len = strlen(src);
  size_t bytes_to_copy = (src_len + 1 > *dest_size) ? (*dest_size - 1) : src_len;

  memcpy(dest, src, bytes_to_copy);
  dest[bytes_to_copy] = '\0';
  *dest_size = bytes_to_copy + 1;

  return (src_len + 1 > *dest_size) ? -1 : 0;
}

void
log_message(const char *format, ...) {
  va_list args;
  va_start(args, format);
#ifdef __ANDROID__
  __android_log_vprint(ANDROID_LOG_INFO, "bare", format, args);
#else
  vprintf(format, args);
  printf("\n");
#endif
  va_end(args);
}
