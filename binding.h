#ifndef BINDING_H
#define BINDING_H

// Helper to safely copy string to buffer and update size
int
safe_copy_string(const char *src, char *dest, size_t *dest_size);

void
log_message(const char *format, ...);

#ifdef __APPLE__

int
store_data_in_apple_keychain(
  const char *data,
  size_t data_len,
  const char *name,         // entry identifier; maps to kSecAttrAccount
  const char *service,      // NULL for default (bundle ID)
  const char *access_control, // "UserPresence", "BiometryAny", "BiometryCurrentSet", NULL for default
  char *error_msg,
  size_t *error_size
);

int
get_data_from_apple_keychain(
  char *out_data,
  size_t *data_size,
  const char *name,         // entry identifier; maps to kSecAttrAccount
  const char *service,      // NULL for default
  const char *title,        // biometric prompt title (kSecUseOperationPrompt); NULL for default
  char *error_msg,
  size_t *error_size
);

int
delete_data_from_apple_keychain(
  const char *name,         // entry identifier; maps to kSecAttrAccount
  const char *service,      // NULL for default
  char *error_msg,
  size_t *error_size
);

#endif

#ifdef __ANDROID__

#include <stdbool.h>

int
store_data_in_android_keystore(
  const char *data,
  size_t data_len,
  const char *name,
  bool require_biometric,
  bool allow_device_credential,
  const char *title,
  const char *subtitle,
  const char *description,
  const char *cancel,
  char *out_error,
  size_t *error_size
);

int
get_data_from_android_keystore(
  char *out_data,
  size_t *data_size,
  const char *name,
  bool require_biometric,
  bool allow_device_credential,
  const char *title,
  const char *subtitle,
  const char *description,
  const char *cancel,
  char *out_error,
  size_t *error_size
);

int
delete_data_from_android_keystore(
  const char *name,
  bool require_biometric,
  bool allow_device_credential,
  const char *title,
  const char *subtitle,
  const char *description,
  const char *cancel,
  bool preserve_key,
  char *out_error,
  size_t *error_size
);

#endif

#endif // BINDING_H
