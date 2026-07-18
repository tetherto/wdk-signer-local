#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "binding.h"

const char *SIGNER_DEFAULT_SERVICE = "bare-signer-service";
const char *SIGNER_DEFAULT_ACCOUNT = "mnemonic";

static int
copy_osstatus_message(OSStatus status, char *dest, size_t *dest_size) {
  if (dest == NULL || dest_size == NULL || *dest_size == 0) {
    return -1;
  }

  CFStringRef message = SecCopyErrorMessageString(status, NULL);
  if (message != NULL) {
    if (CFStringGetCString(message, dest, *dest_size, kCFStringEncodingUTF8)) {
      *dest_size = strlen(dest) + 1;
      CFRelease(message);
      return 0;
    }
    CFRelease(message);
  }

  char fallback[64];
  snprintf(fallback, sizeof(fallback), "keychain error (%d)", (int) status);
  return safe_copy_string(fallback, dest, dest_size);
}

// Map access control string to iOS SecAccessControlCreateFlags
static SecAccessControlCreateFlags
map_access_control_string(const char *access_control_str) {
  if (access_control_str == NULL) {
    // Default: UserPresence
    return kSecAccessControlUserPresence;
  }

  if (strcmp(access_control_str, "UserPresence") == 0) {
    return kSecAccessControlUserPresence;
  } else if (strcmp(access_control_str, "BiometryAny") == 0) {
    return kSecAccessControlBiometryAny;
  } else if (strcmp(access_control_str, "BiometryCurrentSet") == 0) {
    return kSecAccessControlBiometryCurrentSet;
  }

  // Default if unknown
  return kSecAccessControlUserPresence;
}

int
store_data_in_apple_keychain(
  const char *data,
  size_t data_len,
  const char *name,
  const char *service_param,
  const char *access_control_str,
  char *error_msg,
  size_t *error_size
) {
  int rc = -1;

  if (data == NULL || data_len == 0) {
    safe_copy_string("data is NULL or empty", error_msg, error_size);
    return -1;
  }

  // Use defaults if parameters are NULL
  const char *service_name = (service_param != NULL && strlen(service_param) > 0)
    ? service_param
    : SIGNER_DEFAULT_SERVICE;

  const char *account_name = (name != NULL && strlen(name) > 0)
    ? name
    : SIGNER_DEFAULT_ACCOUNT;

  SecAccessControlCreateFlags access_flags = map_access_control_string(access_control_str);

  CFStringRef service = NULL;
  CFStringRef account = NULL;
  CFDataRef value = NULL;
  CFErrorRef access_error = NULL;
  SecAccessControlRef access_control = NULL;
  CFMutableDictionaryRef add_query = NULL;
  OSStatus status;

  service = CFStringCreateWithCString(kCFAllocatorDefault, service_name, kCFStringEncodingUTF8);
  if (service == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for service", error_msg, error_size);
    goto cleanup;
  }

  account = CFStringCreateWithCString(kCFAllocatorDefault, account_name, kCFStringEncodingUTF8);
  if (account == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for account", error_msg, error_size);
    goto cleanup;
  }

  value = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)data, data_len);
  if (value == NULL) {
    safe_copy_string("CFDataCreate failed", error_msg, error_size);
    goto cleanup;
  }

  access_control = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    access_flags,
    &access_error
  );
  if (access_control == NULL) {
    if (access_error == NULL) {
      safe_copy_string("SecAccessControlCreateWithFlags failed", error_msg, error_size);
      goto cleanup;
    }

    if (error_msg != NULL && error_size != NULL) {
      CFStringRef desc = CFErrorCopyDescription(access_error);
      if (desc != NULL) {
        if (!CFStringGetCString(desc, error_msg, *error_size, kCFStringEncodingUTF8)) {
          safe_copy_string("SecAccessControlCreateWithFlags failed", error_msg, error_size);
        } else {
          *error_size = strlen(error_msg) + 1;
        }
        CFRelease(desc);
      } else {
        safe_copy_string("SecAccessControlCreateWithFlags failed", error_msg, error_size);
      }
    }
    goto cleanup;
  }

  add_query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (add_query == NULL) {
    safe_copy_string("CFDictionaryCreateMutable failed", error_msg, error_size);
    goto cleanup;
  }

  CFMutableDictionaryRef del_query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (del_query != NULL) {
    CFDictionarySetValue(del_query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(del_query, kSecAttrService, service);
    CFDictionarySetValue(del_query, kSecAttrAccount, account);
    SecItemDelete(del_query);
    CFRelease(del_query);
  }

  CFDictionarySetValue(add_query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(add_query, kSecAttrService, service);
  CFDictionarySetValue(add_query, kSecAttrAccount, account);
  CFDictionarySetValue(add_query, kSecValueData, value);
  CFDictionarySetValue(add_query, kSecAttrAccessControl, access_control);

  status = SecItemAdd(add_query, NULL);
  if (status != errSecSuccess) {
    copy_osstatus_message(status, error_msg, error_size);
    goto cleanup;
  }

  rc = 0;

cleanup:

  if (add_query != NULL) CFRelease(add_query);
  if (access_control != NULL) CFRelease(access_control);
  if (access_error != NULL) CFRelease(access_error);
  if (value != NULL) CFRelease(value);
  if (account != NULL) CFRelease(account);
  if (service != NULL) CFRelease(service);

  return rc;
}

// Returns 0 on success, -1 on error
// On input: *data_size and *error_size contain buffer sizes
// On output: *data_size contains actual bytes written, *error_size includes null terminator
int
get_data_from_apple_keychain(
  char *out_data,
  size_t *data_size,
  const char *name,
  const char *service_param,
  const char *title_param,
  char *error_msg,
  size_t *error_size
) {
  int rc = -1;

  OSStatus status;
  CFTypeRef result = NULL;
  CFMutableDictionaryRef read_query = NULL;
  CFStringRef service = NULL;
  CFStringRef account = NULL;
  CFStringRef title = NULL;

  if (out_data == NULL || data_size == NULL) {
    safe_copy_string("Invalid arguments", error_msg, error_size);
    goto cleanup;
  }

  // Use defaults if parameters are NULL
  const char *service_name = (service_param != NULL && strlen(service_param) > 0)
    ? service_param
    : SIGNER_DEFAULT_SERVICE;

  const char *account_name = (name != NULL && strlen(name) > 0)
    ? name
    : SIGNER_DEFAULT_ACCOUNT;

  service = CFStringCreateWithCString(kCFAllocatorDefault, service_name, kCFStringEncodingUTF8);
  if (service == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for service", error_msg, error_size);
    goto cleanup;
  }

  account = CFStringCreateWithCString(kCFAllocatorDefault, account_name, kCFStringEncodingUTF8);
  if (account == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for account", error_msg, error_size);
    goto cleanup;
  }

  read_query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (read_query == NULL) {
    safe_copy_string("CFDictionaryCreateMutable failed (read)", error_msg, error_size);
    goto cleanup;
  }

  CFDictionarySetValue(read_query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(read_query, kSecAttrService, service);
  CFDictionarySetValue(read_query, kSecAttrAccount, account);
  CFDictionarySetValue(read_query, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(read_query, kSecMatchLimit, kSecMatchLimitOne);

  if (title_param != NULL && strlen(title_param) > 0) {
    title = CFStringCreateWithCString(kCFAllocatorDefault, title_param, kCFStringEncodingUTF8);
    if (title != NULL) {
      CFDictionarySetValue(read_query, kSecUseOperationPrompt, title);
    }
  }

  status = SecItemCopyMatching(read_query, &result);
  if (status != errSecSuccess) {
    copy_osstatus_message(status, error_msg, error_size);
    goto cleanup;
  }

  if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
    safe_copy_string("SecItemCopyMatching returned unexpected result", error_msg, error_size);
    goto cleanup;
  }

  CFDataRef data = (CFDataRef) result;
  CFIndex len = CFDataGetLength(data);
  const UInt8 *bytes = CFDataGetBytePtr(data);

  if ((size_t) len > *data_size) {
    safe_copy_string("Output buffer too small", error_msg, error_size);
    goto cleanup;
  }

  memcpy(out_data, bytes, len);
  *data_size = len;
  // printf("[C] keychain item read (%ld bytes): %.*s\n", (long) len, (int) len, (const char *) bytes);

  rc = 0;

cleanup:
  if (result != NULL) CFRelease(result);
  if (read_query != NULL) CFRelease(read_query);
  if (title != NULL) CFRelease(title);
  if (account != NULL) CFRelease(account);
  if (service != NULL) CFRelease(service);
  return rc;
}

// Returns 0 on success, -1 on error
int
delete_data_from_apple_keychain(
  const char *name,
  const char *service_param,
  char *error_msg,
  size_t *error_size
) {
  int rc = -1;

  OSStatus status;
  CFMutableDictionaryRef delete_query = NULL;
  CFStringRef service = NULL;
  CFStringRef account = NULL;

  // Use defaults if parameters are NULL
  const char *service_name = (service_param != NULL && strlen(service_param) > 0)
    ? service_param
    : SIGNER_DEFAULT_SERVICE;

  const char *account_name = (name != NULL && strlen(name) > 0)
    ? name
    : SIGNER_DEFAULT_ACCOUNT;

  service = CFStringCreateWithCString(kCFAllocatorDefault, service_name, kCFStringEncodingUTF8);
  if (service == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for service", error_msg, error_size);
    goto cleanup;
  }

  account = CFStringCreateWithCString(kCFAllocatorDefault, account_name, kCFStringEncodingUTF8);
  if (account == NULL) {
    safe_copy_string("CFStringCreateWithCString failed for account", error_msg, error_size);
    goto cleanup;
  }

  delete_query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (delete_query == NULL) {
    safe_copy_string("CFDictionaryCreateMutable failed (delete)", error_msg, error_size);
    goto cleanup;
  }

  CFDictionarySetValue(delete_query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(delete_query, kSecAttrService, service);
  CFDictionarySetValue(delete_query, kSecAttrAccount, account);

  status = SecItemDelete(delete_query);
  if (status != errSecSuccess) {
    // Treat "item not found" as a success
    if (status == errSecItemNotFound) { // The error code for item not found
      rc = 0;
      goto cleanup;
    }
    // For all other errors, report and fail
    copy_osstatus_message(status, error_msg, error_size);
    goto cleanup;
  }

  rc = 0;

cleanup:
  if (delete_query != NULL) CFRelease(delete_query);
  if (account != NULL) CFRelease(account);
  if (service != NULL) CFRelease(service);
  return rc;
}

#endif
