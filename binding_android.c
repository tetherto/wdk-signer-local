#if defined(__ANDROID__)

#include <jni.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "binding.h"

JavaVM *javaVM = NULL;

static void
ensure_javavm_initialized(void) {
  if (javaVM != NULL) {
    return;
  }

  void *handle = dlopen("libbare-signer-android.so", RTLD_LAZY);
  if (handle == NULL) {
    fprintf(stderr, "[bare] Failed to dlopen libbare-signer-android.so: %s\n", dlerror());
    return;
  }

  typedef JavaVM* (*get_jvm_func)(void);
  get_jvm_func get_jvm = (get_jvm_func)dlsym(handle, "get_global_jvm");

  if (get_jvm == NULL) {
    fprintf(stderr, "[bare] Failed to find get_global_jvm: %s\n", dlerror());
    dlclose(handle);
    return;
  }

  javaVM = get_jvm();
  printf("[bare] JavaVM initialized: %p\n", javaVM);

  // Don't dlclose - keep the handle open while we use the JavaVM
}

#define HELPER_CLS "com.tetherto.bare.signer.SecureDataHelper"

static jclass
find_app_class(JNIEnv *env, const char *class_name) {
  jclass activityThreadClass = (*env)->FindClass(env, "android/app/ActivityThread");
  if (!activityThreadClass) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jmethodID currentActivityThreadMethod = (*env)->GetStaticMethodID(
    env, activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
  if (!currentActivityThreadMethod) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jobject activityThread = (*env)->CallStaticObjectMethod(env, activityThreadClass, currentActivityThreadMethod);
  if (!activityThread) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jmethodID getApplicationMethod = (*env)->GetMethodID(
    env, activityThreadClass, "getApplication", "()Landroid/app/Application;");
  if (!getApplicationMethod) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jobject application = (*env)->CallObjectMethod(env, activityThread, getApplicationMethod);
  if (!application) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jclass contextClass = (*env)->FindClass(env, "android/content/Context");
  jmethodID getClassLoaderMethod = (*env)->GetMethodID(
    env, contextClass, "getClassLoader", "()Ljava/lang/ClassLoader;");

  jobject classLoader = (*env)->CallObjectMethod(env, application, getClassLoaderMethod);
  if (!classLoader) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  jclass classLoaderClass = (*env)->FindClass(env, "java/lang/ClassLoader");
  jmethodID loadClassMethod = (*env)->GetMethodID(
    env, classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

  jstring classNameStr = (*env)->NewStringUTF(env, class_name);
  jclass targetClass = (jclass)(*env)->CallObjectMethod(env, classLoader, loadClassMethod, classNameStr);

  (*env)->DeleteLocalRef(env, classNameStr);

  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return NULL;
  }

  return targetClass;
}

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
) {
  if (data == NULL || data_len == 0) {
    if (out_error && error_size) safe_copy_string("Data is null or empty", out_error, error_size);
    return -1;
  }

  ensure_javavm_initialized();
  if (javaVM == NULL) {
    if (out_error && error_size) safe_copy_string("JavaVM not initialized", out_error, error_size);
    return -1;
  }

  JNIEnv *env = NULL;
  jint attach_rc = (*javaVM)->AttachCurrentThread(javaVM, &env, NULL);
  if (attach_rc != JNI_OK || env == NULL) {
    if (out_error && error_size) safe_copy_string("Failed to attach thread", out_error, error_size);
    return -1;
  }

  int rc = -1;
  jclass helperClass = NULL;
  jbyteArray jData = NULL;
  jstring jName = NULL, jTitle = NULL, jSubtitle = NULL, jDescription = NULL, jCancel = NULL;

  helperClass = find_app_class(env, HELPER_CLS);
  if (!helperClass) {
    if (out_error && error_size) safe_copy_string("Failed to find SecureDataHelper class", out_error, error_size);
    log_message("Failed to find SecureDataHelper class");
    goto done;
  }

  jmethodID saveMethod = (*env)->GetStaticMethodID(
    env, helperClass, "saveEncryptedDataNative", "([BLjava/lang/String;JZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"
  );
  if (!saveMethod) {
    if (out_error && error_size) safe_copy_string("Failed to find saveEncryptedDataNative method", out_error, error_size);
    if ((*env)->ExceptionCheck(env)) {
      (*env)->ExceptionDescribe(env);
      (*env)->ExceptionClear(env);
    }
    goto done;
  }

  jData = (*env)->NewByteArray(env, (jsize) data_len);
  if (!jData) {
    if (out_error && error_size) safe_copy_string("OOM: NewByteArray(data) failed", out_error, error_size);
    goto done;
  }
  (*env)->SetByteArrayRegion(env, jData, 0, (jsize) data_len, (const jbyte *) data);

  jName = (*env)->NewStringUTF(env, (name && *name) ? name : "mnemonic");
  if (!jName) {
    if (out_error && error_size) safe_copy_string("OOM: NewStringUTF(name) failed", out_error, error_size);
    goto done;
  }

  if (title) jTitle = (*env)->NewStringUTF(env, title);
  if (subtitle) jSubtitle = (*env)->NewStringUTF(env, subtitle);
  if (description) jDescription = (*env)->NewStringUTF(env, description);
  if (cancel) jCancel = (*env)->NewStringUTF(env, cancel);

  (*env)->CallStaticVoidMethod(env, helperClass, saveMethod, jData, jName, 60L,
    (jboolean) require_biometric, (jboolean) allow_device_credential,
    jTitle, jSubtitle, jDescription, jCancel);

  if ((*env)->ExceptionCheck(env)) {
    jthrowable exception = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);

    jclass throwableClass = (*env)->FindClass(env, "java/lang/Throwable");
    if (throwableClass) {
      jmethodID getMessage = (*env)->GetMethodID(env, throwableClass, "getMessage", "()Ljava/lang/String;");
      if (getMessage) {
        jstring msgStr = (jstring) (*env)->CallObjectMethod(env, exception, getMessage);
        if (msgStr) {
          const char *msg = (*env)->GetStringUTFChars(env, msgStr, NULL);
          if (out_error && error_size) safe_copy_string(msg ? msg : "Unknown exception", out_error, error_size);
          log_message("Exception: %s", msg ? msg : "(null)");
          if (msg) (*env)->ReleaseStringUTFChars(env, msgStr, msg);
          (*env)->DeleteLocalRef(env, msgStr);
        } else {
          if (out_error && error_size) safe_copy_string("Unknown exception occurred", out_error, error_size);
        }
      }
      (*env)->DeleteLocalRef(env, throwableClass);
    } else {
      if (out_error && error_size) safe_copy_string("Exception thrown (no Throwable class)", out_error, error_size);
    }

    if (exception) (*env)->DeleteLocalRef(env, exception);
    goto done;
  }
  log_message("saveEncryptedDataNative completed successfully");
  rc = 0;

done:
  if (jData) (*env)->DeleteLocalRef(env, jData);
  if (jName) (*env)->DeleteLocalRef(env, jName);
  if (jTitle) (*env)->DeleteLocalRef(env, jTitle);
  if (jSubtitle) (*env)->DeleteLocalRef(env, jSubtitle);
  if (jDescription) (*env)->DeleteLocalRef(env, jDescription);
  if (jCancel) (*env)->DeleteLocalRef(env, jCancel);
  if (helperClass) (*env)->DeleteLocalRef(env, helperClass);

  (*javaVM)->DetachCurrentThread(javaVM);
  return rc;
}

int
delete_data_from_android_keystore(
  const char *name, bool require_biometric, bool allow_device_credential, const char *title, const char *subtitle, const char *description, const char *cancel, bool preserve_key, char *out_error, size_t *error_size
) {
  ensure_javavm_initialized();
  if (javaVM == NULL) {
    if (out_error && error_size) safe_copy_string("JavaVM not initialized", out_error, error_size);
    return -1;
  }

  JNIEnv *env = NULL;
  if ((*javaVM)->AttachCurrentThread(javaVM, &env, NULL) != JNI_OK || env == NULL) {
    if (out_error && error_size) safe_copy_string("Failed to attach thread", out_error, error_size);
    return -1;
  }

  int rc = -1;

  jclass helperClass = find_app_class(env, HELPER_CLS);
  if (!helperClass) {
    if (out_error && error_size) safe_copy_string("SecureDataHelper class not found", out_error, error_size);
    log_message("[delete] helperClass NULL");

    goto done;
  }

  jmethodID mid = (*env)->GetStaticMethodID(
    env, helperClass, "deleteEncryptedTextNative", "(Ljava/lang/String;JZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V"
  );
  if (!mid) {
    if (out_error && error_size) safe_copy_string("deleteEncryptedTextNative not found", out_error, error_size);
    (*env)->ExceptionClear(env);
    log_message("[delete] methodID NULL");

    goto done;
  }

  jstring jName = (*env)->NewStringUTF(env, (name && *name) ? name : "mnemonic");
  if (!jName) {
    if (out_error && error_size) safe_copy_string("OOM: NewStringUTF(name) failed", out_error, error_size);
    goto done;
  }
  jstring jTitle = title ? (*env)->NewStringUTF(env, title) : NULL;
  jstring jSubtitle = subtitle ? (*env)->NewStringUTF(env, subtitle) : NULL;
  jstring jDescription = description ? (*env)->NewStringUTF(env, description) : NULL;
  jstring jCancel = cancel ? (*env)->NewStringUTF(env, cancel) : NULL;

  (*env)->CallStaticVoidMethod(
    env, helperClass, mid, jName, (jlong) 60L,
    (jboolean) require_biometric, (jboolean) allow_device_credential,
    jTitle, jSubtitle, jDescription, jCancel, (jboolean) preserve_key
  );

  if ((*env)->ExceptionCheck(env)) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);

    jclass thr = (*env)->FindClass(env, "java/lang/Throwable");
    if (thr) {
      jmethodID getMsg = (*env)->GetMethodID(env, thr, "getMessage", "()Ljava/lang/String;");
      jstring msgStr = (jstring) (*env)->CallObjectMethod(env, ex, getMsg);
      const char *msg = msgStr ? (*env)->GetStringUTFChars(env, msgStr, NULL) : "Unknown exception";
      if (out_error && error_size) safe_copy_string(msg, out_error, error_size);
      log_message("[delete] exception: %s", msg);

      if (msgStr) {
        (*env)->ReleaseStringUTFChars(env, msgStr, msg);
        (*env)->DeleteLocalRef(env, msgStr);
      }
      (*env)->DeleteLocalRef(env, thr);
    } else {
      if (out_error && error_size) safe_copy_string("Unknown exception", out_error, error_size);
    }
    if (ex) (*env)->DeleteLocalRef(env, ex);
    goto release_and_done;
  }
  log_message("[delete] success");

  rc = 0;

release_and_done:
  if (jCancel) (*env)->DeleteLocalRef(env, jCancel);
  if (jDescription) (*env)->DeleteLocalRef(env, jDescription);
  if (jSubtitle) (*env)->DeleteLocalRef(env, jSubtitle);
  if (jTitle) (*env)->DeleteLocalRef(env, jTitle);
  if (jName) (*env)->DeleteLocalRef(env, jName);

done:
  if (helperClass) (*env)->DeleteLocalRef(env, helperClass);
  (*javaVM)->DetachCurrentThread(javaVM);
  return rc;
}

int
get_data_from_android_keystore(
  char *out_data, size_t *data_size, const char *name, bool require_biometric, bool allow_device_credential, const char *title, const char *subtitle, const char *description, const char *cancel, char *out_error, size_t *error_size
) {
  ensure_javavm_initialized();
  if (javaVM == NULL) {
    if (out_error && error_size) safe_copy_string("JavaVM not initialized", out_error, error_size);
    return -1;
  }

  JNIEnv *env = NULL;
  if ((*javaVM)->AttachCurrentThread(javaVM, &env, NULL) != JNI_OK || env == NULL) {
    if (out_error && error_size) safe_copy_string("Failed to attach thread", out_error, error_size);
    return -1;
  }

  int rc = -1;

  jclass helperClass = find_app_class(env, HELPER_CLS);
  if (!helperClass) {
    if (out_error && error_size) safe_copy_string("SecureDataHelper class not found", out_error, error_size);
    log_message("[read] helperClass NULL");

    goto done;
  }

  jmethodID mid = (*env)->GetStaticMethodID(
    env, helperClass, "getDecryptedDataNative", "(Ljava/lang/String;JZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B"
  );
  if (!mid) {
    if (out_error && error_size) safe_copy_string("getDecryptedDataNative not found", out_error, error_size);
    (*env)->ExceptionClear(env);
    log_message("[read] methodID NULL");

    goto done;
  }

  jstring jName = (*env)->NewStringUTF(env, (name && *name) ? name : "mnemonic");
  if (!jName) {
    if (out_error && error_size) safe_copy_string("OOM: NewStringUTF(name) failed", out_error, error_size);
    goto done;
  }
  jstring jTitle = title ? (*env)->NewStringUTF(env, title) : NULL;
  jstring jSubtitle = subtitle ? (*env)->NewStringUTF(env, subtitle) : NULL;
  jstring jDescription = description ? (*env)->NewStringUTF(env, description) : NULL;
  jstring jCancel = cancel ? (*env)->NewStringUTF(env, cancel) : NULL;

  jbyteArray jResult = (jbyteArray) (*env)->CallStaticObjectMethod(
    env, helperClass, mid, jName, (jlong) 60L,
    (jboolean) require_biometric, (jboolean) allow_device_credential,
    jTitle, jSubtitle, jDescription, jCancel
  );

  if ((*env)->ExceptionCheck(env)) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);

    jclass thr = (*env)->FindClass(env, "java/lang/Throwable");
    if (thr) {
      jmethodID getMsg = (*env)->GetMethodID(env, thr, "getMessage", "()Ljava/lang/String;");
      jstring msgStr = (jstring) (*env)->CallObjectMethod(env, ex, getMsg);
      const char *msg = msgStr ? (*env)->GetStringUTFChars(env, msgStr, NULL) : "Unknown exception";
      if (out_error && error_size) safe_copy_string(msg, out_error, error_size);
      log_message("[read] exception: %s", msg);

      if (msgStr) {
        (*env)->ReleaseStringUTFChars(env, msgStr, msg);
        (*env)->DeleteLocalRef(env, msgStr);
      }
      (*env)->DeleteLocalRef(env, thr);
    } else {
      if (out_error && error_size) safe_copy_string("Unknown exception", out_error, error_size);
    }
    if (ex) (*env)->DeleteLocalRef(env, ex);
    goto release_and_done;
  }

  if (!jResult) {
    if (out_error && error_size) safe_copy_string("Result is null", out_error, error_size);
    log_message("[read] result is NULL");

    goto release_and_done;
  }

  jsize result_len = (*env)->GetArrayLength(env, jResult);
  if (out_data && data_size) {
    if ((size_t) result_len <= *data_size) {
      jbyte *bytes = (*env)->GetByteArrayElements(env, jResult, NULL);
      if (!bytes) {
        if (out_error && error_size) safe_copy_string("Failed to read result bytes", out_error, error_size);
        goto release_and_done;
      }
      memcpy(out_data, bytes, result_len);
      (*env)->ReleaseByteArrayElements(env, jResult, bytes, JNI_ABORT);
      *data_size = (size_t) result_len;
      log_message("[read] success, %zu bytes", *data_size);
      rc = 0;
    } else {
      if (out_error && error_size) safe_copy_string("data buffer too small", out_error, error_size);
    }
  }

  (*env)->DeleteLocalRef(env, jResult);

release_and_done:
  if (jCancel) (*env)->DeleteLocalRef(env, jCancel);
  if (jDescription) (*env)->DeleteLocalRef(env, jDescription);
  if (jSubtitle) (*env)->DeleteLocalRef(env, jSubtitle);
  if (jTitle) (*env)->DeleteLocalRef(env, jTitle);
  if (jName) (*env)->DeleteLocalRef(env, jName);

done:
  if (helperClass) (*env)->DeleteLocalRef(env, helperClass);
  (*javaVM)->DetachCurrentThread(javaVM);
  return rc;
}

#endif
