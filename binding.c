#include <assert.h>
#include <bare.h>
#include <js.h>
#include <utf.h>
#include <string.h>
#include <stdio.h>
#include "binding.h"

typedef struct {
  char *name;    // Entry identifier (maps to Keychain account on Apple, SharedPreferences key suffix on Android)
  char *service; // Darwin only
  char *access_control; // valid values: UserPresence(default, Darwin), BiometryAny (Darwin), BiometryCurrentSet (Darwin)
  bool require_biometric;       // Android
  bool allow_device_credential; // Android
  char *title;                  // Android & Darwin biometric prompt title (kSecUseOperationPrompt)
  char *subtitle;               // Android
  char *description;            // Android
  char *cancel;                 // Android
} bare_signer_biometric_opts_t;

int
get_data_from_keystore(char *out_data, size_t *data_size, char *out_error, size_t *error_size, bare_signer_biometric_opts_t* opts);

static js_value_t*
mk_error(js_env_t *env, const char *code_str, const char *msg_str);

enum { bare_signer_DATA_LEN = 256 };
enum { bare_signer_MAX_ERROR_LEN = 4096 };

void
bare_signer_biometric_opts_free(bare_signer_biometric_opts_t* opts) {
  if (opts == NULL) return;
  if (opts->name != NULL) free(opts->name);
  if (opts->service != NULL) free(opts->service);
  if (opts->access_control != NULL) free(opts->access_control);
  if (opts->title != NULL) free(opts->title);
  if (opts->subtitle != NULL) free(opts->subtitle);
  if (opts->description != NULL) free(opts->description);
  if (opts->cancel != NULL) free(opts->cancel);
  free(opts);
}

typedef struct {
  char *message;
  size_t message_len;
} bare_signer_error_t;

// unpack the null-terminated c-string from the JS string.
// The returned structure contains either the string or an error message.
int
bare_signer_js_unpack_str(js_env_t *env, js_value_t *src, char **dst, bare_signer_error_t *error) {
  bool ok;
  int e;

  if (dst == NULL) {
    if (error != NULL && error->message_len > 0) {
      snprintf(error->message, error->message_len, "dst is NULL");
    }
    return -1;
  }

  *dst = NULL;

  e = js_is_string(env, src, &ok);
  assert(e == 0);
  if (!ok) {
    if (error != NULL && error->message_len > 0) {
      snprintf(error->message, error->message_len, "JS value is not a string");
    }
    return -1;
  }

  size_t actual_ln;
  e = js_get_value_string_utf8(env, src, NULL, 0, &actual_ln);
  assert(e == 0);
  *dst = malloc(actual_ln + 1);
  assert(*dst != NULL);
  e = js_get_value_string_utf8(env, src, (utf8_t *) *dst, actual_ln + 1, NULL);
  assert(e == 0);
  (*dst)[actual_ln] = '\0';

  return 0;
}

bare_signer_biometric_opts_t*
bare_signer_biometric_opts_parse(js_env_t* env, js_value_t *opts_js, bare_signer_error_t *error) {
  bare_signer_biometric_opts_t *opts = calloc(1, sizeof(bare_signer_biometric_opts_t));
  if (opts == NULL) return NULL;

  bool success = false;

  bool ok;
  int e = js_has_named_property(env, opts_js, "service", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *service_js;
    e = js_get_named_property(env, opts_js, "service", &service_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, service_js, &opts->service, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "name", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *name_js;
    e = js_get_named_property(env, opts_js, "name", &name_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, name_js, &opts->name, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "access_control", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *access_control_js;
    e = js_get_named_property(env, opts_js, "access_control", &access_control_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, access_control_js, &opts->access_control, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "requireBiometric", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *require_biometric_js;
    e = js_get_named_property(env, opts_js, "requireBiometric", &require_biometric_js);
    assert(e == 0);
    bool is_bool = false;
    e = js_is_boolean(env, require_biometric_js, &is_bool);
    assert(e == 0);
    if (!is_bool) {
      if (error && error->message && error->message_len) {
        snprintf(error->message, error->message_len, "requireBiometric must be a boolean");
      }
      goto cleanup;
    }
    bool require_biometric = false;
    e = js_get_value_bool(env, require_biometric_js, &require_biometric);
    assert(e == 0);
    opts->require_biometric = require_biometric;
  }

  e = js_has_named_property(env, opts_js, "allowDeviceCredential", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *allow_device_credential_js;
    e = js_get_named_property(env, opts_js, "allowDeviceCredential", &allow_device_credential_js);
    assert(e == 0);
    bool is_bool = false;
    e = js_is_boolean(env, allow_device_credential_js, &is_bool);
    assert(e == 0);
    if (!is_bool) {
      if (error && error->message && error->message_len) {
        snprintf(error->message, error->message_len, "allowDeviceCredential must be a boolean");
      }
      goto cleanup;
    }
    bool allow_device_credential = false;
    e = js_get_value_bool(env, allow_device_credential_js, &allow_device_credential);
    assert(e == 0);
    opts->allow_device_credential = allow_device_credential;
  }

  e = js_has_named_property(env, opts_js, "title", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *title_js;
    e = js_get_named_property(env, opts_js, "title", &title_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, title_js, &opts->title, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "subtitle", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *subtitle_js;
    e = js_get_named_property(env, opts_js, "subtitle", &subtitle_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, subtitle_js, &opts->subtitle, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "description", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *description_js;
    e = js_get_named_property(env, opts_js, "description", &description_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, description_js, &opts->description, error) != 0) {
      goto cleanup;
    }
  }

  e = js_has_named_property(env, opts_js, "cancel", &ok);
  assert(e == 0);
  if (ok) {
    js_value_t *cancel_js;
    e = js_get_named_property(env, opts_js, "cancel", &cancel_js);
    assert(e == 0);
    if (bare_signer_js_unpack_str(env, cancel_js, &opts->cancel, error) != 0) {
      goto cleanup;
    }
  }

  success = true;

cleanup:
  if (success) {
    return opts;
  }

  bare_signer_biometric_opts_free(opts);
  return NULL;
}

static js_value_t*
mk_error(js_env_t *env, const char *code_str, const char *msg_str) {
    js_value_t *code;
    int err = js_create_string_latin1(env, (const latin1_t *) (code_str ? code_str : "ERROR_UNKNOWN"), -1, &code);
    if (err != 0) return NULL;

    js_value_t *error_msg;
    err = js_create_string_latin1(env, (const latin1_t *) (msg_str ? msg_str : "unknown error"), -1, &error_msg);
    if (err != 0) return NULL;

    js_value_t *result;
    err = js_create_error(env, code, error_msg, &result);
    if (err != 0) return NULL;

    return result;
}

int
get_data_from_keystore(char *out_data, size_t *data_size, char *out_error, size_t *error_size, bare_signer_biometric_opts_t* opts) {
#ifdef __ANDROID__
  bool require_biometric = opts && opts->require_biometric;
  bool allow_device_credential = opts && opts->allow_device_credential;
  const char *title = opts ? opts->title : NULL;
  const char *subtitle = opts ? opts->subtitle : NULL;
  const char *description = opts ? opts->description : NULL;
  const char *cancel = opts ? opts->cancel : NULL;

  const char *name = opts ? opts->name : NULL;

  return get_data_from_android_keystore(
    out_data, data_size, name, require_biometric, allow_device_credential, title, subtitle, description, cancel, out_error, error_size
  );
#elif defined(__APPLE__)
  const char *name = (opts && opts->name) ? opts->name : NULL;
  const char *service = (opts && opts->service) ? opts->service : NULL;
  const char *title = (opts && opts->title) ? opts->title : NULL;
  return get_data_from_apple_keychain(out_data, data_size, name, service, title, out_error, error_size);
#else
  if (out_error != NULL && error_size != NULL) {
    const char *msg = "retrieving data from the keystore is not implemented on this platform";
    safe_copy_string(msg, out_error, error_size);
  } else if (error_size != NULL) {
    *error_size = 0;
  }
  if (data_size != NULL) *data_size = 0;
  return -1;
#endif
}

int
store_data_in_keystore(const char *data, size_t data_len, char *out_error, size_t *error_size, bare_signer_biometric_opts_t* opts) {
#ifdef __ANDROID__
  bool require_biometric = opts && opts->require_biometric;
  bool allow_device_credential = opts && opts->allow_device_credential;
  const char *title = opts ? opts->title : NULL;
  const char *subtitle = opts ? opts->subtitle : NULL;
  const char *description = opts ? opts->description : NULL;
  const char *cancel = opts ? opts->cancel : NULL;

  const char *name = opts ? opts->name : NULL;

  return store_data_in_android_keystore(
    data, data_len, name, require_biometric, allow_device_credential, title, subtitle, description, cancel, out_error, error_size
  );
#elif defined(__APPLE__)
  const char *name = opts ? opts->name : NULL;
  const char *service = (opts && opts->service) ? opts->service : NULL;
  const char *access_control = (opts && opts->access_control) ? opts->access_control : NULL;
  return store_data_in_apple_keychain(data, data_len, name, service, access_control, out_error, error_size);
#else
  if (out_error != NULL && error_size != NULL) {
    const char *msg = "storing data in the keystore is not implemented on this platform";
    safe_copy_string(msg, out_error, error_size);
  } else if (error_size != NULL) {
    *error_size = 0;
  }
  return -1;
#endif
}

int
delete_data_from_keystore(char *out_error, size_t *error_size, bare_signer_biometric_opts_t* opts) {
#ifdef __ANDROID__
  bool require_biometric = opts && opts->require_biometric;
  bool allow_device_credential = opts && opts->allow_device_credential;
  const char *title = opts ? opts->title : NULL;
  const char *subtitle = opts ? opts->subtitle : NULL;
  const char *description = opts ? opts->description : NULL;
  const char *cancel = opts ? opts->cancel : NULL;

  bool preserve_key = true;

  const char *name = opts ? opts->name : NULL;

  return delete_data_from_android_keystore(
    name, require_biometric, allow_device_credential, title, subtitle, description, cancel, preserve_key, out_error, error_size
  );
#elif defined(__APPLE__)
  const char *name = opts ? opts->name : NULL;
  const char *service = (opts && opts->service) ? opts->service : NULL;
  return delete_data_from_apple_keychain(name, service, out_error, error_size);
#else
  if (out_error != NULL && error_size != NULL) {
    const char *msg = "deleting data from the keystore is not implemented on this platform";
    safe_copy_string(msg, out_error, error_size);
  } else if (error_size != NULL) {
    *error_size = 0;
  }
  return -1;
#endif
}

typedef struct {
  uv_work_t work;
  js_env_t *env;
  js_deferred_t *deferred;
  bare_signer_biometric_opts_t* opts;
  char* error_msg;
} bare_signer_delete_data_work_context_t;

static void
bare_signer_delete_data_async_do(uv_work_t *req) {
  bare_signer_delete_data_work_context_t *ctx = (bare_signer_delete_data_work_context_t *) req->data;

  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  size_t error_len = bare_signer_MAX_ERROR_LEN;
  int err = delete_data_from_keystore(error_msg, &error_len, ctx->opts);
  if (err != 0) {
    ctx->error_msg = strdup(error_msg);
    return;
  }
}

static void
bare_signer_delete_data_async_done(uv_work_t *req, int status) {
  int e;
  bare_signer_delete_data_work_context_t *ctx = (bare_signer_delete_data_work_context_t *) req->data;

  js_handle_scope_t *scope;
  e = js_open_handle_scope(ctx->env, &scope);
  assert(e == 0);

  if (status != 0) {
    js_value_t* error = mk_error(ctx->env, "DELETE_DATA_ERROR", "uv work request failed");
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  if (ctx->error_msg != NULL) {
    js_value_t* error = mk_error(ctx->env, "DELETE_DATA_ERROR", ctx->error_msg);
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  js_value_t *result;
  e = js_get_undefined(ctx->env, &result);
  assert(e == 0);
  e = js_resolve_deferred(ctx->env, ctx->deferred, result);
  assert(e == 0);

cleanup:

  e = js_close_handle_scope(ctx->env, scope);
  assert(e == 0);

  if (ctx->error_msg != NULL) {
    free(ctx->error_msg);
  }
  if (ctx->opts != NULL) {
    bare_signer_biometric_opts_free(ctx->opts);
  }
  free(ctx);
}

static js_value_t *
bare_signer_delete_data(js_env_t *env, js_callback_info_t *info) {
  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  char error_msg2[bare_signer_MAX_ERROR_LEN] = {0};
  bare_signer_error_t error = {
    .message = error_msg,
    .message_len = sizeof(error_msg)
  };
  bare_signer_biometric_opts_t* opts = NULL;

  int e;

  js_deferred_t *deferred;
  js_value_t *promise;
  e = js_create_promise(env, &deferred, &promise);
  assert(e == 0);

  enum { args_num = 1 };
  size_t argc = args_num;
  js_value_t *argv[args_num];
  e = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(e == 0);
  if (argc != args_num) {
    js_value_t *js_err = mk_error(env, "DELETE_DATA_ERROR", "invalid number of arguments, expected 1");
    js_reject_deferred(env, deferred, js_err);
    goto cleanup;
  }

  bool ok_opts;
  e = js_is_object(env, argv[0], &ok_opts);
  assert(e == 0);
  if (!ok_opts) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 1 must be an object");
    js_reject_deferred(env, deferred, mk_error(env, "DELETE_DATA_ERROR", error_msg2));
    goto cleanup;
  }
  opts = bare_signer_biometric_opts_parse(env, argv[0], &error);
  if (opts == NULL) {
    snprintf(error_msg2, sizeof(error_msg2), "opts: %s", error.message);
    js_reject_deferred(env, deferred, mk_error(env, "DELETE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  bare_signer_delete_data_work_context_t *ctx = calloc(1, sizeof(bare_signer_delete_data_work_context_t));
  assert(ctx != NULL);
  ctx->work.data = ctx;
  ctx->env = env;
  ctx->deferred = deferred;
  ctx->opts = opts;
  opts = NULL; // would be freed in ctx cleanup

  uv_loop_t *loop;
  e = js_get_env_loop(env, &loop);
  assert(e == 0);

  e = uv_queue_work(loop, &ctx->work, bare_signer_delete_data_async_do, bare_signer_delete_data_async_done);
  assert(e == 0);

cleanup:
  if (opts != NULL) {
    bare_signer_biometric_opts_free(opts);
  }
  return promise;
}

typedef struct {
  uv_work_t work;
  js_env_t *env;
  js_deferred_t *deferred;
  bare_signer_biometric_opts_t* opts;
  char data[bare_signer_DATA_LEN];
  size_t data_len;
  char* error_msg;
} bare_signer_read_data_work_context_t;

static void
bare_signer_read_data_async_do(uv_work_t *req) {
  bare_signer_read_data_work_context_t *ctx = (bare_signer_read_data_work_context_t *) req->data;

  size_t data_len = bare_signer_DATA_LEN;
  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  size_t error_len = bare_signer_MAX_ERROR_LEN;
  int err = get_data_from_keystore(ctx->data, &data_len, error_msg, &error_len, ctx->opts);
  if (err != 0) {
    ctx->error_msg = strdup(error_msg);
    return;
  }
  ctx->data_len = data_len;
}

static void
bare_signer_read_data_async_done(uv_work_t *req, int status) {
  int e;
  bare_signer_read_data_work_context_t *ctx = (bare_signer_read_data_work_context_t *) req->data;

  js_handle_scope_t *scope;
  e = js_open_handle_scope(ctx->env, &scope);
  assert(e == 0);

  if (status != 0) {
    js_value_t* error = mk_error(ctx->env, "READ_DATA_ERROR", "uv work request failed");
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  if (ctx->error_msg != NULL) {
    js_value_t* error = mk_error(ctx->env, "READ_DATA_ERROR", ctx->error_msg);
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  void *buffer_data;
  js_value_t *result;
  e = js_create_arraybuffer(ctx->env, ctx->data_len, &buffer_data, &result);
  assert(e == 0);
  memcpy(buffer_data, ctx->data, ctx->data_len);
  e = js_resolve_deferred(ctx->env, ctx->deferred, result);
  assert(e == 0);

cleanup:

  e = js_close_handle_scope(ctx->env, scope);
  assert(e == 0);

  memset(ctx->data, 0, sizeof(ctx->data));

  if (ctx->error_msg != NULL) {
    free(ctx->error_msg);
  }
  if (ctx->opts != NULL) {
    bare_signer_biometric_opts_free(ctx->opts);
  }
  free(ctx);
}

static js_value_t *
bare_signer_read_data(js_env_t *env, js_callback_info_t *info) {
  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  char error_msg2[bare_signer_MAX_ERROR_LEN] = {0};
  bare_signer_error_t error = {
    .message = error_msg,
    .message_len = sizeof(error_msg)
  };
  bare_signer_biometric_opts_t* opts = NULL;

  int e;

  js_deferred_t *deferred;
  js_value_t *promise;
  e = js_create_promise(env, &deferred, &promise);
  assert(e == 0);

  enum { args_num = 1 };
  size_t argc = args_num;
  js_value_t *argv[args_num];
  e = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(e == 0);
  if (argc != args_num) {
    js_value_t *js_err = mk_error(env, "READ_DATA_ERROR", "invalid number of arguments, expected 1");
    js_reject_deferred(env, deferred, js_err);
    goto cleanup;
  }

  bool ok_opts;
  e = js_is_object(env, argv[0], &ok_opts);
  assert(e == 0);
  if (!ok_opts) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 1 must be an object");
    js_reject_deferred(env, deferred, mk_error(env, "READ_DATA_ERROR", error_msg2));
    goto cleanup;
  }
  opts = bare_signer_biometric_opts_parse(env, argv[0], &error);
  if (opts == NULL) {
    snprintf(error_msg2, sizeof(error_msg2), "opts: %s", error.message);
    js_reject_deferred(env, deferred, mk_error(env, "READ_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  bare_signer_read_data_work_context_t *ctx = calloc(1, sizeof(bare_signer_read_data_work_context_t));
  assert(ctx != NULL);
  ctx->work.data = ctx;
  ctx->env = env;
  ctx->deferred = deferred;
  ctx->opts = opts;
  opts = NULL; // would be freed in ctx cleanup

  uv_loop_t *loop;
  e = js_get_env_loop(env, &loop);
  assert(e == 0);

  e = uv_queue_work(loop, &ctx->work, bare_signer_read_data_async_do, bare_signer_read_data_async_done);
  assert(e == 0);

cleanup:
  if (opts != NULL) {
    bare_signer_biometric_opts_free(opts);
  }
  return promise;
}

typedef struct {
  uv_work_t work;
  js_env_t *env;
  js_deferred_t *deferred;
  bare_signer_biometric_opts_t* opts;
  char data[bare_signer_DATA_LEN];
  size_t data_len;
  char* error_msg;
} bare_signer_store_data_work_context_t;

static void
bare_signer_store_data_async_do(uv_work_t *req) {
  bare_signer_store_data_work_context_t *ctx = (bare_signer_store_data_work_context_t *) req->data;

  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  size_t error_len = bare_signer_MAX_ERROR_LEN;
  int err = store_data_in_keystore(ctx->data, ctx->data_len, error_msg, &error_len, ctx->opts);
  if (err != 0) {
    ctx->error_msg = strdup(error_msg);
    return;
  }
}

static void
bare_signer_store_data_async_done(uv_work_t *req, int status) {
  int e;
  bare_signer_store_data_work_context_t *ctx = (bare_signer_store_data_work_context_t *) req->data;

  js_handle_scope_t *scope;
  e = js_open_handle_scope(ctx->env, &scope);
  assert(e == 0);

  if (status != 0) {
    js_value_t* error = mk_error(ctx->env, "STORE_DATA_ERROR", "uv work request failed");
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  if (ctx->error_msg != NULL) {
    js_value_t* error = mk_error(ctx->env, "STORE_DATA_ERROR", ctx->error_msg);
    e = js_reject_deferred(ctx->env, ctx->deferred, error);
    assert(e == 0);
    goto cleanup;
  }

  js_value_t *result;
  e = js_get_undefined(ctx->env, &result);
  assert(e == 0);
  e = js_resolve_deferred(ctx->env, ctx->deferred, result);
  assert(e == 0);

cleanup:

  e = js_close_handle_scope(ctx->env, scope);
  assert(e == 0);

  memset(ctx->data, 0, sizeof(ctx->data));

  if (ctx->error_msg != NULL) {
    free(ctx->error_msg);
  }
  if (ctx->opts != NULL) {
    bare_signer_biometric_opts_free(ctx->opts);
  }
  free(ctx);
}

static js_value_t *
bare_signer_store_data(js_env_t *env, js_callback_info_t *info) {
  char error_msg[bare_signer_MAX_ERROR_LEN] = {0};
  char error_msg2[bare_signer_MAX_ERROR_LEN] = {0};
  bare_signer_error_t error = {
    .message = error_msg,
    .message_len = sizeof(error_msg)
  };
  bare_signer_biometric_opts_t* opts = NULL;

  int e;

  js_deferred_t *deferred;
  js_value_t *promise;
  e = js_create_promise(env, &deferred, &promise);
  assert(e == 0);

  enum { args_num = 4 };
  size_t argc = args_num;
  js_value_t *argv[args_num];
  e = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(e == 0);
  if (argc != args_num) {
    js_value_t *js_err = mk_error(env, "STORE_DATA_ERROR", "invalid number of arguments, expected 4");
    js_reject_deferred(env, deferred, js_err);
    goto cleanup;
  }

  bool ok;
  e = js_is_arraybuffer(env, argv[0], &ok);
  assert(e == 0);
  if (!ok) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 1 (data) must be an ArrayBuffer");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  void *data_buffer;
  size_t buffer_size;
  e = js_get_arraybuffer_info(env, argv[0], &data_buffer, &buffer_size);
  assert(e == 0);

  e = js_is_int32(env, argv[1], &ok);
  assert(e == 0);
  if (!ok) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 2 (offset) must be an int");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }
  int64_t offset;
  e = js_get_value_int64(env, argv[1], &offset);
  assert(e == 0);

  e = js_is_int32(env, argv[2], &ok);
  assert(e == 0);
  if (!ok) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 3 (length) must be an int");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }
  int64_t data_len;
  e = js_get_value_int64(env, argv[2], &data_len);
  assert(e == 0);

  if (offset < 0 || data_len < 0) {
    snprintf(error_msg2, sizeof(error_msg2), "offset and length must be non-negative");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  if ((size_t)offset + (size_t)data_len > buffer_size) {
    snprintf(error_msg2, sizeof(error_msg2), "offset + length exceeds buffer size");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  if ((size_t)data_len > bare_signer_DATA_LEN) {
    snprintf(error_msg2, sizeof(error_msg2), "data too long (max %d bytes)", bare_signer_DATA_LEN);
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  e = js_is_object(env, argv[3], &ok);
  assert(e == 0);
  if (!ok) {
    snprintf(error_msg2, sizeof(error_msg2), "argument 4 must be an object");
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }
  opts = bare_signer_biometric_opts_parse(env, argv[3], &error);
  if (opts == NULL) {
    snprintf(error_msg2, sizeof(error_msg2), "opts: %s", error.message);
    js_reject_deferred(env, deferred, mk_error(env, "STORE_DATA_ERROR", error_msg2));
    goto cleanup;
  }

  bare_signer_store_data_work_context_t *ctx = calloc(1, sizeof(bare_signer_store_data_work_context_t));
  assert(ctx != NULL);
  ctx->work.data = ctx;
  ctx->env = env;
  ctx->deferred = deferred;
  memcpy(ctx->data, (unsigned char *)data_buffer + offset, data_len);
  ctx->data_len = data_len;
  ctx->opts = opts;
  opts = NULL;

  uv_loop_t *loop;
  e = js_get_env_loop(env, &loop);
  assert(e == 0);

  e = uv_queue_work(loop, &ctx->work, bare_signer_store_data_async_do, bare_signer_store_data_async_done);
  assert(e == 0);

cleanup:
  if (opts != NULL) {
    bare_signer_biometric_opts_free(opts);
  }
  return promise;
}

static js_value_t *
bare_signer_exports(js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("storeData", bare_signer_store_data)
  V("deleteData", bare_signer_delete_data)
  V("readData", bare_signer_read_data)
#undef V

  return exports;
}

BARE_MODULE(bare_signer, bare_signer_exports)
