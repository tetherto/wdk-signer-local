#include <jni.h>
#include <string>
#include <thread>
#include <chrono>

static JavaVM* g_jvm = nullptr;

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT JavaVM* get_global_jvm() {
    return g_jvm;
}