// heymod2.cpp - WORKING build-B structure (zygisk.hpp full machinery) with a
// minimal, static-free pre-stage for seccomp arming. No new statics, no iostream,
// everything else identical to the proven build.
#include "zygisk.hpp"
#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <dlfcn.h>

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static const char *TARGET = "com.heytea.overseago";
static const char *LIB = "/data/data/com.heytea.overseago/files/libgrp.so";
static const char *SOCKPATH = "/data/local/tmp/sanfd.sock";

static void wlog2(const char *tag, long v) {
    char buf[64];
    // hand-rolled formatting to keep stdio out of the pre stage
    unsigned i = 0;
    while (tag[i] && i < 32) buf[i] = tag[i], i++;
    buf[i++] = ' ';
    char t[24]; unsigned tn = 0;
    unsigned long uv = (v < 0) ? -(unsigned long)v : (unsigned long)v;
    if (!uv) t[tn++] = '0';
    while (uv && tn < sizeof t) { t[tn++] = (char)('0' + uv % 10); uv /= 10; }
    if (v < 0) buf[i++] = '-';
    while (tn && i < 55) buf[i++] = t[--tn];
    buf[i++] = '\n';
    int fd = (int)syscall(SYS_openat, -100, "/dev/heymod.log", O_WRONLY|O_CREAT|O_APPEND, 0666);
    if (fd >= 0) { syscall(SYS_write, fd, buf, i); syscall(SYS_close, fd); }
}

static long seccomp_install_errno_only(void) {
    struct sock_filter f[10];
    memset(f, 0, sizeof f);
    unsigned n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 2-1-1, 7-1-1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 62,  8-3-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 186, 8-4-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 234, 8-5-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 231, 8-6-1, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | 0);
    struct sock_fprog prog;
    prog.len = (unsigned short)n;
    prog.filter = f;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static long seccomp_install_arm(int *out_listener) {
    struct sock_filter f[12];
    memset(f, 0, sizeof f);
    unsigned n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 2-1-1, 9-1-1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 62,  10-3-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 186, 10-4-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 234, 10-5-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 231, 10-6-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 257, 11-7-1, 1);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 2,   11-8-1, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF);
    struct sock_fprog prog;
    prog.len = (unsigned short)n;
    prog.filter = f;
    long fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (out_listener) *out_listener = (int)fd;
    return fd;
}

class HeyMod final : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override { this->api_ = api; this->env_ = env; }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (env_ == nullptr || args == nullptr) return;
        const char *nice = nullptr;
        if (args->nice_name != nullptr)
            nice = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (nice != nullptr && strstr(nice, TARGET) != nullptr) {
            wlog2("pre_hit", (long)syscall(SYS_getpid, 0, 0, 0));
            long sn = (long)syscall(SYS_prctl, 38, 1, 0, 0, 0);
            wlog2("nnpset", sn);
            wlog2("pre_secc_start", 1);
            long r0 = seccomp_install_errno_only();
            wlog2("seccA", r0);
            wlog2("pre_done", 1);
        }
        if (nice != nullptr) env_->ReleaseStringUTFChars(args->nice_name, nice);
    }
    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (env_ == nullptr || args == nullptr) return;
        const char *nice = nullptr;
        if (args->nice_name != nullptr)
            nice = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (nice != nullptr && strstr(nice, TARGET) != nullptr) {
            void *h = dlopen(LIB, RTLD_NOW | RTLD_GLOBAL);
            wlog2(h ? "post_loaded" : "post_fail", 1);
        }
        if (nice != nullptr) env_->ReleaseStringUTFChars(args->nice_name, nice);
    }
private:
    Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

REGISTER_ZYGISK_MODULE(HeyMod)
