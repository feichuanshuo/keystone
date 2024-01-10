//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

/* this implementes basic system calls for the enclave */

int
ocall(
        unsigned long call_id, void *data, size_t data_len, void *return_buffer,
        size_t return_len) {
    return SYSCALL_5(
            SYSCALL_OCALL, call_id, data, data_len, return_buffer, return_len);
}

// 从共享缓冲区中复制数据到指定的目标地址
int
copy_from_shared(void *dst, uintptr_t offset, size_t data_len) {
    return SYSCALL_3(SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

// NOTE 生成验证报告
int
attest_enclave(void *report, void *data, size_t size) {
    return SYSCALL_3(SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

/* returns sealing key */
int
get_sealing_key(
        struct sealing_key *sealing_key_struct, size_t sealing_key_struct_size,
        void *key_ident, size_t key_ident_size) {
    return SYSCALL_4(
            SYSCALL_GET_SEALING_KEY, sealing_key_struct, sealing_key_struct_size,
            key_ident, key_ident_size);
}

// FIXME 尝试自定义读取文件
int
sys_read(int fd, void *buf, size_t len) {
    return SYSCALL_3(SYS_read, fd, buf, len);
}
