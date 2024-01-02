//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "edge/edge_common.h"

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4

int
main() {
    struct edge_data retdata;
    // 获取Host的随机数nonce
    ocall(OCALL_GET_STRING, NULL, 0, &retdata, sizeof(struct edge_data));

    for (unsigned long i = 1; i <= 10000; i++) {
        if (i % 5000 == 0) {
            ocall(OCALL_PRINT_VALUE, &i, sizeof(unsigned long), 0, 0);
        }
    }

    // 从共享缓冲区中复制nonce到指定的目标地址
    char nonce[2048];
    if (retdata.size > 2048) retdata.size = 2048;
    copy_from_shared(nonce, retdata.offset, retdata.size);

    // 生成验证报告
    char buffer[2048];

    /*NOTE 生成验证报告调用路径
     * attestor.c -> sdk/src/app/syscall.c -> sdk/include/app/syscall.h
     * -> runtime/call/syscall.c -> runtime/call/sbi.c
     * -> sm/src/sm-sbi-opensbi.c -> sm/src/sm-sbi.c -> sm/src/enclave.c
     * */
    attest_enclave((void *) buffer, nonce, retdata.size);

    ocall(OCALL_COPY_REPORT, buffer, 2048, 0, 0);

    EAPP_RETURN(0);
}
