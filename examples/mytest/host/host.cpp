//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <edge_call.h>
#include <keystone.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

void getProcessInformation(void* buffer);
uintptr_t virtualAddress_to_physicalAddress(unsigned long va,int pid);

// 外设路径
#define SYSFS_USB_DEVICES "/sys/bus/usb/devices"

// 边缘调用编号
#define OCALL_GET_PROCESS_INFORMATION 1

using namespace Keystone;

int
main(int argc, char **argv) {
    Enclave enclave;
    Params params;

    params.setFreeMemSize(1024 * 1024);
    params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024 * 1024);

    enclave.init(argv[1], argv[2], params);

    enclave.registerOcallDispatch(incoming_call_dispatch);

    register_call(OCALL_GET_PROCESS_INFORMATION, getProcessInformation);

    edge_call_init_internals(
            (uintptr_t) enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    enclave.run();

    return 0;
}


// 获取进程信息
void getProcessInformation(void *buffer){
    char filename[256];
    FILE *stat_file;
    char stat_buffer[1024];
    unsigned long start_code,end_code,arg_start,arg_end;

    printf("当前程序版本：v0.1\n");
    // 获取当前进程的ID
    pid_t process_id = getpid();
    printf("当前进程的id是：%d\n",process_id);


    // 构造stat文件路径
    snprintf(filename, sizeof(filename), "/proc/%d/stat", process_id);

    // 打开stat文件
    stat_file = fopen(filename, "r");
    if (stat_file == NULL) {
        perror("Error opening stat file");
        exit(EXIT_FAILURE);
    }

    // 逐行读取stat文件
    if(fgets(stat_buffer,sizeof(stat_buffer) + 1,stat_file)!=NULL){
        char *token;

        token = strtok(stat_buffer," ");

        int count = 0;

        while( token != NULL ) {
            printf( "%s\n", token );

            switch (++count) {
                case 26:
                    start_code = strtoul(token, NULL, 10);
                    break;
                case 27:
                    end_code = strtoul(token,NULL,10);
                    break;
                case 48:
                    arg_start = strtoul(token,NULL,10);
                case 49:
                    arg_end = strtoul(token,NULL,10);
                default:
                    break;
            }
            token = strtok(NULL, " ");
        }
    }

    printf("start_code=%ld\n",start_code);
    printf("start_code physicalAddress=%ld\n", virtualAddress_to_physicalAddress(start_code,process_id));
    printf("end_code=%ld\n",end_code);
    printf("end_code physicalAddress=%ld\n", virtualAddress_to_physicalAddress(end_code,process_id));
    printf("arg_start=%lx\n",arg_start);
    printf("arg_end=%lx\n",arg_end);

    // 关闭stat文件
    fclose(stat_file);
}

// 虚拟地址转物理地址
uintptr_t virtualAddress_to_physicalAddress(unsigned long va,int pid){
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/pagemap", pid);

    FILE *pagemap = fopen(filename, "rb");
    if (!pagemap) {
        perror("Error opening pagemap");
        exit(EXIT_FAILURE);
    }

    // 计算页框大小
    long page_size = sysconf(_SC_PAGESIZE);

    // 计算虚拟地址在页表中的索引
    off_t offset = va / page_size * sizeof(uint64_t);

    // 定位到虚拟地址对应的页表项
    if (fseeko(pagemap, offset, SEEK_SET) != 0) {
        perror("Error seeking to pagemap offset");
        fclose(pagemap);
        exit(EXIT_FAILURE);
    }

    // 读取页表项
    uint64_t pagemap_entry;
    if (fread(&pagemap_entry, sizeof(uint64_t), 1, pagemap) != 1) {
        perror("Error reading pagemap entry");
        fclose(pagemap);
        exit(EXIT_FAILURE);
    }

    fclose(pagemap);

    // 提取物理页框号
    uintptr_t page_frame_number = pagemap_entry & ((1ULL << 55) - 1);

    // 计算物理地址
    uintptr_t pa = (page_frame_number * page_size) + (va % page_size);

    return pa;
}