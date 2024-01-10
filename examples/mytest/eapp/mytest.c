#include "app/syscall.h"
#include "app/eapp_utils.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OCALL_GET_PROCESS_INFORMATION 1

void get_process_code_range(int pid, unsigned long *start_code, unsigned long *end_code);

int main() {


//    ocall(OCALL_GET_PROCESS_INFORMATION, NULL, 0, NULL, 0);

    // FIXME 尝试自定义读取文件
    sys_read(0, NULL, 0);
    // 强制刷新标准输出缓冲区
    fflush(stdout);
    EAPP_RETURN(0);
//    return 0;
}

// 获取进程的start_code和end_code
// TODO 获得start_code和end_code存在问题
void get_process_code_range(int pid, unsigned long *start_code, unsigned long *end_code) {
    char filename[256];
    FILE *stat_file;
    char buffer[1024];

    // 构造stat文件路径
    snprintf(filename, sizeof(filename), "/proc/%d/stat", pid);

    // 打开stat文件
    stat_file = fopen(filename, "r");
    if (stat_file == NULL) {
        perror("Error opening stat file");
        exit(EXIT_FAILURE);
    }

    // 逐行读取stat文件
    if(fgets(buffer,sizeof(buffer) + 1,stat_file)!=NULL){
        char *token;

        token = strtok(buffer," ");

        int count = 0;

        while( token != NULL ) {
            printf( "%s\n", token );

            switch (++count) {
                case 26:
                    *start_code = strtoul(token, NULL, 10);
                    break;
                case 27:
                    *end_code = strtoul(token,NULL,10);
                    break;
                default:
                    break;
            }
            token = strtok(NULL, " ");
        }
    }

    // 关闭stat文件
    fclose(stat_file);
}