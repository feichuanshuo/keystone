//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#ifndef _ATTESTATION_HOST_H_
#define _ATTESTATION_HOST_H_

#include <optional>
#include <utility>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

class SharedBuffer {
public:
    SharedBuffer(void *buffer, size_t buffer_len)
    /* For now we assume the call struct is at the front of the shared
     * buffer. This will have to change to allow nested calls. */
            : edge_call_((struct edge_call *) buffer),
              buffer_((uintptr_t) buffer),
              buffer_len_(buffer_len) {}

    uintptr_t ptr() { return buffer_; }

    size_t size() { return buffer_len_; }

    std::optional<char *> get_c_string_or_set_bad_offset();

    std::optional<unsigned long> get_unsigned_long_or_set_bad_offset();

    std::optional <Report> get_report_or_set_bad_offset();

    void set_ok();

    void setup_ret_or_bad_ptr(unsigned long ret_val);

    void setup_wrapped_ret_or_bad_ptr(const std::string &ret_val);

private:
    uintptr_t data_ptr();

    int args_ptr(uintptr_t *ptr, size_t *size);

    int validate_ptr(uintptr_t ptr);

    int get_offset_from_ptr(uintptr_t ptr, edge_data_offset *offset);

    int get_ptr_from_offset(edge_data_offset offset, uintptr_t *ptr);

    std::optional <std::pair<uintptr_t, size_t>>
    get_call_args_ptr_or_set_bad_offset();

    void set_bad_offset();

    void set_bad_ptr();

    int setup_ret(void *ptr, size_t size);

    int setup_wrapped_ret(void *ptr, size_t size);

    struct edge_call *const edge_call_;
    uintptr_t const buffer_;
    size_t const buffer_len_;
};

// The Host class mimicks a host interacting with the local enclave
// and the remote verifier.
// Host 类模拟与本地 enclave 和远程验证程序交互的主机。
class Host {
public:
    Host(
            const Keystone::Params &params, const std::string &eapp_file,
            const std::string &rt_file)
            : params_(params), eapp_file_(eapp_file), rt_file_(rt_file) {}

    // Given a random nonce from the remote verifier, this method leaves
    // it for the enclave to fetch, and returns the attestation report
    // from the enclave to the verifier.
    // 将来自远程验证程序的随机随机数提供给 enclave ，并将enclave证明报告返回给验证程序
    Report run(const std::string &nonce);

private:
    struct RunData {
        SharedBuffer shared_buffer;                         // 共享缓冲区
        const std::string &nonce;                           // 随机数nonce
        std::unique_ptr <Report> report;                    // 证明报告
    };

    // 根据 edge_call 的 call_id 调用相应的函数
    static void dispatch_ocall(RunData &run_data);

    // 打印缓冲区中的字符串
    static void print_buffer_wrapper(RunData &run_data);

    // 打印缓冲区中的无符号长整型
    static void print_value_wrapper(RunData &run_data);

    // 将缓冲区中的 Report 复制到 run_data.report 中
    static void copy_report_wrapper(RunData &run_data);

    // 将随机数 nonce 复制到缓冲区中
    static void get_host_string_wrapper(RunData &run_data);

    const Keystone::Params params_;                         // Keystone 参数
    const std::string eapp_file_;                           // eapp
    const std::string rt_file_;                             // runtime
};

#endif /* _ATTESTATION_HOST_H_ */
