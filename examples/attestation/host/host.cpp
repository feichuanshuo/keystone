//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "host.h"

#include <getopt.h>
#include <stdlib.h>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4

// 设置边缘调用状态为CALL_STATUS_OK
void
SharedBuffer::set_ok() {
    edge_call_->return_data.call_status = CALL_STATUS_OK;
}

// 设置边缘调用状态为CALL_STATUS_BAD_OFFSET
void
SharedBuffer::set_bad_offset() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
}

// 设置边缘调用状态为CALL_STATUS_BAD_PTR
void
SharedBuffer::set_bad_ptr() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR;
}

// 计算出相对于缓冲区起始地址的指针
int
SharedBuffer::get_ptr_from_offset(edge_data_offset offset, uintptr_t *ptr) {
    /* Validate that _shared_start+offset is sane */
    /* 验证 _shared_start+offset 是否正常 */
    if (offset > UINTPTR_MAX - buffer_ || offset > buffer_len_) {
        return -1;
    }

    /* ptr looks valid, create it */
    *ptr = buffer_ + offset;
    return 0;
}

// 返回边缘调用参数的指针和大小
int
SharedBuffer::args_ptr(uintptr_t *ptr, size_t *size) {
    *size = edge_call_->call_arg_size;
    return get_ptr_from_offset(edge_call_->call_arg_offset, ptr);
}

// 尝试获取边缘调用的参数指针和大小，如果失败则设置 bad_offset
std::optional <std::pair<uintptr_t, size_t>>
SharedBuffer::get_call_args_ptr_or_set_bad_offset() {
    uintptr_t call_args;
    size_t arg_len;
    if (args_ptr(&call_args, &arg_len) != 0) {
        set_bad_offset();
        return std::nullopt;
    }
    return std::pair{call_args, arg_len};
}

// 尝试获取边缘调用的字符串参数，如果失败则设置 bad_offset
std::optional<char *>
SharedBuffer::get_c_string_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{(char *) v.value().first} : std::nullopt;
}

// 尝试获取边缘调用的无符号长整型参数，如果失败则设置 bad_offset
std::optional<unsigned long>
SharedBuffer::get_unsigned_long_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{*(unsigned long *) v.value().first}
                         : std::nullopt;
}

// 尝试获取边缘调用的 Report 参数，如果失败则设置 bad_offset
std::optional <Report>
SharedBuffer::get_report_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    if (!v.has_value()) return std::nullopt;
    Report ret;
    ret.fromBytes((byte *) v.value().first);
    return ret;
}

uintptr_t
SharedBuffer::data_ptr() {
    return (uintptr_t) edge_call_ + sizeof(struct edge_call);
}

// 验证指针是否在缓冲区内
int
SharedBuffer::validate_ptr(uintptr_t ptr) {
    /* Validate that ptr starts in range */
    if (ptr > buffer_ + buffer_len_ || ptr < buffer_) {
        return 1;
    }
    return 0;
}

// 计算出相对于缓冲区起始地址的偏移量
int
SharedBuffer::get_offset_from_ptr(uintptr_t ptr, edge_data_offset *offset) {
    // 验证指针是否在缓冲区内
    int valid = validate_ptr(ptr);
    if (valid != 0) return valid;

    /* ptr looks valid, create it */
    *offset = ptr - buffer_;
    return 0;
}

int
SharedBuffer::setup_ret(void *ptr, size_t size) {
    edge_call_->return_data.call_ret_size = size;
    return get_offset_from_ptr(
            (uintptr_t) ptr, &edge_call_->return_data.call_ret_offset);
}

void
SharedBuffer::setup_ret_or_bad_ptr(unsigned long ret_val) {
    // Assuming we are done with the data section for args, use as
    // return region.
    //
    // TODO safety check?
    uintptr_t data_section = data_ptr();

    memcpy((void *) data_section, &ret_val, sizeof(unsigned long));

    if (setup_ret((void *) data_section, sizeof(unsigned long))) {
        set_bad_ptr();
    } else {
        set_ok();
    }
}

// 设置边缘调用返回数据
int
SharedBuffer::setup_wrapped_ret(void *ptr, size_t size) {
    struct edge_data data_wrapper;
    data_wrapper.size = size;
    get_offset_from_ptr(
            buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data),
            &data_wrapper.offset);

    memcpy(
            (void *) (buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data)),
            ptr, size);

    memcpy(
            (void *) (buffer_ + sizeof(struct edge_call)), &data_wrapper,
            sizeof(struct edge_data));

    edge_call_->return_data.call_ret_size = sizeof(struct edge_data);
    return get_offset_from_ptr(
            buffer_ + sizeof(struct edge_call),
            &edge_call_->return_data.call_ret_offset);
}

// 设置边缘调用返回数据，如果失败则设置 bad_ptr
void
SharedBuffer::setup_wrapped_ret_or_bad_ptr(const std::string &ret_val) {
    if (setup_wrapped_ret((void *) ret_val.c_str(), ret_val.length() + 1)) {
        set_bad_ptr();
    } else {
        set_ok();
    }
    return;
}

/*==================================================================================*/

// 打印缓冲区中的字符串
void
Host::print_buffer_wrapper(RunData &run_data) {
    SharedBuffer &shared_buffer = run_data.shared_buffer;

    auto t = shared_buffer.get_c_string_or_set_bad_offset();
    if (t.has_value()) {
        printf("Enclave said: %s", t.value());
        auto ret_val = strlen(t.value());
        shared_buffer.setup_ret_or_bad_ptr(ret_val);
    }
}

// 打印缓冲区中的无符号长整型
void
Host::print_value_wrapper(RunData &run_data) {
    SharedBuffer &shared_buffer = run_data.shared_buffer;

    auto t = shared_buffer.get_unsigned_long_or_set_bad_offset();
    if (t.has_value()) {
        printf("Enclave said value: %u\n", t.value());
        shared_buffer.set_ok();
    }
    return;
}

// 将缓冲区中的 Report 复制到 run_data.report 中
void
Host::copy_report_wrapper(RunData &run_data) {
    SharedBuffer &shared_buffer = run_data.shared_buffer;

    auto t = shared_buffer.get_report_or_set_bad_offset();
    if (t.has_value()) {
        run_data.report = std::make_unique<Report>(std::move(t.value()));
        shared_buffer.set_ok();
    }
    return;
}

// 将随机数 nonce 复制到缓冲区中
void
Host::get_host_string_wrapper(RunData &run_data) {
    SharedBuffer &shared_buffer = run_data.shared_buffer;

    shared_buffer.setup_wrapped_ret_or_bad_ptr(run_data.nonce);
    return;
}

// 根据 edge_call 的 call_id 调用相应的函数
void
Host::dispatch_ocall(RunData &run_data) {
    // 获取edge_call的地址
    struct edge_call *edge_call = (struct edge_call *) run_data.shared_buffer.ptr();
    // 判断call_id
    switch (edge_call->call_id) {
        case OCALL_PRINT_BUFFER:
            print_buffer_wrapper(run_data);
            break;
        case OCALL_PRINT_VALUE:
            print_value_wrapper(run_data);
            break;
        case OCALL_COPY_REPORT:
            copy_report_wrapper(run_data);
            break;
        case OCALL_GET_STRING:
            get_host_string_wrapper(run_data);
            break;
    }
    return;
}

// 将来自远程验证程序的随机随机数提供给 enclave ，并将enclave证明报告返回给验证程序
Report
Host::run(const std::string &nonce) {
    Keystone::Enclave enclave;
    enclave.init(eapp_file_.c_str(), rt_file_.c_str(), params_);

    RunData run_data{
            SharedBuffer{enclave.getSharedBuffer(), enclave.getSharedBufferSize()},
            nonce, nullptr};

    // 注册边缘调用分发函数
    enclave.registerOcallDispatch([&run_data](void *buffer) {
        assert(buffer == (void *) run_data.shared_buffer.ptr());
        dispatch_ocall(run_data);
    });

    uintptr_t encl_ret;
    enclave.run(&encl_ret);

    return *run_data.report;
}
