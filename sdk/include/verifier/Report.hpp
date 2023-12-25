//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <string>
#include "Keys.hpp"
#include "common/sha3.h"
#include "ed25519/ed25519.h"
#include "verifier/json11.h"

struct enclave_report_t {
    byte hash[MDSIZE];
    uint64_t data_len;
    byte data[ATTEST_DATA_MAXLEN];
    byte signature[SIGNATURE_SIZE];
};

struct sm_report_t {
    byte hash[MDSIZE];
    byte public_key[PUBLIC_KEY_SIZE];
    byte signature[SIGNATURE_SIZE];
};

struct report_t {
    struct enclave_report_t enclave;
    struct sm_report_t sm;
    byte dev_public_key[PUBLIC_KEY_SIZE];
};

class Report {
private:
    struct report_t report;

public:
    // 将字节数组转换为十六进制表示的字符串
    std::string BytesToHex(byte *bytes, size_t len);
    // 将十六进制字符串转换为字节数组
    void HexToBytes(byte *bytes, size_t len, std::string hexstr);
    // 从 json 字符串中解析报告
    void fromJson(std::string json);
    // 将 bin 中的二进制数据复制到 Report 结构体对象中
    void fromBytes(byte *bin);
    // 将 Report 结构体对象转换为 JSON 字符串
    std::string stringfy();
    // 以Json格式打印报告
    void printJson();
    // 以更可读格式打印报告
    void printPretty();
    // 验证报告中的enclave和SM的哈希值是否和预期相同（之前计算的值）,验证签名是否有效
    int verify(
            const byte *expected_enclave_hash, const byte *expected_sm_hash,
            const byte *dev_public_key);
    // 验证签名是否有效
    int checkSignaturesOnly(const byte *dev_public_key);
    // 获取报告中的数据段
    void *getDataSection();
    // 获取报告中的数据段长度
    size_t getDataSize();
    // 获取报告中的 enclave 哈希值
    byte *getEnclaveHash();
    // 获取报告中的 SM 哈希值
    byte *getSmHash();
};
