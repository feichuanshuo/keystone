//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <Report.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "ed25519/ed25519.h"

using json11::Json;

// 将字节数组转换为十六进制表示的字符串
std::string
Report::BytesToHex(byte *bytes, size_t len) {
    unsigned int i;
    std::string str;
    for (i = 0; i < len; i += 1) {
        std::stringstream ss;
        // // 将字节转换为两位的十六进制，并追加到字符串
        ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t) bytes[i];

        str += ss.str();
    }
    return str;
}

// 将十六进制字符串转换为字节数组
void
Report::HexToBytes(byte *bytes, size_t len, std::string hexstr) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        unsigned int data = 0;
        std::stringstream ss;
        // 从 hexstr 中提取两个字符，将其转换为十六进制表示的整数
        ss << hexstr.substr(i * 2, 2);
        // 将提取到的字符转换为十六进制表示的整数
        ss >> std::hex >> data;
        // 将整数存储为字节
        bytes[i] = (byte) data;
    }
}

// 从 json 字符串中解析报告
void
Report::fromJson(std::string jsonstr) {
    std::string err;
    const auto json = Json::parse(jsonstr, err);

    // 解析设备公钥
    std::string device_pubkey = json["device_pubkey"].string_value();
    HexToBytes(report.dev_public_key, PUBLIC_KEY_SIZE, device_pubkey);

    // 解析 SM 哈希值
    std::string sm_hash = json["security_monitor"]["hash"].string_value();
    HexToBytes(report.sm.hash, MDSIZE, sm_hash);

    // 解析 SM 公钥
    std::string sm_pubkey = json["security_monitor"]["pubkey"].string_value();
    HexToBytes(report.sm.public_key, PUBLIC_KEY_SIZE, sm_pubkey);

    // 解析 SM 签名
    std::string sm_signature =
            json["security_monitor"]["signature"].string_value();
    HexToBytes(report.sm.signature, SIGNATURE_SIZE, sm_signature);

    // 解析 enclave 哈希值
    std::string enclave_hash = json["enclave"]["hash"].string_value();
    HexToBytes(report.enclave.hash, MDSIZE, enclave_hash);

    // 解析 enclave datalen
    report.enclave.data_len = json["enclave"]["datalen"].int_value();

    // 解析 enclave data
    std::string enclave_data = json["enclave"]["data"].string_value();
    HexToBytes(report.enclave.data, report.enclave.data_len, enclave_data);

    // 解析 enclave 签名
    std::string enclave_signature = json["enclave"]["signature"].string_value();
    HexToBytes(report.enclave.signature, SIGNATURE_SIZE, enclave_signature);
}

// 将 bin 中的二进制数据复制到 Report 结构体对象中
void
Report::fromBytes(byte *bin) {
    std::memcpy(&report, bin, sizeof(struct report_t));
}

// 将 Report 结构体对象转换为 JSON 字符串
std::string
Report::stringfy() {
    if (report.enclave.data_len > ATTEST_DATA_MAXLEN) {
        return "{ \"error\" : \"invalid data length\" }";
    }
    auto json = Json::object{
            {"device_pubkey", BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE)},
            {
             "security_monitor",
                              Json::object{
                                      {"hash",      BytesToHex(report.sm.hash, MDSIZE)},
                                      {"pubkey",    BytesToHex(report.sm.public_key, PUBLIC_KEY_SIZE)},
                                      {"signature", BytesToHex(report.sm.signature, SIGNATURE_SIZE)}},
            },
            {
             "enclave",
                              Json::object{
                                      {"hash",    BytesToHex(report.enclave.hash, MDSIZE)},
                                      {"datalen", static_cast<int>(report.enclave.data_len)},
                                      {"data",
                                                  BytesToHex(report.enclave.data, report.enclave.data_len)},
                                      {"signature",
                                                  BytesToHex(report.enclave.signature, SIGNATURE_SIZE)},
                              },
            },
    };

    return json11::Json(json).dump();
}

// 以Json格式打印报告
void
Report::printJson() {
    std::cout << stringfy() << std::endl;
}

// 以更可读格式打印报告
void
Report::printPretty() {
    std::cout << "\t\t=== Security Monitor ===" << std::endl;
    std::cout << "Hash: " << BytesToHex(report.sm.hash, MDSIZE) << std::endl;
    std::cout << "Pubkey: " << BytesToHex(report.sm.public_key, PUBLIC_KEY_SIZE)
              << std::endl;
    std::cout << "Signature: " << BytesToHex(report.sm.signature, SIGNATURE_SIZE)
              << std::endl;
    std::cout << std::endl << "\t\t=== Enclave Application ===" << std::endl;
    std::cout << "Hash: " << BytesToHex(report.enclave.hash, MDSIZE) << std::endl;
    std::cout << "Signature: "
              << BytesToHex(report.enclave.signature, SIGNATURE_SIZE)
              << std::endl;
    std::cout << "Enclave Data: "
              << BytesToHex(report.enclave.data, report.enclave.data_len)
              << std::endl;
    std::cout << "\t\t-- Device pubkey --" << std::endl;
    std::cout << BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE) << std::endl;
}

// 获取报告中的 enclave 哈希值
byte *
Report::getEnclaveHash() {
    return report.enclave.hash;
}

// 获取报告中的 SM 哈希值
byte *
Report::getSmHash() {
    return report.sm.hash;
}

// 验证报告中的enclave和SM的哈希值是否和预期相同（之前计算的值）,验证签名是否有效
int
Report::verify(
        const byte *expected_enclave_hash, const byte *expected_sm_hash,
        const byte *dev_public_key) {
    /* verify that enclave hash matches */
    // 验证报告中的enclave 哈希值是否与预期相同
    int encl_hash_valid =
            memcmp(expected_enclave_hash, report.enclave.hash, MDSIZE) == 0;
    // 验证报告中的 SM 哈希值是否与预期相同
    int sm_hash_valid = memcmp(expected_sm_hash, report.sm.hash, MDSIZE) == 0;
    // 验证签名是否有效
    int signature_valid = checkSignaturesOnly(dev_public_key);

    return encl_hash_valid && sm_hash_valid && signature_valid;
}

// 验证签名是否有效
int
Report::checkSignaturesOnly(const byte *dev_public_key) {
    int sm_valid = 0;
    int enclave_valid = 0;

    /* verify SM report */
    sm_valid = ed25519_verify(
            report.sm.signature, reinterpret_cast<byte *>(&report.sm),
            MDSIZE + PUBLIC_KEY_SIZE, dev_public_key);

    /* verify Enclave report */
    enclave_valid = ed25519_verify(
            report.enclave.signature, reinterpret_cast<byte *>(&report.enclave),
            MDSIZE + sizeof(uint64_t) + report.enclave.data_len,
            report.sm.public_key);

    return sm_valid && enclave_valid;
}

// 获取报告中的数据段
void *
Report::getDataSection() {
    return report.enclave.data;
}

// 获取报告中的数据段长度
size_t
Report::getDataSize() {
    return report.enclave.data_len;
}
