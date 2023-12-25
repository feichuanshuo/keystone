//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <stdlib.h>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"


class Verifier {
public:
    Verifier(
            const Keystone::Params &params, const std::string &eapp_file,
            const std::string &rt_file, const std::string &sm_bin_file)
            : params_(params),
              eapp_file_(eapp_file),
              rt_file_(rt_file),
              sm_bin_file_(sm_bin_file) {}
    // This method generates a random nonce, invokes the run() method
    // of the Host, and verifies that the returned attestation report
    // is valid.
    // 生成随机数，之后调用 Host 的 run（） 方法，并验证返回的证明报告是否有效
    void run();

private:
    // Debug only: verifies just the signature but not the hashes.
    // 只验证签名，不验证哈希
    static void debug_verify(Report &report, const byte *dev_public_key);

    // Verifies that both the enclave hash and the SM hash in the
    // attestation report matches with the expected onces computed by
    // the Verifier.
    // 验证报告中的enclave和SM的哈希值是否和预期相同（之前计算的值）
    static void verify_hashes(
            Report &report, const byte *expected_enclave_hash,
            const byte *expected_sm_hash, const byte *dev_public_key);

    // Verifies that the nonce returned in the attestation report is
    // the same as the one sent.
    // 验证证明报告中返回的随机数是否与发送的随机数相同
    static void verify_data(Report &report, const std::string &nonce);

    // Verifies the hashes and the nonce in the attestation report.
    // 验证证明报告中的哈希值和随机数
    void verify_report(Report &report, const std::string &nonce);

    // Computes the hash of the expected EApp running in the enclave.
    // 计算在 enclave 中运行的预期 EApp 的哈希值
    void compute_expected_enclave_hash(byte *expected_enclave_hash);

    // Computes the hash of the expected Security Monitor (SM).
    // 计算预期 SM 的哈希值
    void compute_expected_sm_hash(byte *expected_sm_hash);

    const Keystone::Params params_;                     // Keystone 参数
    const std::string eapp_file_;                       // eapp
    const std::string rt_file_;                         // runtime
    const std::string sm_bin_file_;                     // SM
};
