#include <stddef.h>

#define ED25519_NO_SEED 1

#include "sha3/sha3.h"
/* Adopted from https://github.com/orlp/ed25519
  provides:
  - void ed25519_create_keypair(t_pubkey *public_key, t_privkey *private_key, t_seed *seed);
  - void ed25519_sign(t_signature *signature,
                      const unsigned uint8_t *message,
                      size_t message_len,
                      t_pubkey *public_key,
                      t_privkey *private_key);
*/

#include "ed25519/ed25519.h"
/* adopted from
  provides:
  - int sha3_init(sha3_context * md);
  - int sha3_update(sha3_context * md, const unsigned char *in, size_t inlen);
  - int sha3_final(sha3_context * md, unsigned char *out);
  types: sha3_context
*/

#include "string.h"

/*
  provides memcpy, memset
*/


typedef unsigned char byte;

// Sanctum header fields in DRAM
extern byte sanctum_dev_public_key[32];         // 设备公钥
extern byte sanctum_dev_secret_key[64];         // 设备私钥
unsigned int sanctum_sm_size = 0x1ff000;        // SM大小
extern byte sanctum_sm_hash[64];                // SM哈希
extern byte sanctum_sm_public_key[32];          // SM公钥
extern byte sanctum_sm_secret_key[64];          // SM私钥
extern byte sanctum_sm_signature[64];           // SM签名
#define DRAM_BASE 0x80000000                    // DRAM基址

/* Update this to generate valid entropy for target platform*/
/* 伪随机数生成器，该函数在实际设备上应该使用硬件提供的真正随机数生成器（TRNG），但在测试目的上，它只是简单地返回一个常量。*/
inline byte

random_byte(unsigned int i) {
#warning Bootloader does not have entropy source, keys are for TESTING ONLY
    return 0xac + (0xdd ^ i);
}

void bootloader() {
    //*sanctum_sm_size = 0x200;
    // Reserve stack space for secrets
    byte scratchpad[128];                    // 临时存储空间
    sha3_ctx_t hash_ctx;                     // SHA3上下文

    // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
    // ... SD card to beginning of memory.
    // sd_init();
    // sd_read_from_start(DRAM, 1024);

    /* Gathering high quality entropy during boot on embedded devices is
     * a hard problem. Platforms taking security seriously must provide
     * a high quality entropy source available in hardware. Platforms
     * that do not provide such a source must gather their own
     * entropy. See the Keystone documentation for further
     * discussion. For testing purposes, we have no entropy generation.
    */

    // Create a random seed for keys and nonces from TRNG
    // 生成随机数
    for (unsigned int i = 0; i < 32; i++) {
        scratchpad[i] = random_byte(i);
    }

    /* On a real device, the platform must provide a secure root device
       keystore. For testing purposes we hardcode a known private/public
       keypair */
    // TEST Device key
    // 填充公私钥到对应字段
#include "use_test_keys.h"

    // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
    // 用随机种子生成设备公私钥
    //ed25519_create_keypair(sanctum_dev_public_key, sanctum_dev_secret_key, scratchpad);

    // Measure SM
    // 度量SM
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, (void *) DRAM_BASE, sanctum_sm_size);
    sha3_final(sanctum_sm_hash, &hash_ctx);

    // Combine SK_D and H_SM via a hash
    // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
    // 生成SM密钥种子
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, sanctum_dev_secret_key, sizeof(*sanctum_dev_secret_key));
    sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
    sha3_final(scratchpad, &hash_ctx);
    // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
    // 生成SM公私钥
    ed25519_create_keypair(sanctum_sm_public_key, sanctum_sm_secret_key, scratchpad);

    // 生成SM证书并签名
    // Endorse the SM
    memcpy(scratchpad, sanctum_sm_hash, 64);
    memcpy(scratchpad + 64, sanctum_sm_public_key, 32);
    // Sign (H_SM, PK_SM) with SK_D
    ed25519_sign(sanctum_sm_signature, scratchpad, 64 + 32, sanctum_dev_public_key, sanctum_dev_secret_key);

    // Clean up
    // Erase SK_D
    // 擦除设备私钥
    memset((void *) sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));

    // caller will clean core state and memory (including the stack), and boot.
    return;
}
