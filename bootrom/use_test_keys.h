/* 将密钥复制到缓存区 */
#include "test_dev_key.h"
memcpy(sanctum_dev_secret_key, _sanctum_dev_secret_key, _sanctum_dev_secret_key_len);
memcpy(sanctum_dev_public_key, _sanctum_dev_public_key, _sanctum_dev_public_key_len);
