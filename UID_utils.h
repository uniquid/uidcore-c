/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

 /**
 * @file   UID_utils.h
 *
 * @date   29/lug/2016
 * @author M. Palumbi
 */
 
 
#ifndef __UID_UTILS_H
#define __UID_UTILS_H

#include "sha2.h"
#include "UID_identity.h"

size_t fromhex(const char *str, uint8_t *buf, size_t len);
uint8_t *fromnhex(const char *str, uint8_t *buf, size_t len);

char *tohex(const uint8_t *bin, size_t l, char *buf);
int cryptoMessageSign(const uint8_t *message, size_t message_len, const uint8_t *privkey, uint8_t *signature);
int cryptoMessageVerify(const uint8_t *message, size_t message_len, const char *address_raw, const uint8_t *signature);
void UID_hashMessage_init(size_t message_len, SHA256_CTX *ctx);
void UID_hashMessage_update(char *partial_message, size_t partial_len, SHA256_CTX *ctx);
void UID_hashMessage_final(uint8_t hash[32], SHA256_CTX *ctx);
int UID_signMessageHash(uint8_t hash[32], UID_Bip32Path *path, char *b64signature, size_t ssize);
int UID_signMessage(char *message, UID_Bip32Path *path, char *b64signature, size_t ssize);
int UID_addressFromSignedHash(uint8_t hash[32], char *b64signature, BTC_Address address);
int UID_verifyMessage(char *message, char *b64signature, char *address);



#endif
