/*
 *  @file   UID_transaction.c
 *
 *
 *  @date   12/dec/2016
 *  @author M. Palumbi
 */


/**
 * @file UID_transaction.h
 *
 * The module implements functions related to transaction signing.
 *
 */

#include <stdio.h>
#include <string.h>
#include "sha2.h"
#include "UID_transaction.h"
#include "UID_utils.h"
#include "UID_identity.h"
#include "ecdsa.h"


size_t decode_varint(uint8_t *stream, uint64_t *dest)
{
    uint8_t byte;
    uint8_t bitpos = 0;
    uint64_t result = 0;
    int len=0;
    
    do
    {
        if (bitpos >= 64)
            return 0; // error! "varint overflow"
        
        byte = stream[len];
        len++;

        result |= (uint64_t)(byte & 0x7F) << bitpos;
        bitpos = (uint8_t)(bitpos + 7);
    } while (byte & 0x80);
    
    *dest = result;
    return len;
}



/**
 * takes a raw tx (with/without full input scripts) and
 * compute the digest [sha256(sha256())] for the <in> input of the transaction.
 * If address is != NULL, use it to build a pay2address script for the input
 * else uses the script in the tx
 * 
 * @param[in]  rawtx    tx in binary form.
 * @param[in]  len      len of the raw tx
 * @param[in]  in       input for wich calculate the digest
 * @param[in]  adrress  raw bitcoin address (20 bytes)
 * @param[out] hash     returns the digest (sha256(sha256()))
 */
static uint8_t script[26] = { 0x19, 0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac };
int UID_digestRawTx(uint8_t *rawtx, size_t len, u_int in, uint8_t address[20], uint8_t hash[32])
{
    uint8_t *ptr;
    uint64_t n_inputs, i, l;
    size_t s;
	SHA256_CTX	context;

	sha256_Init(&context);

    s = decode_varint(rawtx+4, &n_inputs);
    if (in >= n_inputs) return UID_TX_INDEX_OUT_RANGE;
	sha256_Update(&context, rawtx, 4 + s);

    ptr = rawtx + 4 + s;  // points to the beginning of first input

    for (i = 0; i < n_inputs; i++) {
    	sha256_Update(&context, ptr, 36);
    	ptr += 36;
        s = decode_varint(ptr, &l);

        if (in == i)
            if (NULL == address) {
                sha256_Update(&context, ptr, l + s); // hash the script
            }
            else {  // build pay2address script
                memcpy(script + 4, address, 20);
                sha256_Update(&context, script, sizeof(script)); // hash the script
            }
        else 
            sha256_Update(&context, (uint8_t *)"", 1); // hash 0
        ptr += l + s;
        sha256_Update(&context, ptr, 4);
        ptr += 4;
    }

    sha256_Update(&context, ptr, len - (ptr - rawtx));
	sha256_Final(&context, hash);
	sha256_Raw(hash, 32, hash);

    return UID_TX_OK;
}

/**
 * build the signed transaction (hex coded)
 * @todo  check the len of the out buffer during the buid
 */
int UID_buildSignedHex(uint8_t *rawtx, size_t len, UID_ScriptSig *scriptsig, char *hexouttx, size_t olen)
{
(void)olen;
    size_t s;
    uint8_t *ptr;
    char *hextx;
    uint64_t n_input, i, l;

    hextx = hexouttx;
    s = decode_varint(rawtx+4, &n_input);
	tohex(rawtx, 4 + s, hextx);
	ptr = rawtx + 4 + s;
	hextx += 2*(4 + s);

    for (i = 0; i < n_input; i++) {
        tohex(ptr, 36, hextx);
        ptr += 36;
        hextx += 72;
        s = decode_varint(ptr, &l);
        ptr += l + s;

        s = decode_varint(scriptsig[i], &l);
        tohex(scriptsig[i], 2*(l + s), hextx);

        hextx += 2*(l + s);
        tohex(ptr, 4, hextx);
        ptr += 4;
        hextx += 8;
    }

    s = len - (ptr - rawtx) - 4; // -4 to remove the hash code type
	tohex(ptr, s, hextx);
	hextx[2*s] = 0;

    return hextx - hexouttx + 2*s;
}

int UID_buildScriptSig(uint8_t *rawtx, size_t rawtx_len, UID_Bip32Path *path, int n_inputs, UID_ScriptSig *scriptsig, int n_script)
{
    int i;
    int res;
    uint8_t public_key[33];
    uint8_t pubkeyhash[20];
	uint8_t hash[32];
    uint8_t sig[64] = {0};
	u_int8_t len_der;

    if(n_script < n_inputs) return UID_TX_NOMEM;
    for( i=0; i<n_inputs; i++) {
        UID_getPubkeyAt(&path[i], public_key); //ecdsa_get_public_key33(&secp256k1, private_key, public_key);
        ecdsa_get_pubkeyhash(public_key, pubkeyhash);
        res = UID_digestRawTx(rawtx, rawtx_len, i, pubkeyhash, hash);
        if (UID_TX_OK != res) return res;
        UID_signAt(&path[i], hash, sig);  // ecdsa_sign_digest(&secp256k1, private_key, hash, sig, &pby);

        len_der = ecdsa_sig_to_der(sig, scriptsig[i]+2); // OP_PUSH(len of DER) || DER
        scriptsig[i][0] = 1 + len_der + 1 + 1 + 33;      // len script: OP_PUSH(len of DER) DER hash-type OP_PUSH(len of pubkey) pubkey
        scriptsig[i][1] = len_der + 1;                   // OP_PUSH(len of pubkey)
        scriptsig[i][len_der+2] = 0x01;                  // hash-type
        scriptsig[i][len_der+3] = 33;                    // OP_PUSH(len of pubkey)
        memcpy(scriptsig[i]+2+len_der+1+1, public_key, 33);
    }
    return UID_TX_OK;
}
