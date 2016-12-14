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
int UID_digest_raw_tx(uint8_t *rawtx, size_t len, u_int in, uint8_t address[20], uint8_t hash[32])
{
    uint8_t *ptr;
    uint64_t n_input, i, l;
    size_t s;
	SHA256_CTX	context;

	sha256_Init(&context);

    s = decode_varint(rawtx+4, &n_input);
	sha256_Update(&context, rawtx, 4 + s);

    ptr = rawtx + 4 + s;  // points to the beginning of first input

    for (i = 0; i < n_input; i++) {
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
        printf("---> %lld\n", l+s);
        sha256_Update(&context, ptr, 4);
        ptr += 4;
    }

    sha256_Update(&context, ptr, len - (ptr - rawtx));
	sha256_Final(&context, hash);
	sha256_Raw(hash, 32, hash);

    return 0;
}