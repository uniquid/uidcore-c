/*
 * UID_tokens.h
 *
 *  Created on: 3/aug/2016
 *      Author: M. Palumbi
 */
 
 
#ifndef __UID_GLOBALS_H
#define __UID_GLOBALS_H



#define BTC_ADDRESS_MIN_LENGHT 26
#define BTC_ADDRESS_MAX_LENGHT 35
#define BTC_SIGNATURE_LENGHT 88
// overestimation of the lenght of the ASCII representation of the integer type
#define ASCII_DECIMAL_LENGHT(type) ((sizeof(type)*8 - 1 + 10) / 10 * 3 + 1) 

typedef char BTC_Address[BTC_ADDRESS_MAX_LENGHT+1]; //address base58 coded
typedef uint8_t BTC_PublicKey[33];  //compressed public key
typedef uint8_t BTC_PrivateKey[32]; //Private key
typedef char BTC_Signature[BTC_SIGNATURE_LENGHT+1]; //Private key

typedef struct
{
    BTC_PrivateKey privateKey;
    BTC_PublicKey publicKey;
} UID_KeyPair;


#endif