/**
 *  @file   UID_transaction.h
 *
 *
 *  @date   12/dec/2016
 *  @author M. Palumbi
 */



#ifndef __UID_TRANSACTION_H
#define __UID_TRANSACTION_H

#include <stdint.h>
#include <stdlib.h>

int UID_digest_raw_tx(uint8_t *rawtx, size_t len, u_int in, uint8_t address[20], uint8_t hash[32]);


#endif // __UID_TRANSACTION_H