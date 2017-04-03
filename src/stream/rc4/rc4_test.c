/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_RC4

int rc4_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   rc4_state st;
   const unsigned char key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   const unsigned char pt[]  = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   const unsigned char ct[]  = { 0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96 };
   unsigned char buf[10];

   rc4_setup(&st, key, sizeof(key));
   rc4_crypt(&st, pt, sizeof(pt), buf);
   if (XMEMCMP(buf, ct, sizeof(ct))) return CRYPT_FAIL_TESTVECTOR;

   return CRYPT_OK;
#endif
}

#endif
