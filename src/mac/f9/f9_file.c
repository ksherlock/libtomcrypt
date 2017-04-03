/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file f9_file.c
  f9 support, process a file, Tom St Denis
*/

#ifdef LTC_F9_MODE

/**
   f9 a file
   @param cipher   The index of the cipher desired
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @param filename The name of the file you wish to f9
   @param out      [out] Where the authentication tag is to be stored
   @param outlen   [in/out] The max size and resulting size of the authentication tag
   @return CRYPT_OK if successful, CRYPT_NOP if file support has been disabled
*/
int f9_file(int cipher,
              const unsigned char *key, unsigned long keylen,
              const char *filename,
                    unsigned char *out, unsigned long *outlen)
{
#ifdef LTC_NO_FILE
   return CRYPT_NOP;
#else
   size_t x;
   int err;
   f9_state f9;
   FILE *in;
   unsigned char *buf;

   LTC_ARGCHK(key      != NULL);
   LTC_ARGCHK(filename != NULL);
   LTC_ARGCHK(out      != NULL);
   LTC_ARGCHK(outlen   != NULL);

   if ((buf = XMALLOC(LTC_FILE_READ_BUFSIZE)) == NULL) {
      return CRYPT_MEM;
   }

   in = fopen(filename, "rb");
   if (in == NULL) {
      err = CRYPT_FILE_NOTFOUND;
      goto LBL_ERR;
   }

   if ((err = f9_init(&f9, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      goto LBL_ERR;
   }

   do {
      x = fread(buf, 1, LTC_FILE_READ_BUFSIZE, in);
      if ((err = f9_process(&f9, buf, (unsigned long)x)) != CRYPT_OK) {
         fclose(in);
         goto LBL_ERR;
      }
   } while (x == LTC_FILE_READ_BUFSIZE);
   fclose(in);

   err = f9_done(&f9,    out, outlen);

LBL_ERR:
   XFREE(buf);
   return err;
#endif
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
