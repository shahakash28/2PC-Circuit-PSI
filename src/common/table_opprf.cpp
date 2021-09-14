/*
 * \author Akash Shah
 * \email akashshah08@outlook.com
 * \organization Microsoft Research India
 *
 * \copyright the MIT License. Copyright (c) 2021 Microsoft Research
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell sopies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "table_opprf.h"
#include <openssl/sha.h>
#include <random>
#include<cstring>

std::uint64_t hashToPosition(std::uint64_t element, osuCrypto::block nonce) {
  SHA_CTX ctx;
  unsigned char hash[SHA_DIGEST_LENGTH];

  unsigned char* message=(unsigned char*)malloc(sizeof(uint64_t)+sizeof(osuCrypto::block));
  memcpy(message, &element,sizeof(uint64_t));
  memcpy(message+sizeof(uint64_t), &nonce, sizeof(osuCrypto::block));

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, message, sizeof(uint64_t)+sizeof(osuCrypto::block));
  SHA1_Final(hash, &ctx);

  uint64_t result = 0;
  std::copy(hash, hash + sizeof(result), reinterpret_cast<unsigned char*>(&result));

  return result;
}
