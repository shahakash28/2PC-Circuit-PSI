#pragma once
// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (c) 2021 Microsoft Research
//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Modified by Akash Shah

namespace ENCRYPTO {

struct PsiAnalyticsContext {
  uint16_t port;
  uint32_t role;
  uint64_t bitlen;
  uint64_t neles;
  uint64_t nbins;
  uint64_t nfuns;  // number of hash functions in the hash table
  uint64_t radix;
  double epsilon;
  uint64_t ffuns;
  uint64_t fbins;
  double fepsilon;
  std::string address;

  std::vector<uint64_t> sci_io_start;

  uint64_t sentBytesOPRF;
  uint64_t recvBytesOPRF;
  uint64_t sentBytesHint;
  uint64_t recvBytesHint;
  uint64_t sentBytesSCI;
  uint64_t recvBytesSCI;

  uint64_t sentBytes;
  uint64_t recvBytes;

  enum {
    PSM1,
    PSM2
  } psm_type;

  struct {
    double hashing;
    double base_ots_sci;
    double base_ots_libote;
    double oprf;
    double hint_transmission;
    double hint_computation;
    double psm_time;
    double total;
  } timings;
};

}
