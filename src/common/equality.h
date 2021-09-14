/*
 * Original Work copyright (c) 2021 Microsoft Research
 * Modified Work copyright (c) 2021 Microsoft Research
 *
 * Original Authors: Deevashwer Rathee, Mayank Rathee
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whome the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Modified by Akash Shah
 */
#ifndef EQUALITY_H__
#define EQUALITY_H__
#include "EzPC/SCI/src/OT/emp-ot.h"
#include "EzPC/SCI/src/utils/emp-tool.h"
#include "EzPC/SCI/src/Millionaire/bit-triple-generator.h"
#include <cmath>
#include<ctime>
#include <thread>
#include<bitset>

using namespace sci;
using namespace std;

template<typename IO>
class Equality {
	public:
		IO* io= nullptr;
		sci::OTPack<IO>* otpack;
		TripleGenerator<IO>* triple_gen;
		int party;
		int l, r, log_alpha, beta, beta_pow;
		int num_digits, num_cmps;
		int num_triples;
		uint8_t mask_beta, mask_r;
		Triple* triples_std;
    uint8_t* leaf_eq;
		int total_triples_count, triples_count, triples_count_1;

		Equality(int party,
				int bitlength,
				int log_radix_base,
				int num_cmps,
        IO* io,
				sci::OTPack<IO> *otpack)
		{
			assert(log_radix_base <= 8);
			assert(bitlength <= 64);
			this->party = party;
			this->l = bitlength;
			this->beta = log_radix_base;
			this->num_cmps = num_cmps;
      this->io = io;
      this->otpack = otpack;
      this->triple_gen = new TripleGenerator<IO>(party, io, otpack);
			configure();
		}

		void configure()
		{
			this->num_digits = ceil((double)l/beta);
			this->r = l % beta;
			this->log_alpha = sci::bitlen(num_digits) - 1;
			this->num_triples = num_digits-1;
			if (beta == 8) this->mask_beta = -1;
			else this->mask_beta = (1 << beta) - 1;
			this->mask_r = (1 << r) - 1;
			this->beta_pow = 1 << beta;
			total_triples_count = num_triples*num_cmps;
      //total_triples
			this->triples_std = new Triple(num_triples*num_cmps, true);
		}

		~Equality()
		{
			delete triple_gen;
		}

		void computeLeafOTs(uint64_t* data)
		{

			uint8_t* digits; // num_digits * num_cmps

			digits = new uint8_t[num_digits*num_cmps];
			leaf_eq = new uint8_t[num_digits*num_cmps];

			for(int i = 0; i < num_digits; i++) // Stored from LSB to MSB
				for(int j = 0; j < num_cmps; j++)
					if ((i == num_digits-1) && (r != 0))
						digits[i*num_cmps+j] = (uint8_t)(data[j] >> i*beta) & mask_r;
					else
						digits[i*num_cmps+j] = (uint8_t)(data[j] >> i*beta) & mask_beta;

			if(party == sci::ALICE)
			{
	    	uint8_t** leaf_ot_messages; // (num_digits * num_cmps) X beta_pow (=2^beta)
				leaf_ot_messages = new uint8_t*[num_digits*num_cmps];
				for(int i = 0; i < num_digits*num_cmps; i++)
					leaf_ot_messages[i] = new uint8_t[beta_pow];

				// Set Leaf OT messages
				triple_gen->prg->random_bool((bool*)leaf_eq, num_digits*num_cmps);

				for(int i = 0; i < num_digits; i++) {
					for(int j = 0; j < num_cmps; j++) {
						if (i == (num_digits - 1) && (r > 0)){
#ifdef WAN_EXEC
							set_leaf_ot_messages(leaf_ot_messages[i*num_cmps+j], digits[i*num_cmps+j],
									beta_pow, leaf_eq[i*num_cmps+j]);
#else
						  set_leaf_ot_messages(leaf_ot_messages[i*num_cmps+j], digits[i*num_cmps+j],
									1 << r, leaf_eq[i*num_cmps+j]);
#endif
						}
						else{
							set_leaf_ot_messages(leaf_ot_messages[i*num_cmps+j], digits[i*num_cmps+j],
									beta_pow, leaf_eq[i*num_cmps+j]);
						}
					}
				}
				// Perform Leaf OTs
#ifdef WAN_EXEC
				otpack->kkot_beta->send(leaf_ot_messages, num_cmps*(num_digits), 1);
#else
				if (r == 1) {
					otpack->kkot_beta->send(leaf_ot_messages, num_cmps*(num_digits-1), 1);
					otpack->iknp_straight->send(leaf_ot_messages+num_cmps*(num_digits-1), num_cmps, 1);
				}
				else if (r != 0) {
					otpack->kkot_beta->send(leaf_ot_messages, num_cmps*(num_digits-1), 1);
					if(r == 2){
						otpack->kkot_4->send(leaf_ot_messages+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else if(r == 3){
						otpack->kkot_8->send(leaf_ot_messages+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else if(r == 4){
						otpack->kkot_16->send(leaf_ot_messages+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else{
						throw std::invalid_argument("Not yet implemented!");
					}
				}
				else {
					otpack->kkot_beta->send(leaf_ot_messages, num_cmps*num_digits, 1);
				}
#endif
				// Cleanup
				for(int i = 0; i < num_digits*num_cmps; i++)
					delete[] leaf_ot_messages[i];
				delete[] leaf_ot_messages;
			}
			else // party = sci::BOB
			{
				// Perform Leaf OTs
#ifdef WAN_EXEC
				otpack->kkot_beta->recv(leaf_eq, digits, num_cmps*(num_digits), 1);
#else
				if (r == 1) {
					otpack->kkot_beta->recv(leaf_eq, digits, num_cmps*(num_digits-1), 1);
					otpack->iknp_straight->recv(leaf_eq+num_cmps*(num_digits-1),
							digits+num_cmps*(num_digits-1), num_cmps, 1);
				}
				else if (r != 0) {
					otpack->kkot_beta->recv(leaf_eq, digits, num_cmps*(num_digits-1), 1);
					if(r == 2){
						otpack->kkot_4->recv(leaf_eq+num_cmps*(num_digits-1),
								digits+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else if(r == 3){
						otpack->kkot_8->recv(leaf_eq+num_cmps*(num_digits-1),
								digits+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else if(r == 4){
						otpack->kkot_16->recv(leaf_eq+num_cmps*(num_digits-1),
								digits+num_cmps*(num_digits-1), num_cmps, 1);
					}
					else{
						throw std::invalid_argument("Not yet implemented!");
					}
				}
				else {
					otpack->kkot_beta->recv(leaf_eq, digits, num_cmps*(num_digits), 1);
				}
#endif
			}
			// Cleanup
			delete[] digits;
		}

		void set_leaf_ot_messages(uint8_t* ot_messages,
				uint8_t digit,
				int N,
				uint8_t mask_byte)
		{
			for(int k = 0; k < N; k++) {
					ot_messages[k] = (digit == k) ^ mask_byte;
			}
		}

		/**************************************************************************************************
		 *                         AND computation related functions
		 **************************************************************************************************/

    void generate_triples() {
      triple_gen->generate(party, triples_std, _16KKOT_to_4OT);
    }

		void traverse_and_compute_ANDs(uint8_t* z){
			// Combine leaf OT results in a bottom-up fashion
			int counter_std = 0, old_counter_std = 0;
			int counter_corr = 0, old_counter_corr = 0;
			int counter_combined = 0, old_counter_combined = 0;
			uint8_t* ei = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* fi = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* e = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* f = new uint8_t[(num_triples*num_cmps)/8];

			int old_triple_count=0, triple_count=0;

			for(int i = 1; i < num_digits; i*=2) {
				int counter=0;
				for(int j = 0; j < num_digits and j+i < num_digits; j += 2*i) {
						for(int m=0; m < num_cmps; m+=8) {
							ei[(counter*num_cmps + m)/8] = triples_std->ai[(triple_count+ counter*num_cmps + m)/8];
							fi[(counter*num_cmps + m)/8] = triples_std->bi[(triple_count+ counter*num_cmps + m)/8];
							ei[(counter*num_cmps + m)/8] ^= sci::bool_to_uint8(leaf_eq + j*num_cmps + m, 8);
							fi[(counter*num_cmps + m)/8] ^= sci::bool_to_uint8(leaf_eq + (j+i)*num_cmps + m, 8);
						}
					counter++;
				}
				triple_count += counter*num_cmps;
				int comm_size = (counter*num_cmps)/8;

				if(party == sci::ALICE)
				{
					io->send_data(ei, comm_size);
					io->send_data(fi, comm_size);
					io->recv_data(e, comm_size);
					io->recv_data(f, comm_size);
				}
				else // party = sci::BOB
				{
					io->recv_data(e, comm_size);
					io->recv_data(f, comm_size);
					io->send_data(ei, comm_size);
					io->send_data(fi, comm_size);
				}

				for(int i = 0; i < comm_size; i++) {
					e[i] ^= ei[i];
					f[i] ^= fi[i];
				}

				counter=0;
				for(int j = 0; j < num_digits and j+i < num_digits; j += 2*i) {
          for(int m=0; m < num_cmps; m+=8) {
							uint8_t temp_z;
							if (party == sci::ALICE)
								temp_z = e[(counter*num_cmps + m)/8] & f[(counter*num_cmps + m)/8];
							else
								temp_z = 0;
							temp_z ^= f[(counter*num_cmps + m)/8] & triples_std->ai[(old_triple_count+ counter*num_cmps + m)/8];
							temp_z ^= e[(counter*num_cmps + m)/8] & triples_std->bi[(old_triple_count+ counter*num_cmps + m)/8];
							temp_z ^= triples_std->ci[(old_triple_count+ counter*num_cmps + m)/8];
							sci::uint8_to_bool(leaf_eq + j*num_cmps + m, temp_z, 8);
				   }
					 counter++;
        }
				old_triple_count= triple_count;
			}

			for(int i=0; i<num_cmps; i++) {
				z[i]=leaf_eq[i];
			}

			//cleanup
			delete[] ei;
			delete[] fi;
			delete[] e;
			delete[] f;
		}

		void AND_step_1(uint8_t* ei, // evaluates batch of 8 ANDs
				uint8_t* fi,
				uint8_t* xi,
				uint8_t* yi,
				uint8_t* ai,
				uint8_t* bi,
				int num_ANDs) {
			assert(num_ANDs % 8 == 0);
			for(int i = 0; i < num_ANDs; i+=8) {
				ei[i/8] = ai[i/8];
				fi[i/8] = bi[i/8];
				ei[i/8] ^= sci::bool_to_uint8(xi+i, 8);
				fi[i/8] ^= sci::bool_to_uint8(yi+i, 8);
			}
		}
		void AND_step_2(uint8_t* zi, // evaluates batch of 8 ANDs
				uint8_t* e,
				uint8_t* f,
				uint8_t* ei,
				uint8_t* fi,
				uint8_t* ai,
				uint8_t* bi,
				uint8_t* ci,
				int num_ANDs)
		{
			assert(num_ANDs % 8 == 0);
			for(int i = 0; i < num_ANDs; i+=8) {
				uint8_t temp_z;
				if (party == sci::ALICE)
					temp_z = e[i/8] & f[i/8];
				else
					temp_z = 0;
				temp_z ^= f[i/8] & ai[i/8];
				temp_z ^= e[i/8] & bi[i/8];
				temp_z ^= ci[i/8];
				sci::uint8_to_bool(zi+i, temp_z, 8);
			}
		}
};

void equality_thread(int tid, int party, uint64_t* x, uint8_t* z, int lnum_cmps, int l, int b, sci::NetIO* io, sci::OTPack<sci::NetIO>* otpack) {
    Equality<NetIO>* compare;
    if(tid & 1) {
        compare = new Equality<NetIO>(3-party, l, b, lnum_cmps, io, otpack);
    } else {
        compare = new Equality<NetIO>(party, l, b, lnum_cmps, io, otpack);
    }
    compare->computeLeafOTs(x);
    compare->generate_triples();

    compare->traverse_and_compute_ANDs(z);
    delete compare;
    return;
}


void perform_equality(uint64_t* x, int party, int l, int b, int num_cmps, string address, int port, uint8_t* z, sci::NetIO** ioArr, OTPack<sci::NetIO>** otpackArr) {
    uint64_t mask_l;
    if (l == 64) mask_l = -1;
    else mask_l = (1ULL << l) - 1;

    std::thread cmp_threads[2];
    int chunk_size = (num_cmps/(8*2))*8;

    for (int i = 0; i < 2; ++i) {
        int offset = i*chunk_size;
        int lnum_cmps;
        if (i == (2 - 1)) {
            lnum_cmps = num_cmps - offset;
        } else {
            lnum_cmps = chunk_size;
        }
        cmp_threads[i] = std::thread(equality_thread, i, party, x+offset, z+offset, lnum_cmps, l, b, ioArr[i], otpackArr[i]);
    }

    for (int i = 0; i < 2; ++i) {
      cmp_threads[i].join();
    }

    for (int i = 0; i < 2; i++) {
        delete otpackArr[i];
    }
}

#endif //EQUALITY_H__
