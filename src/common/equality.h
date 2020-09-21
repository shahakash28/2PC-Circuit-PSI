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
			//this->triples_std_1 = new Triple((num_triples)*batch_size*num_cmps, true);
		}

		~Equality()
		{
			delete triple_gen;
		}

		void computeLeafOTs(uint64_t* data)
		{

			struct timespec start, finish, lomstart, lomfinish, locstart, locfinish;

			clock_gettime(CLOCK_MONOTONIC, &start);
			uint8_t* digits; // num_digits * num_cmps

			digits = new uint8_t[num_digits*num_cmps];
			leaf_eq = new uint8_t[num_digits*num_cmps];
      /*std::cout<<"Some inputs inside are: "<<std::endl;
      for(int i=0;i<10;i++)
        std::cout<<data[i]<<std::endl;
      std::cout<<"+++++++++++++++++"<<std::endl;*/

			// Extract radix-digits from data
			for(int i = 0; i < num_digits; i++) // Stored from LSB to MSB
				for(int j = 0; j < num_cmps; j++)
					if ((i == num_digits-1) && (r != 0))
						digits[i*num_cmps+j] = (uint8_t)(data[j] >> i*beta) & mask_r;
					else
						digits[i*num_cmps+j] = (uint8_t)(data[j] >> i*beta) & mask_beta;
      /*std::cout<<"Some digits:"<<std::endl;
			for(int i=0; i<10; i++) {
				for(int j=0; j<num_digits; j++) {
					std::cout<< (int)digits[j*num_cmps+i]<<" ";
				}
				std::cout<<std::endl;
			}
			std::cout<<"+++++++++++++++"<<std::endl;*/

			if(party == sci::ALICE)
			{
	    	uint8_t** leaf_ot_messages; // (num_digits * num_cmps) X beta_pow (=2^beta)
				leaf_ot_messages = new uint8_t*[num_digits*num_cmps];
				for(int i = 0; i < num_digits*num_cmps; i++)
					leaf_ot_messages[i] = new uint8_t[beta_pow];

        clock_gettime(CLOCK_MONOTONIC, &lomstart);
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
				clock_gettime(CLOCK_MONOTONIC, &lomfinish);

				clock_gettime(CLOCK_MONOTONIC, &locstart);

				// Perform Leaf OTs
				//cout<<"I am Sender in Leaf OT"<<endl;
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
				clock_gettime(CLOCK_MONOTONIC, &locfinish);
				double total_time = (lomfinish.tv_sec - lomstart.tv_sec);
				total_time += (lomfinish.tv_nsec - lomstart.tv_nsec) / 1000000000.0;
				std::cout<<"Leaf OT Message Time: "<<total_time<<std::endl;
				total_time = (locfinish.tv_sec - locstart.tv_sec);
				total_time += (locfinish.tv_nsec - locstart.tv_nsec) / 1000000000.0;
				std::cout<<"Leaf OT Comm. Time "<<total_time<<std::endl;

			}
			else // party = sci::BOB
			{ //triple_gen->generate(3-party, triples_std, _16KKOT_to_4OT);
				// Perform Leaf OTs
				//cout<<"I am receiver in Leaf OT"<<endl;
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

				// Extract equality result from leaf_res_cmp
				/*for(int i = 0; i < num_digits*num_cmps; i++) {
		      for(int j=batch_size-1; j>= 0; j--) {
						leaf_eq[j*num_digits*num_cmps+ i] = (leaf_eq[i]>>j) & 1;
					}
				}*/
			}

			clock_gettime(CLOCK_MONOTONIC, &finish);
			double total_time = (finish.tv_sec - start.tv_sec);
  		total_time += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
      std::cout<<"Leaf OT-Time: "<<total_time<<std::endl;

      /*std::cout<<"Some leaf ot messages:"<<std::endl;
			for(int i=0; i<10; i++) {
				for(int j=0; j<num_digits; j++) {
					std::cout<< (int)leaf_eq[j*num_cmps+i]<<" ";
				}
				std::cout<<std::endl;
			}
			std::cout<<"+++++++++++++++"<<std::endl;*/
			/*for (int i = 0; i < num_cmps; i++)
				res[i] = leaf_res_cmp[i];
     */
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
			struct timespec start, finish;
			clock_gettime(CLOCK_MONOTONIC, &start);
      triple_gen->generate(party, triples_std, _16KKOT_to_4OT);
			clock_gettime(CLOCK_MONOTONIC, &finish);
			double total_time = (finish.tv_sec - start.tv_sec);
  		total_time += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
      std::cout<<"Triple Generation Time: "<<total_time<<std::endl;
    }

		void traverse_and_compute_ANDs(uint8_t* z){

			struct timespec start, finish, lomstart, lomfinish, locstart, locfinish;

			//if(sci::ALICE) {

			//}

			//std::cout << "Num Triples are: " << num_triples<< std::endl;

			clock_gettime(CLOCK_MONOTONIC, &start);

			//clock_gettime(CLOCK_MONOTONIC, &start);
			// Combine leaf OT results in a bottom-up fashion
			int counter_std = 0, old_counter_std = 0;
			int counter_corr = 0, old_counter_corr = 0;
			int counter_combined = 0, old_counter_combined = 0;
			uint8_t* ei = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* fi = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* e = new uint8_t[(num_triples*num_cmps)/8];
			uint8_t* f = new uint8_t[(num_triples*num_cmps)/8];
      //std::cout<<"Size of auxes: "<< (num_triples*num_cmps)/8 <<std::endl;

			int old_triple_count=0, triple_count=0;

			for(int i = 1; i < num_digits; i*=2) {
				int counter=0;
				for(int j = 0; j < num_digits and j+i < num_digits; j += 2*i) {
						for(int m=0; m < num_cmps; m+=8) {
							//std::cout<<"Comparison Number "<< m << std::endl;
							/*if(m==0) {
								std::cout<<"Let us check beaver triples"<<std::endl;
								std::cout<<"a [j="<<j<<"]: "<<std::bitset<8>(triples_std->ai[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
								std::cout<<"b [j="<<j<<"]: "<<std::bitset<8>(triples_std->bi[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
								std::cout<<"c [j="<<j<<"]: "<<std::bitset<8>(triples_std->ci[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
							}*/
							ei[(counter*num_cmps + m)/8] = triples_std->ai[(triple_count+ counter*num_cmps + m)/8];
							fi[(counter*num_cmps + m)/8] = triples_std->bi[(triple_count+ counter*num_cmps + m)/8];
							/*if(m==0) {
								std::cout<<"ei [j="<<j<<"]: "<<std::bitset<8>(ei[(counter*num_cmps + m)/8])<<std::endl;
								std::cout<<"fi [j="<<j<<"]: "<<std::bitset<8>(fi[(counter*num_cmps + m)/8])<<std::endl;
							}*/
							ei[(counter*num_cmps + m)/8] ^= sci::bool_to_uint8(leaf_eq + j*num_cmps + m, 8);
							fi[(counter*num_cmps + m)/8] ^= sci::bool_to_uint8(leaf_eq + (j+i)*num_cmps + m, 8);
							/*if(m==0) {
								std::cout<<"ei [j="<<j<<"]: "<<std::bitset<8>(ei[(counter*num_cmps + m)/8])<<std::endl;
								std::cout<<"fi [j="<<j<<"]: "<<std::bitset<8>(fi[(counter*num_cmps + m)/8])<<std::endl;
							}*/
						}
					counter++;
				}
				triple_count += counter*num_cmps;
				int comm_size = (counter*num_cmps)/8;
        //std::cout<<

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
					/*if(i%(num_cmps/8)==0) {
            std::cout<<"e [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(e[i])<<std::endl;
						std::cout<<"f [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(f[i])<<std::endl;

            std::cout<<"ei [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(ei[i])<<std::endl;
						std::cout<<"fi [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(fi[i])<<std::endl;
					}*/
					e[i] ^= ei[i];
					f[i] ^= fi[i];
					/*if(i%(num_cmps/8)==0) {
						std::cout<<"e [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(e[i])<<std::endl;
						std::cout<<"f [j="<<i/(num_cmps/8)<<"]: "<<std::bitset<8>(f[i])<<std::endl;
					}*/
				}

				counter=0;
				for(int j = 0; j < num_digits and j+i < num_digits; j += 2*i) {
          for(int m=0; m < num_cmps; m+=8) {
							uint8_t temp_z;
							if (party == sci::ALICE)
								temp_z = e[(counter*num_cmps + m)/8] & f[(counter*num_cmps + m)/8];
							else
								temp_z = 0;
							/*if(m==0) {
	 							 std::cout<<"temp_z [j="<<j<<"]: "<<std::bitset<8>(temp_z)<<std::endl;
	 						 }*/

							temp_z ^= f[(counter*num_cmps + m)/8] & triples_std->ai[(old_triple_count+ counter*num_cmps + m)/8];
							/*if(m==0) {
	 							 std::cout<<"temp_z [j="<<j<<"]: "<<std::bitset<8>(temp_z)<<std::endl;
	 						 }*/
							temp_z ^= e[(counter*num_cmps + m)/8] & triples_std->bi[(old_triple_count+ counter*num_cmps + m)/8];
							/*if(m==0) {
	 							 std::cout<<"temp_z [j="<<j<<"]: "<<std::bitset<8>(temp_z)<<std::endl;
	 						 }*/
							temp_z ^= triples_std->ci[(old_triple_count+ counter*num_cmps + m)/8];
							/*if(m==0) {
	 							 std::cout<<"temp_z [j="<<j<<"]: "<<std::bitset<8>(temp_z)<<std::endl;
	 						 }*/

               /*if(m==0) {
								 std::cout<<"Let us check beaver triples"<<std::endl;
								 std::cout<<"Triples Id: "<< (old_triple_count+ counter*num_cmps + m)/8 <<std::endl;
 	 							 std::cout<<"a [j="<<j<<"]: "<<std::bitset<8>(triples_std->ai[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
                 std::cout<<"b [j="<<j<<"]: "<<std::bitset<8>(triples_std->bi[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
                 std::cout<<"c [j="<<j<<"]: "<<std::bitset<8>(triples_std->ci[(old_triple_count+ counter*num_cmps + m)/8])<<std::endl;
 	 						 }*/
							sci::uint8_to_bool(leaf_eq + j*num_cmps + m, temp_z, 8);
				   }
					 counter++;
        }
        /*std::cout<<"Some leaf ot messages: Level " << i<<std::endl;
  			for(int i=0; i<10; i++) {
  				for(int j=0; j<num_digits; j++) {
  					std::cout<< (int)leaf_eq[j*num_cmps+i]<<" ";
  				}
  				std::cout<<std::endl;
  			}
  			std::cout<<"+++++++++++++++"<<std::endl;*/
				old_triple_count= triple_count;
			}

			clock_gettime(CLOCK_MONOTONIC, &finish);
			double total_time = (finish.tv_sec - start.tv_sec);
  		total_time += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
      std::cout<<"AND Time: "<<total_time<<std::endl;

			//std::cout<<"Some Outputs"<< std::endl;

			for(int i=0; i<num_cmps; i++) {
				z[i]=leaf_eq[i];
        //std::cout<<(int)leaf_eq[i]<<std::endl;
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
    //if(tid == 0) {
    /*std::cout<<"Some inputs are: "<<std::endl;
    for(int i=0;i<10;i++)
      std::cout<<x[i]<<std::endl;
    std::cout<<"+++++++++++++++++"<<std::endl;*/
    compare->computeLeafOTs(x);
    compare->generate_triples();

    compare->traverse_and_compute_ANDs(z);
    //}
    delete compare;
    return;
}


void perform_equality(uint64_t* x, int party, int l, int b, int num_cmps, string address, int port, uint8_t* z, sci::NetIO** ioArr, OTPack<sci::NetIO>** otpackArr) {
    uint64_t mask_l;
    if (l == 64) mask_l = -1;
    else mask_l = (1ULL << l) - 1;

  /*uint64_t comm_sent = 0;
	uint64_t multiThreadedIOStart[2];
	for(int i=0;i<2;i++){
		multiThreadedIOStart[i] = ioArr[i]->counter;
	}*/

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
        delete ioArr[i];
        delete otpackArr[i];
    }
    /************** Verification ****************/
    /********************************************/
   /*
    switch (party) {
        case sci::ALICE: {
            ioArr[0]->send_data(x, 8*num_cmps);
            ioArr[0]->send_data(z, num_cmps);
            break;
        }
        case sci::BOB: {
            uint64_t *xi = new uint64_t[num_cmps];
            uint8_t *zi = new uint8_t[num_cmps];
            xi = new uint64_t[num_cmps];
            zi = new uint8_t[num_cmps];
            ioArr[0]->recv_data(xi, 8*num_cmps);
            ioArr[0]->recv_data(zi, num_cmps);
            for(int i = 0; i < num_cmps; i++) {
                zi[i] ^= z[i];
                assert(zi[i] == ((xi[i] & mask_l) > (x[i] & mask_l)));
            }
            cout << "Secure Comparison Successful" << endl;
            delete[] xi;
            delete[] zi;
            break;
        }
    }
    delete[] x;
    delete[] z;*/

    /**** Process & Write Benchmarking Data *****/
    /********************************************/
    /*
    string file_addr;
    switch (party) {
        case 1: {
            file_addr = "millionaire-P0.csv";
            break;
        }
        case 2: {
            file_addr = "millionaire-P1.csv";
            break;
        }
    }
    bool write_title = true; {
        fstream result(file_addr.c_str(), fstream::in);
        if(result.is_open())
            write_title = false;
        result.close();
    }
    fstream result(file_addr.c_str(), fstream::out|fstream::app);
    if(write_title){
        result << "Bitlen,Base,Batch Size,#Threads,#Comparisons,Time (mus),Throughput/sec" << endl;
    }
    result << l << "," << b << "," << batch_size << "," << num_threads << "," << num_cmps
        << "," << t << "," << (double(num_cmps)/t)*1e6 << endl;
    result.close();
    */
    /******************* Cleanup ****************/
    /********************************************/

}

#endif //EQUALITY_H__
