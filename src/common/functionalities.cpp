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

#include "functionalities.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"

#include "ots/ots.h"
#include "polynomials/Poly.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/common/hash_table_entry.h"
#include "HashingTables/common/hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "config.h"
#include "batch_equality.h"
#include "equality.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>
#include <unordered_map>
#include <cmath>
#include "table_opprf.h"

#include <openssl/sha.h>

struct hashlocmap {
  int bin;
  int index;
};

std::vector<uint64_t> content_of_bins;

namespace ENCRYPTO {

using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context) {
  // establish network connection
  std::unique_ptr<CSocket> sock =
    EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  sci::NetIO* ioArr[2];
  sci::OTPack<sci::NetIO> *otpackArr[2];

  int party=1;
  if(context.role == 0) {
    party=2;
  }

  //Config
  int l= (int)context.bitlen;
  int b= (int)context.nmegabins;

  ioArr[0] = new NetIO(party==1 ? nullptr:context.address.c_str(), context.port+1);
  ioArr[1] = new NetIO(party==1 ? nullptr:context.address.c_str(), context.port+2);

  const auto clock_time_total_start = std::chrono::system_clock::now();
  otpackArr[0] = new OTPack<NetIO>(ioArr[0], party, b, l);
  otpackArr[1] = new OTPack<NetIO>(ioArr[1], 3-party, b, l);
  BatchEquality<NetIO>* compare;
  // create hash tables from the elements
  int num_cmps, rmdr;
  rmdr = context.nbins % 8;
  num_cmps = context.nbins + rmdr;
  int pad;
  uint64_t value;
  if(context.role == 0) {
    pad = rmdr;
    value = S_CONST;
  } else {
    pad = 3*rmdr;
    value = C_CONST;
  }

  compare = new BatchEquality<NetIO>(party, l, b, 3, num_cmps, ioArr[0], ioArr[1], otpackArr[0], otpackArr[1]);

  if (context.role == CLIENT) {
    content_of_bins.reserve(3*num_cmps);
    //OpprgPsiClient(inputs, context);
    const auto start_time = std::chrono::system_clock::now();
    const auto hashing_start_time = std::chrono::system_clock::now();

    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
    cuckoo_table.SetNumOfHashFunctions(context.nfuns);
    cuckoo_table.Insert(inputs);
    cuckoo_table.MapElements();
    //cuckoo_table.Print();

    if (cuckoo_table.GetStashSize() > 0u) {
      std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
    }

    /*ofstream file1 ("cuckoo_table_contents", ios::out);
    std::cout<<"Cuckoo Hash Table"<<std::endl;
    for(int i=0; i<context.nbins; i++){
      std::cout << cuckoo_table.hash_table_.at(i).GetElement() <<std::endl;
      file1 << cuckoo_table.hash_table_.at(i).GetElement();
      file1 << " ";
    }
    file1.close();*/

    auto cuckoo_table_v = cuckoo_table.AsRawVector();

    const auto hashing_end_time = std::chrono::system_clock::now();
    const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
    context.timings.hashing = hashing_duration.count();
    const auto oprf_start_time = std::chrono::system_clock::now();

    auto masks_with_dummies = ot_receiver(cuckoo_table_v, context, false);

    const auto oprf_end_time = std::chrono::system_clock::now();
    const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
    context.timings.oprf = oprf_duration.count();
    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<masks_with_dummies[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;
    */

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      osuCrypto::PRNG prng(masks_with_dummies[i], 2);
      for(int j=0;j<3;j++) {
            std::cout<<"( "<<i<<"-"<< j<<", "<<prng.get<uint64_t>()<<"), ";
      }
        std::cout<<"\n";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::vector<uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);
    std::unique_ptr<CSocket> sock =
        EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    const auto ftrans_start_time = std::chrono::system_clock::now();
    sock->Receive(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
    sock->Close();
    const auto ftrans_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
    context.timings.polynomials_transmission = polynomial_trans.count();
    const auto filter_start_time = std::chrono::system_clock::now();
    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
    for(int i=0;i<context.fbins;i++) {
      std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    ENCRYPTO::CuckooTable garbled_cuckoo_table(static_cast<std::size_t>(context.fbins));
    garbled_cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    garbled_cuckoo_table.Insert(cuckoo_table_v);
    auto addresses = garbled_cuckoo_table.GetElementAddresses();

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Addresses are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      for(int j=0;j<context.ffuns;j++) {
        std::cout<<"( "<<i<<"-"<<j<<", "<<addresses[i*context.ffuns+j]<<"), ";
      }
      std::cout<<"\n";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    for(int i=0; i<context.nbins; i++) {
      osuCrypto::PRNG prngo(masks_with_dummies[i], 2);
      for(int j=0; j< context.ffuns; j++) {
        content_of_bins[i*context.ffuns + j]=garbled_cuckoo_filter[addresses[i*context.ffuns+j]] ^ prngo.get<uint64_t>();
      }
    }
    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Contents of Bins are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      for(int j=0;j<context.ffuns;j++) {
        std::cout<<"( "<<i<<", "<<content_of_bins[i*context.ffuns+j]<<"), ";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
    const auto filter_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_duration = filter_end_time - filter_start_time;
    context.timings.polynomials = polynomial_duration.count();
    //return content_of_bins;
    uint8_t* res_shares;
    const auto clock_time_cir_start = std::chrono::system_clock::now();
      for(int i=0; i<pad; i++) {
        content_of_bins[3*context.nbins+i]=value;
      }

      perform_batch_equality(content_of_bins.data(), compare, res_shares);
      const auto clock_time_cir_end = std::chrono::system_clock::now();
      const duration_millis cir_duration = clock_time_cir_end - clock_time_cir_start;
      context.timings.aby_total = cir_duration.count();
      const auto clock_time_total_end = std::chrono::system_clock::now();
      const duration_millis total_duration = clock_time_total_end - clock_time_total_start;
      context.timings.total = total_duration.count();
  } else {
    content_of_bins.reserve(num_cmps);
    //OpprgPsiServer(inputs, context);
    const auto start_time = std::chrono::system_clock::now();

    const auto hashing_start_time = std::chrono::system_clock::now();

    ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
    simple_table.SetNumOfHashFunctions(context.nfuns);
    simple_table.Insert(inputs);
    simple_table.MapElements();
    //simple_table.Print();

    auto simple_table_v = simple_table.AsRaw2DVector();
    // context.simple_table = simple_table_v;

    const auto hashing_end_time = std::chrono::system_clock::now();
    const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
    context.timings.hashing = hashing_duration.count();

    const auto oprf_start_time = std::chrono::system_clock::now();

    auto masks = ot_sender(simple_table_v, context, false);

    const auto oprf_end_time = std::chrono::system_clock::now();
    const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
    context.timings.oprf = oprf_duration.count();

    /*std::cout<<"Size of Hash Table:"<< context.nbins <<std::endl;

    std::cout<<"***********************************"<<std::endl;
    std::cout<<"The OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      uint64_t size = masks[i].size();
      for(int j=0;j<size;j++) {
        std::cout<<"( "<<i<<", "<<masks[i][j]<<"), ";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
   const auto filter_start_time = std::chrono::system_clock::now();
    uint64_t bufferlength = (uint64_t)ceil(context.nbins/2.0);
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed(), bufferlength);

    for( int i=0; i<context.nbins; i++) {
      content_of_bins[i] = prng.get<uint64_t>();
    }

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Bin Random Values are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<content_of_bins[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::unordered_map<uint64_t,hashlocmap> tloc;
    std::vector<uint64_t> filterinputs;
    for(int i=0; i<context.nbins; i++) {
      int binsize = simple_table_v[i].size();
      for(int j=0; j<binsize; j++) {
        tloc[simple_table_v[i][j]].bin = i;
        tloc[simple_table_v[i][j]].index = j;
        filterinputs.push_back(simple_table_v[i][j]);
      }
    }

    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.fbins));
    cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    cuckoo_table.Insert(filterinputs);
    cuckoo_table.MapElements();
    //cuckoo_table.Print();

    if (cuckoo_table.GetStashSize() > 0u) {
      std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
    }

    std::vector<uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);

    bufferlength = (uint64_t)ceil(context.fbins - 3*context.nbins);
    osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      uint64_t size = masks[i].size();
      for(int j=0;j<size;j++) {
        osuCrypto::PRNG prng(masks[i][j], 2);
        for(int k=0;k<3;k++){
            std::cout<<"( "<<i<<"-"<< j<<"-"<< k <<", "<<prng.get<uint64_t>()<<"), ";
        }
        std::cout<<"\n";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    for(int i=0; i<context.fbins; i++){
      if(!cuckoo_table.hash_table_.at(i).IsEmpty()) {
        uint64_t element = cuckoo_table.hash_table_.at(i).GetElement();
        uint64_t function_id = cuckoo_table.hash_table_.at(i).GetCurrentFunctinId();
        hashlocmap hlm = tloc[element];
        osuCrypto::PRNG prng(masks[hlm.bin][hlm.index], 2);
        uint64_t pad = 0u;
        for(int j=0;j<=function_id;j++) {
           pad = prng.get<uint64_t>();
        }
        garbled_cuckoo_filter[i] = content_of_bins[hlm.bin] ^ pad;
      } else {
        garbled_cuckoo_filter[i] = prngo.get<uint64_t>();
      }
    }
    const auto filter_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_duration = filter_end_time - filter_start_time;
    context.timings.polynomials = polynomial_duration.count();

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
    for(int i=0;i<context.fbins;i++) {
      std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::unique_ptr<CSocket> sock =
        EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    const auto ftrans_start_time = std::chrono::system_clock::now();
    std::cout<<"Hint Size: "<< context.fbins * sizeof(uint64_t)<< endl;
    sock->Send(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
    const auto ftrans_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
    context.timings.polynomials_transmission = polynomial_trans.count();
    sock->Close();

    uint8_t* res_shares;
    const auto clock_time_cir_start = std::chrono::system_clock::now();
      for(int i=0; i<pad; i++) {
        content_of_bins[context.nbins+i]=value;
      }

    perform_batch_equality(content_of_bins.data(), compare, res_shares);
    const auto clock_time_cir_end = std::chrono::system_clock::now();
    const duration_millis cir_duration = clock_time_cir_end - clock_time_cir_start;
    context.timings.aby_total = cir_duration.count();
    const auto clock_time_total_end = std::chrono::system_clock::now();
    const duration_millis total_duration = clock_time_total_end - clock_time_total_start;
    context.timings.total = total_duration.count();

  }




  /*for(int i=0; i<context.nbins; i++) {
      for(int i)
  }*/
  /*

  // instantiate ABY
  ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                 context.nthreads);
  party.ConnectAndBaseOTs();
  auto bc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_BOOL)->GetCircuitBuildRoutine());  // GMW circuit
  assert(bc);

  share_ptr s_in_server, s_in_client;

  // share inputs in ABY
  if (context.role == SERVER) {
    s_in_server = share_ptr(bc->PutSIMDINGate(content_of_bins.size(), content_of_bins.data(), context.maxbitlen, SERVER));
    s_in_client = share_ptr(bc->PutDummySIMDINGate(content_of_bins.size(), context.maxbitlen));
  } else {
    s_in_server = share_ptr(bc->PutDummySIMDINGate(content_of_bins.size(), context.maxbitlen));
    s_in_client = share_ptr(bc->PutSIMDINGate(content_of_bins.size(), content_of_bins.data(), context.maxbitlen, CLIENT));
  }

  // compare outputs of OPPRFs for each bin in ABY (using SIMD)
  auto s_eq = share_ptr(bc->PutEQGate(s_in_server.get(), s_in_client.get()));

  std::vector<share_ptr> bin_results;
  for (uint32_t i = 0; i < content_of_bins.size(); ++i) {
    uint32_t pos[] = {i};
    bin_results.emplace_back(bc->PutSubsetGate(s_eq.get(), pos, 1));
    bin_results.at(i) = share_ptr(bc->PutOUTGate(bin_results.at(i).get(), ALL));
  }

  share_ptr s_out;
  auto t_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.threshold)));
  auto s_threshold = share_ptr(bc->PutCONSGate(context.threshold, t_bitlen));
  std::uint64_t const_zero = 0;
  auto s_zero = share_ptr(bc->PutCONSGate(const_zero, 1));

  if (context.analytics_type == PsiAnalyticsContext::NONE) {
    // we want to only do benchmarking, so no additional operations
  } else if (context.analytics_type == PsiAnalyticsContext::THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    s_out = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM_IF_GT_THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    auto s_gt_t = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
    s_out = share_ptr(bc->PutMUXGate(s_out.get(), s_zero.get(), s_gt_t.get()));
  } else {
    throw std::runtime_error("Encountered an unknown analytics type");
  }

  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
  }

  party.ExecCircuit();

  uint64_t output = 0;
  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    output = s_out->get_clear_value<uint64_t>();
  }

  context.timings.aby_setup = party.GetTiming(P_SETUP);
  context.timings.aby_online = party.GetTiming(P_ONLINE);
  context.timings.aby_total = context.timings.aby_setup + context.timings.aby_online;
  context.timings.base_ots_aby = party.GetTiming(P_BASE_OT);

  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();
  */
  uint64_t output = 0;
  return output;
}

uint64_t run_gcf_tab_psi(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context) {
  // establish network connection
  std::unique_ptr<CSocket> sock =
    EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  int party=1;
  if(context.role == 0) {
    party=2;
  }

  sci::NetIO* ioArr[2];
  sci::OTPack<sci::NetIO> *otpackArr[2];
  int b = (int)context.nmegabins;
  string address1 = context.address;
  for(int i=0; i<2; i++)
    ioArr[i] = new NetIO(party==1 ? nullptr:address1.c_str(), context.port+1+i);
  const auto clock_time_total_start = std::chrono::system_clock::now();
  for(int i = 0; i < 2; i++) {
        if (i == 0) {
            otpackArr[i] = new OTPack<NetIO>(ioArr[i], party, b, context.bitlen);
        } else if (i == 1) {
            otpackArr[i] = new OTPack<NetIO>(ioArr[i], 3-party, b, context.bitlen);
        }
    }

    std::cout << "All Base OTs Done" << std::endl;

  // create hash tables from the elements
  int num_cmps, rmdr;
  rmdr = context.nbins % 8;
  num_cmps = context.nbins + rmdr;
  int pad;
  uint64_t value;
  if(context.role == 0) {
    pad = rmdr;
    value = S_CONST;
  } else {
    pad = rmdr;
    value = C_CONST;
  }

  if (context.role == CLIENT) {
    /*********************Hashing*******************/
    const auto start_time = std::chrono::system_clock::now();
    const auto hashing_start_time = std::chrono::system_clock::now();

    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
    cuckoo_table.SetNumOfHashFunctions(context.nfuns);
    cuckoo_table.Insert(inputs);
    cuckoo_table.MapElements();
    //cuckoo_table.Print();

    if (cuckoo_table.GetStashSize() > 0u) {
      std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
    }

    /*ofstream file1 ("cuckoo_table_contents", ios::out);
    std::cout<<"Cuckoo Hash Table"<<std::endl;
    for(int i=0; i<context.nbins; i++){
      std::cout << cuckoo_table.hash_table_.at(i).GetElement() <<std::endl;
      file1 << cuckoo_table.hash_table_.at(i).GetElement();
      file1 << " ";
    }
    file1.close();*/

    auto cuckoo_table_v = cuckoo_table.AsRawVector();

    const auto hashing_end_time = std::chrono::system_clock::now();
    const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
    context.timings.hashing = hashing_duration.count();

    /*********************OPRF 1*******************/
    const auto oprf_start_time = std::chrono::system_clock::now();
    auto masks_with_dummies = ot_receiver(cuckoo_table_v, context, false);
    const auto oprf_end_time = std::chrono::system_clock::now();
    const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
    context.timings.oprf = oprf_duration.count();
    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<masks_with_dummies[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;
    */

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      osuCrypto::PRNG prng(masks_with_dummies[i], 2);
      for(int j=0;j<3;j++) {
            std::cout<<"( "<<i<<"-"<< j<<", "<<prng.get<uint64_t>()<<"), ";
      }
        std::cout<<"\n";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
    /*********************Hint Computation*******************/
    std::vector<uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);
    std::unique_ptr<CSocket> sock =
        EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    const auto ftrans_start_time = std::chrono::system_clock::now();
    sock->Receive(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
    sock->Close();
    const auto ftrans_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
    context.timings.polynomials_transmission = polynomial_trans.count();
    const auto filter_start_time = std::chrono::system_clock::now();
    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
    for(int i=0;i<context.fbins;i++) {
      std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    ENCRYPTO::CuckooTable garbled_cuckoo_table(static_cast<std::size_t>(context.fbins));
    garbled_cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    garbled_cuckoo_table.Insert(cuckoo_table_v);
    auto addresses = garbled_cuckoo_table.GetElementAddresses();

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Addresses are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      for(int j=0;j<context.ffuns;j++) {
        std::cout<<"( "<<i<<"-"<<j<<", "<<addresses[i*context.ffuns+j]<<"), ";
      }
      std::cout<<"\n";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
    //content_of_bins.reserve(3*num_cmps);
    std::vector<std::vector<uint64_t>> opprf_values(context.nbins, std::vector<uint64_t>(context.ffuns));

    for(int i=0; i<context.nbins; i++) {
      osuCrypto::PRNG prngo(masks_with_dummies[i], 2);
      for(int j=0; j< context.ffuns; j++) {
        opprf_values[i][j]=garbled_cuckoo_filter[addresses[i*context.ffuns+j]] ^ prngo.get<uint64_t>();
      }
    }

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Contents of Bins are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      for(int j=0;j<context.ffuns;j++) {
        std::cout<<"( "<<i<<", "<<opprf_values[i][j]<<"), ";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    const auto filter_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_duration = filter_end_time - filter_start_time;
    context.timings.polynomials = polynomial_duration.count();

    /***************Table OPPRF*********************/
    const int ts=4;

    const auto oprf2_start_time = std::chrono::system_clock::now();
    auto table_masks = ot_sender(opprf_values, context, true);
    const auto oprf2_end_time = std::chrono::system_clock::now();
    const duration_millis oprf2_duration = oprf2_end_time - oprf2_start_time;
    context.timings.oprf2 = oprf2_duration.count();


    const auto table_start_time = std::chrono::system_clock::now();
    uint64_t bufferlength = (uint64_t)ceil(context.nbins/2.0);
    osuCrypto::PRNG tab_prng(osuCrypto::sysRandomSeed(), bufferlength);

    content_of_bins.reserve(num_cmps);
    for( int i=0; i<context.nbins; i++) {
      content_of_bins[i] = tab_prng.get<uint64_t>();
    }

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The actual contents are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<content_of_bins[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::vector<osuCrypto::block> padding_vals;
    padding_vals.reserve(num_cmps);
    std::vector<uint64_t> table_opprf;
    table_opprf.reserve(ts*num_cmps);
    osuCrypto::PRNG padding_prng(osuCrypto::sysRandomSeed(), 2*num_cmps);

    bufferlength = (uint64_t)ceil(context.nbins/2.0);
    osuCrypto::PRNG dummy_prng(osuCrypto::sysRandomSeed(), bufferlength);

    //Get addresses
    uint64_t addresses1[context.ffuns];
    uint8_t bitaddress[context.ffuns];
    uint8_t bitindex[ts];
    uint64_t mask_ad = (1ULL << 2) - 1;

    double ave_ctr=0.0;

    for(int i=0; i<context.nbins; i++) {
      bool uniqueMap = false;
      int ctr=0;
      while (!uniqueMap) {
        auto nonce = padding_prng.get<osuCrypto::block>();

        for(int j=0; j< context.ffuns; j++) {
          addresses1[j] = hashToPosition(reinterpret_cast<uint64_t *>(&table_masks[i][j])[0], nonce);
          bitaddress[j] = addresses1[j] & mask_ad;
        }

        uniqueMap = true;
        for(int j=0; j<ts; j++)
          bitindex[j]=ts;

        for(uint8_t j=0; j< context.ffuns; j++) {
          if(bitindex[bitaddress[j]] != ts) {
            uniqueMap = false;
            break;
          } else {
            bitindex[bitaddress[j]] = j;
          }
        }

        if(uniqueMap) {
          padding_vals.push_back(nonce);
          for(int j=0; j<ts; j++)
            if(bitindex[j]!=-1) {
              table_opprf[i*ts+j] = reinterpret_cast<uint64_t *>(&table_masks[i][bitindex[j]])[0] ^ content_of_bins[i];
            } else {
              table_opprf[i*ts+j] = dummy_prng.get<uint64_t>();
            }
          ave_ctr += ctr;
        }
        ctr++;
      }
    //table_opprf[i*4+]
    }

    ave_ctr = ave_ctr/context.nbins;
    std::cout<<"Average counts: "<<ave_ctr<<std::endl;
    const auto table_end_time = std::chrono::system_clock::now();
    const duration_millis table_duration = table_end_time - table_start_time;
    context.timings.table_compute = table_duration.count();

    const auto ttrans_start_time = std::chrono::system_clock::now();
    sock = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    //Send nonces
    sock->Send(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
    //Send table
    sock->Send(table_opprf.data(), context.nbins * ts* sizeof(uint64_t));
    sock->Close();
    const auto ttrans_end_time = std::chrono::system_clock::now();
    const duration_millis ttrans_duration = ttrans_end_time - ttrans_start_time;
    context.timings.table_transmission = ttrans_duration.count();

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Contents of Bins are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      for(int j=0;j<context.ffuns;j++) {
        std::cout<<"( "<<i<<", "<<content_of_bins[i*context.ffuns+j]<<"), ";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
    //return content_of_bins;
    uint8_t* res_shares = new uint8_t[num_cmps];
    const auto clock_time_cir_start = std::chrono::system_clock::now();
    for(int i=0; i<pad; i++) {
        content_of_bins[context.nbins+i]=value;
    }

    perform_equality(content_of_bins.data(), party, context.bitlen, b, num_cmps, context.address, context.port, res_shares, ioArr, otpackArr);
    //  perform_batch_equality(content_of_bins.data(), compare, res_shares);
      const auto clock_time_cir_end = std::chrono::system_clock::now();
      const duration_millis cir_duration = clock_time_cir_end - clock_time_cir_start;
      context.timings.aby_total = cir_duration.count();
      const auto clock_time_total_end = std::chrono::system_clock::now();
      const duration_millis total_duration = clock_time_total_end - clock_time_total_start;
      context.timings.total = total_duration.count();
  } else {
    content_of_bins.reserve(num_cmps);

    const auto start_time = std::chrono::system_clock::now();

    const auto hashing_start_time = std::chrono::system_clock::now();

    ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
    simple_table.SetNumOfHashFunctions(context.nfuns);
    simple_table.Insert(inputs);
    simple_table.MapElements();
    //simple_table.Print();

    auto simple_table_v = simple_table.AsRaw2DVector();
    // context.simple_table = simple_table_v;

    const auto hashing_end_time = std::chrono::system_clock::now();
    const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
    context.timings.hashing = hashing_duration.count();

    const auto oprf_start_time = std::chrono::system_clock::now();

    auto masks = ot_sender(simple_table_v, context, false);

    const auto oprf_end_time = std::chrono::system_clock::now();
    const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
    context.timings.oprf = oprf_duration.count();

    /*std::cout<<"Size of Hash Table:"<< context.nbins <<std::endl;

    std::cout<<"***********************************"<<std::endl;
    std::cout<<"The OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      uint64_t size = masks[i].size();
      for(int j=0;j<size;j++) {
        std::cout<<"( "<<i<<", "<<masks[i][j]<<"), ";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/
   const auto filter_start_time = std::chrono::system_clock::now();
    uint64_t bufferlength = (uint64_t)ceil(context.nbins/2.0);
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed(), bufferlength);

    for( int i=0; i<context.nbins; i++) {
      content_of_bins.push_back(prng.get<uint64_t>());
    }

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Bin Random Values are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<content_of_bins[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::unordered_map<uint64_t,hashlocmap> tloc;
    std::vector<uint64_t> filterinputs;
    for(int i=0; i<context.nbins; i++) {
      int binsize = simple_table_v[i].size();
      for(int j=0; j<binsize; j++) {
        tloc[simple_table_v[i][j]].bin = i;
        tloc[simple_table_v[i][j]].index = j;
        filterinputs.push_back(simple_table_v[i][j]);
      }
    }

    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.fbins));
    cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    cuckoo_table.Insert(filterinputs);
    cuckoo_table.MapElements();
    //cuckoo_table.Print();

    if (cuckoo_table.GetStashSize() > 0u) {
      std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
    }

    std::vector<uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);

    bufferlength = (uint64_t)ceil(context.fbins - 3*context.nbins);
    osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      uint64_t size = masks[i].size();
      for(int j=0;j<size;j++) {
        osuCrypto::PRNG prng(masks[i][j], 2);
        for(int k=0;k<3;k++){
            std::cout<<"( "<<i<<"-"<< j<<"-"<< k <<", "<<prng.get<uint64_t>()<<"), ";
        }
        std::cout<<"\n";
      }
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    for(int i=0; i<context.fbins; i++){
      if(!cuckoo_table.hash_table_.at(i).IsEmpty()) {
        uint64_t element = cuckoo_table.hash_table_.at(i).GetElement();
        uint64_t function_id = cuckoo_table.hash_table_.at(i).GetCurrentFunctinId();
        hashlocmap hlm = tloc[element];
        osuCrypto::PRNG prng(masks[hlm.bin][hlm.index], 2);
        uint64_t pad = 0u;
        for(int j=0;j<=function_id;j++) {
           pad = prng.get<uint64_t>();
        }
        garbled_cuckoo_filter[i] = content_of_bins[hlm.bin] ^ pad;
      } else {
        garbled_cuckoo_filter[i] = prngo.get<uint64_t>();
      }
    }
    const auto filter_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_duration = filter_end_time - filter_start_time;
    context.timings.polynomials = polynomial_duration.count();

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
    for(int i=0;i<context.fbins;i++) {
      std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    std::unique_ptr<CSocket> sock =
        EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    const auto ftrans_start_time = std::chrono::system_clock::now();
    std::cout<<"Hint Size: "<< context.fbins * sizeof(uint64_t)<< endl;
    sock->Send(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
    const auto ftrans_end_time = std::chrono::system_clock::now();
    const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
    context.timings.polynomials_transmission = polynomial_trans.count();
    sock->Close();

    const auto oprf2_start_time = std::chrono::system_clock::now();
    const int ts=4;
    auto masks_with_dummies = ot_receiver(content_of_bins, context, true);
    const auto oprf2_end_time = std::chrono::system_clock::now();
    const duration_millis oprf2_duration = oprf2_end_time - oprf2_start_time;
    context.timings.oprf2 = oprf2_duration.count();

    const auto ttrans_start_time = std::chrono::system_clock::now();
    std::vector<osuCrypto::block> padding_vals;
    padding_vals.reserve(num_cmps);
    std::vector<uint64_t> table_opprf;
    table_opprf.reserve(ts*num_cmps);
    sock = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    //Receive nonces
    sock->Receive(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
    //Receive table
    sock->Receive(table_opprf.data(), context.nbins * ts* sizeof(uint64_t));
    sock->Close();
    const auto ttrans_end_time = std::chrono::system_clock::now();
    const duration_millis ttrans_duration = ttrans_end_time - ttrans_start_time;
    context.timings.table_transmission = ttrans_duration.count();

    const auto table_start_time = std::chrono::system_clock::now();
    uint64_t addresses1;
    uint8_t bitaddress;
    uint64_t mask_ad = (1ULL << 2) - 1;
    std::vector<uint64_t> actual_contents_of_bins;
    actual_contents_of_bins.reserve(num_cmps);

    for(int i=0; i<context.nbins; i++) {
          addresses1 = hashToPosition(reinterpret_cast<uint64_t *>(&masks_with_dummies[i])[0], padding_vals[i]);
          bitaddress = addresses1 & mask_ad;
          actual_contents_of_bins[i] = reinterpret_cast<uint64_t *>(&masks_with_dummies[i])[0] ^ table_opprf[ts*i+bitaddress];
    }

    /*std::cout<<"***********************************"<<std::endl;
    std::cout<<"The actual contents are: ["<<std::endl;
    for(int i=0;i<context.nbins;i++) {
      std::cout<<"( "<<i<<", "<<actual_contents_of_bins[i]<<"), ";
    }
    std::cout<<"]"<<std::endl;
    std::cout<<"***********************************"<<std::endl;*/

    const auto table_end_time = std::chrono::system_clock::now();
    const duration_millis table_duration = table_end_time - table_start_time;
    context.timings.table_compute = table_duration.count();

    for(int i=0; i<pad; i++) {
      actual_contents_of_bins[context.nbins+i]=value;
    }
    const auto clock_time_cir_start = std::chrono::system_clock::now();
    //perform_batch_equality(content_of_bins.data(), compare, res_shares);
    uint8_t* res_shares = new uint8_t[num_cmps];
    perform_equality(actual_contents_of_bins.data(), party, context.bitlen, b, num_cmps, context.address, context.port, res_shares, ioArr, otpackArr);
    const auto clock_time_cir_end = std::chrono::system_clock::now();
    const duration_millis cir_duration = clock_time_cir_end - clock_time_cir_start;
    context.timings.aby_total = cir_duration.count();
    const auto clock_time_total_end = std::chrono::system_clock::now();
    const duration_millis total_duration = clock_time_total_end - clock_time_total_start;
    context.timings.total = total_duration.count();

  }




  /*for(int i=0; i<context.nbins; i++) {
      for(int i)
  }*/
  /*

  // instantiate ABY
  ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                 context.nthreads);
  party.ConnectAndBaseOTs();
  auto bc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_BOOL)->GetCircuitBuildRoutine());  // GMW circuit
  assert(bc);

  share_ptr s_in_server, s_in_client;

  // share inputs in ABY
  if (context.role == SERVER) {
    s_in_server = share_ptr(bc->PutSIMDINGate(content_of_bins.size(), content_of_bins.data(), context.maxbitlen, SERVER));
    s_in_client = share_ptr(bc->PutDummySIMDINGate(content_of_bins.size(), context.maxbitlen));
  } else {
    s_in_server = share_ptr(bc->PutDummySIMDINGate(content_of_bins.size(), context.maxbitlen));
    s_in_client = share_ptr(bc->PutSIMDINGate(content_of_bins.size(), content_of_bins.data(), context.maxbitlen, CLIENT));
  }

  // compare outputs of OPPRFs for each bin in ABY (using SIMD)
  auto s_eq = share_ptr(bc->PutEQGate(s_in_server.get(), s_in_client.get()));

  std::vector<share_ptr> bin_results;
  for (uint32_t i = 0; i < content_of_bins.size(); ++i) {
    uint32_t pos[] = {i};
    bin_results.emplace_back(bc->PutSubsetGate(s_eq.get(), pos, 1));
    bin_results.at(i) = share_ptr(bc->PutOUTGate(bin_results.at(i).get(), ALL));
  }

  share_ptr s_out;
  auto t_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.threshold)));
  auto s_threshold = share_ptr(bc->PutCONSGate(context.threshold, t_bitlen));
  std::uint64_t const_zero = 0;
  auto s_zero = share_ptr(bc->PutCONSGate(const_zero, 1));

  if (context.analytics_type == PsiAnalyticsContext::NONE) {
    // we want to only do benchmarking, so no additional operations
  } else if (context.analytics_type == PsiAnalyticsContext::THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    s_out = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM_IF_GT_THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    auto s_gt_t = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
    s_out = share_ptr(bc->PutMUXGate(s_out.get(), s_zero.get(), s_gt_t.get()));
  } else {
    throw std::runtime_error("Encountered an unknown analytics type");
  }

  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
  }

  party.ExecCircuit();

  uint64_t output = 0;
  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    output = s_out->get_clear_value<uint64_t>();
  }

  context.timings.aby_setup = party.GetTiming(P_SETUP);
  context.timings.aby_online = party.GetTiming(P_ONLINE);
  context.timings.aby_total = context.timings.aby_setup + context.timings.aby_online;
  context.timings.base_ots_aby = party.GetTiming(P_BASE_OT);

  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();
  */
  uint64_t output = 0;
  return output;
}

void OpprgPsiClient(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();
  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
  cuckoo_table.SetNumOfHashFunctions(context.nfuns);
  cuckoo_table.Insert(elements);
  cuckoo_table.MapElements();
  //cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  /*ofstream file1 ("cuckoo_table_contents", ios::out);
  std::cout<<"Cuckoo Hash Table"<<std::endl;
  for(int i=0; i<context.nbins; i++){
    std::cout << cuckoo_table.hash_table_.at(i).GetElement() <<std::endl;
    file1 << cuckoo_table.hash_table_.at(i).GetElement();
    file1 << " ";
  }
  file1.close();*/

  auto cuckoo_table_v = cuckoo_table.AsRawVector();

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();
  const auto oprf_start_time = std::chrono::system_clock::now();

  auto masks_with_dummies = ot_receiver(cuckoo_table_v, context, false);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();
  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The OPRF outputs are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    std::cout<<"( "<<i<<", "<<masks_with_dummies[i]<<"), ";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;
  */

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    osuCrypto::PRNG prng(masks_with_dummies[i], 2);
    for(int j=0;j<3;j++) {
          std::cout<<"( "<<i<<"-"<< j<<", "<<prng.get<uint64_t>()<<"), ";
    }
      std::cout<<"\n";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  std::vector<uint64_t> garbled_cuckoo_filter;
  garbled_cuckoo_filter.reserve(context.fbins);
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  const auto ftrans_start_time = std::chrono::system_clock::now();
  sock->Receive(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
  sock->Close();
  const auto ftrans_end_time = std::chrono::system_clock::now();
  const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
  context.timings.polynomials_transmission = polynomial_trans.count();
  const auto filter_start_time = std::chrono::system_clock::now();
  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
  for(int i=0;i<context.fbins;i++) {
    std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  ENCRYPTO::CuckooTable garbled_cuckoo_table(static_cast<std::size_t>(context.fbins));
  garbled_cuckoo_table.SetNumOfHashFunctions(context.ffuns);
  garbled_cuckoo_table.Insert(cuckoo_table_v);
  auto addresses = garbled_cuckoo_table.GetElementAddresses();

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Addresses are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    for(int j=0;j<context.ffuns;j++) {
      std::cout<<"( "<<i<<"-"<<j<<", "<<addresses[i*context.ffuns+j]<<"), ";
    }
    std::cout<<"\n";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  for(int i=0; i<context.nbins; i++) {
    osuCrypto::PRNG prngo(masks_with_dummies[i], 2);
    for(int j=0; j< context.ffuns; j++) {
      content_of_bins[i*context.ffuns + j]=garbled_cuckoo_filter[addresses[i*context.ffuns+j]] ^ prngo.get<uint64_t>();
    }
  }
  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Contents of Bins are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    for(int j=0;j<context.ffuns;j++) {
      std::cout<<"( "<<i<<", "<<content_of_bins[i*context.ffuns+j]<<"), ";
    }
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  const auto filter_end_time = std::chrono::system_clock::now();
  const duration_millis polynomial_duration = filter_end_time - filter_start_time;
  context.timings.polynomials = polynomial_duration.count();
  //return content_of_bins;
}

void OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();

  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
  simple_table.SetNumOfHashFunctions(context.nfuns);
  simple_table.Insert(elements);
  simple_table.MapElements();
  //simple_table.Print();

  auto simple_table_v = simple_table.AsRaw2DVector();
  // context.simple_table = simple_table_v;

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  const auto oprf_start_time = std::chrono::system_clock::now();

  auto masks = ot_sender(simple_table_v, context, false);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  /*std::cout<<"Size of Hash Table:"<< context.nbins <<std::endl;

  std::cout<<"***********************************"<<std::endl;
  std::cout<<"The OPRF outputs are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    uint64_t size = masks[i].size();
    for(int j=0;j<size;j++) {
      std::cout<<"( "<<i<<", "<<masks[i][j]<<"), ";
    }
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/
  const auto filter_start_time = std::chrono::system_clock::now();
  uint64_t bufferlength = (uint64_t)ceil(context.nbins/2.0);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed(), bufferlength);

  for( int i=0; i<context.nbins; i++) {
    content_of_bins[i] = prng.get<uint64_t>();
  }

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Bin Random Values are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    std::cout<<"( "<<i<<", "<<content_of_bins[i]<<"), ";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  std::unordered_map<uint64_t,hashlocmap> tloc;
  std::vector<uint64_t> filterinputs;
  for(int i=0; i<context.nbins; i++) {
    int binsize = simple_table_v[i].size();
    for(int j=0; j<binsize; j++) {
      tloc[simple_table_v[i][j]].bin = i;
      tloc[simple_table_v[i][j]].index = j;
      filterinputs.push_back(simple_table_v[i][j]);
    }
  }

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.fbins));
  cuckoo_table.SetNumOfHashFunctions(context.ffuns);
  cuckoo_table.Insert(filterinputs);
  cuckoo_table.MapElements();
  //cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  std::vector<uint64_t> garbled_cuckoo_filter;
  garbled_cuckoo_filter.reserve(context.fbins);

  bufferlength = (uint64_t)ceil(context.fbins - 3*context.nbins);
  osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The 3-OPRF outputs are: ["<<std::endl;
  for(int i=0;i<context.nbins;i++) {
    uint64_t size = masks[i].size();
    for(int j=0;j<size;j++) {
      osuCrypto::PRNG prng(masks[i][j], 2);
      for(int k=0;k<3;k++){
          std::cout<<"( "<<i<<"-"<< j<<"-"<< k <<", "<<prng.get<uint64_t>()<<"), ";
      }
      std::cout<<"\n";
    }
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  for(int i=0; i<context.fbins; i++){
    if(!cuckoo_table.hash_table_.at(i).IsEmpty()) {
      uint64_t element = cuckoo_table.hash_table_.at(i).GetElement();
      uint64_t function_id = cuckoo_table.hash_table_.at(i).GetCurrentFunctinId();
      hashlocmap hlm = tloc[element];
      osuCrypto::PRNG prng(masks[hlm.bin][hlm.index], 2);
      uint64_t pad = 0u;
      for(int j=0;j<=function_id;j++) {
         pad = prng.get<uint64_t>();
      }
      garbled_cuckoo_filter[i] = content_of_bins[hlm.bin] ^ pad;
    } else {
      garbled_cuckoo_filter[i] = prngo.get<uint64_t>();
    }
  }
  const auto filter_end_time = std::chrono::system_clock::now();
  const duration_millis polynomial_duration = filter_end_time - filter_start_time;
  context.timings.polynomials = polynomial_duration.count();

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Garbled Cuckoo Filter contents are: ["<<std::endl;
  for(int i=0;i<context.fbins;i++) {
    std::cout<<"( "<<i<<", "<<garbled_cuckoo_filter[i]<<"), ";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  const auto ftrans_start_time = std::chrono::system_clock::now();
  std::cout<<"Hint Size: "<< context.fbins * sizeof(uint64_t)<< endl;
  sock->Send(garbled_cuckoo_filter.data(), context.fbins * sizeof(uint64_t));
  const auto ftrans_end_time = std::chrono::system_clock::now();
  const duration_millis polynomial_trans = ftrans_end_time - ftrans_start_time;
  context.timings.polynomials_transmission = polynomial_trans.count();


  sock->Close();
  //return content_of_bins;
}

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role) {
  //std::cout<<"EstablishConnection Started" << std::endl;
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  //std::cout<<"EstablishConnection Successful" << std::endl;
  return socket;
}

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2) {
  std::vector<std::uint64_t> intersection_v;

  std::sort(v1.begin(), v1.end());
  std::sort(v2.begin(), v2.end());

  std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(intersection_v));
  return intersection_v.size();
}

void PrintTimings(const PsiAnalyticsContext &context) {
  std::cout << "Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << "Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << "Time for polynomials " << context.timings.polynomials << " ms\n";
  std::cout << "Time for transmission of the polynomials "
            << context.timings.polynomials_transmission << " ms\n";
//  std::cout << "Time for OPPRF " << context.timings.opprf << " ms\n";

  std::cout << "ABY timings: online time " << context.timings.aby_online << " ms, setup time "
            << context.timings.aby_setup << " ms, total time " << context.timings.aby_total
            << " ms\n";

  std::cout << "Total runtime: " << context.timings.total << "ms\n";
  std::cout << "Total runtime w/o base OTs: "
            << context.timings.total - context.timings.base_ots_aby -
                   context.timings.base_ots_libote
            << "ms\n";
}

void PrintTimingsNew(const PsiAnalyticsContext &context) {
  std::cout << "Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << "Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << "Time for hint computation " << context.timings.polynomials << " ms\n";
  std::cout << "Time for transmission of the hint "
            << context.timings.polynomials_transmission << " ms\n";
//  std::cout << "Time for OPPRF " << context.timings.opprf << " ms\n";
  std::cout << "Time for OPRF 2 " << context.timings.oprf2 << " ms\n";
  std::cout << "Time for table hint computation " << context.timings.table_compute << " ms\n";
  std::cout << "Time for transmission of the table hint "
          << context.timings.table_transmission << " ms\n";

  std::cout << "Circuit Time " << context.timings.aby_total
            << " ms\n";

  std::cout << "Total runtime: " << context.timings.total << "ms\n";
  std::cout << "Total runtime w/o base OTs: "
            << context.timings.total - context.timings.base_ots_aby -
                   context.timings.base_ots_libote
            << "ms\n";
}

}
