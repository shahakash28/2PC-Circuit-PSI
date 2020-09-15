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
  int l=62;
  int b=5;

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

    auto masks_with_dummies = ot_receiver(cuckoo_table_v, context);

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
    /*
    std::unique_ptr<CSocket> sock =
        EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

    const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
    std::vector<std::vector<ZpMersenneLongElement>> polynomials(context.nmegabins);
    std::vector<ZpMersenneLongElement> X(context.nbins), Y(context.nbins);
    for (auto &polynomial : polynomials) {
      polynomial.resize(context.polynomialsize);
    }

    for (auto i = 0ull; i < X.size(); ++i) {
      X.at(i).elem = masks_with_dummies.at(i);
    }

    std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

    const auto receiving_start_time = std::chrono::system_clock::now();



    const auto receiving_end_time = std::chrono::system_clock::now();
    const duration_millis sending_duration = receiving_end_time - receiving_start_time;
    context.timings.polynomials_transmission = sending_duration.count();

    const auto eval_poly_start_time = std::chrono::system_clock::now();
    for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
      for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
        polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
            poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
      }
    }

    for (auto i = 0ull; i < X.size(); ++i) {
      std::size_t p = i / nbinsinmegabin;
      Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
    }

    const auto eval_poly_end_time = std::chrono::system_clock::now();
    const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
    context.timings.polynomials = eval_poly_duration.count();

    std::vector<uint64_t> raw_bin_result;
    raw_bin_result.reserve(X.size());
    for (auto i = 0ull; i < X.size(); ++i) {
      raw_bin_result.push_back(X[i].elem ^ Y[i].elem);
    }

    const auto end_time = std::chrono::system_clock::now();
    const duration_millis total_duration = end_time - start_time;
    context.timings.total = total_duration.count();
    */
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

    auto masks = ot_sender(simple_table_v, context);

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

  auto masks_with_dummies = ot_receiver(cuckoo_table_v, context);

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
  /*
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

  const auto receiving_start_time = std::chrono::system_clock::now();



  const auto receiving_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = receiving_end_time - receiving_start_time;
  context.timings.polynomials_transmission = sending_duration.count();

  const auto eval_poly_start_time = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }

  const auto eval_poly_end_time = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
  context.timings.polynomials = eval_poly_duration.count();

  std::vector<uint64_t> raw_bin_result;
  raw_bin_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    raw_bin_result.push_back(X[i].elem ^ Y[i].elem);
  }

  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;
  context.timings.total = total_duration.count();
  */
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

  auto masks = ot_sender(simple_table_v, context);

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

}
