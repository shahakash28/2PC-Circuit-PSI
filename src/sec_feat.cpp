#include <cassert>
#include <iostream>
#include <unordered_map>

#include <boost/program_options.hpp>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "common/functionalities.h"
#include "common/config.h"

auto read_test_options(int32_t argcp, char **argvp) {
  namespace po = boost::program_options;
  ENCRYPTO::PsiAnalyticsContext context;
  po::options_description allowed("Allowed options");
  std::string type;
  // clang-format off
  allowed.add_options()("help,h", "produce this message")
  ("role,r",         po::value<decltype(context.role)>(&context.role)->required(),                                  "Role of the node")
  ("neles,n",        po::value<decltype(context.neles)>(&context.neles)->default_value(4096u),                      "Number of my elements")
  ("bit-length,b",   po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(62u),                      "Bit-length of the elements")
  ("epsilon,e",      po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(1.27f),                   "Epsilon, a table size multiplier")
  ("address,a",      po::value<decltype(context.address)>(&context.address)->default_value("127.0.0.1"),            "IP address of the server")
  ("port,p",         po::value<decltype(context.port)>(&context.port)->default_value(7777),                         "Port of the server")
  ("threads,t",      po::value<decltype(context.nthreads)>(&context.nthreads)->default_value(1),                    "Number of threads")
  ("others-neles,o", po::value<decltype(context.notherpartyselems)>(&context.notherpartyselems)->default_value(0u), "Number of other party's elements")
  ("threshold,c",    po::value<decltype(context.threshold)>(&context.threshold)->default_value(0u),                 "Show PSI size if it is > threshold")
  ("nmegabins,m",    po::value<decltype(context.nmegabins)>(&context.nmegabins)->default_value(1u),                 "Number of mega bins")
  ("polysize,s",     po::value<decltype(context.polynomialsize)>(&context.polynomialsize)->default_value(0u),       "Size of the polynomial(s), default: neles")
  ("functions,f",    po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u),                         "Number of hash functions in hash tables")
  ("type,y",         po::value<std::string>(&type)->default_value("None"),                                          "Function type {None, Threshold, Sum, SumIfGtThreshold}");
  // clang-format on

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argcp, argvp, allowed), vm);
    po::notify(vm);
  } catch (const boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<
               boost::program_options::required_option> > &e) {
    if (!vm.count("help")) {
      std::cout << e.what() << std::endl;
      std::cout << allowed << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if (vm.count("help")) {
    std::cout << allowed << "\n";
    exit(EXIT_SUCCESS);
  }

  if (type.compare("None") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::NONE;
  } else if (type.compare("Threshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::THRESHOLD;
  } else if (type.compare("Sum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM;
  } else if (type.compare("SumIfGtThreshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD;
  } else {
    std::string error_msg(std::string("Unknown function type: " + type));
    throw std::runtime_error(error_msg.c_str());
  }

  if (context.notherpartyselems == 0) {
    context.notherpartyselems = context.neles;
  }

  if (context.polynomialsize == 0) {
    context.polynomialsize = context.neles * context.nfuns;
  }
  context.polynomialbytelength = context.polynomialsize * sizeof(std::uint64_t);

  const std::size_t client_neles =
      context.role == CLIENT ? context.neles : context.notherpartyselems;
  context.nbins = client_neles * context.epsilon;

  //std::cout<<"In Input Parsing: "<< context.nbins<< ", "<< context.epsilon<< ", "<< context.neles<< std::endl;

  context.ffuns =3u;
  context.fepsilon= 1.27f;
  context.fbins=context.fepsilon*context.neles*context.nfuns;

  return context;
}

int main(int argc, char **argv) {
  auto context = read_test_options(argc, argv);
  auto gen_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.neles))) + 3;
  std::vector<uint64_t> inputs;
  if(context.role == CLIENT) {
    for(int i=0;i<context.neles;i++){
      inputs.push_back(1000*i);
    }
  } else {
    for(int i=0;i<context.neles;i++){
      inputs.push_back(2000*i);
    }
  }

  std::unordered_map<uint64_t,uint64_t> payloads;
  for(int i=0;i<context.neles;i++){
    payloads[inputs[i]] = 50*i;
  }

  /*std::cout<<"***********************************"<<std::endl;
  std::cout<<"The Input is: ["<<std::endl;
  for(int i=0;i<100;i++) {
    std::cout<<inputs[i]<<", ";
  }
  std::cout<<"]"<<std::endl;
  std::cout<<"***********************************"<<std::endl;*/


  //auto inputs = ENCRYPTO::GeneratePseudoRandomElements(context.neles, gen_bitlen);
  clock_t tStart, tEnd;
  tStart = clock();
  ENCRYPTO::run_psi_analytics_with_pl(inputs, payloads, context);
  tEnd = clock();
  std::cout << "PSI circuit successfully executed" << std::endl;

  PrintTimings(context);
  return EXIT_SUCCESS;
}
