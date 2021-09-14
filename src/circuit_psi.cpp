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

#include <cassert>
#include <iostream>

#include <boost/program_options.hpp>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "common/functionalities.h"
#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
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
  ("hint-epsilon,E",      po::value<decltype(context.fepsilon)>(&context.fepsilon)->default_value(1.27f),           "Epsilon, a hint table size multiplier")
  ("address,a",      po::value<decltype(context.address)>(&context.address)->default_value("127.0.0.1"),            "IP address of the server")
  ("port,p",         po::value<decltype(context.port)>(&context.port)->default_value(7777),                         "Port of the server")
  ("radix,m",    po::value<decltype(context.radix)>(&context.radix)->default_value(5u),                             "Radix in PSM Protocol")
  ("functions,f",    po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u),                         "Number of hash functions in hash tables")
  ("hint-functions,F",    po::value<decltype(context.ffuns)>(&context.ffuns)->default_value(3u),                         "Number of hash functions in hint hash tables")
  ("psm-type,y",         po::value<std::string>(&type)->default_value("PSM1"),                                          "PSM type {PSM1, PSM2}");
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

  if (type.compare("PSM1") == 0) {
    context.psm_type = ENCRYPTO::PsiAnalyticsContext::PSM1;
  } else if (type.compare("PSM2") == 0) {
    context.psm_type = ENCRYPTO::PsiAnalyticsContext::PSM2;
  } else {
    std::string error_msg(std::string("Unknown PSM type: " + type));
    throw std::runtime_error(error_msg.c_str());
  }

  context.nbins = context.neles * context.epsilon;

  context.fbins=context.fepsilon * context.neles * context.nfuns;

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

  //Setup Connection
  std::unique_ptr<CSocket> sock = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sci::NetIO* ioArr[2];
  osuCrypto::IOService ios;
  osuCrypto::Channel chl;
  osuCrypto::Session *ep;
  std::string name = "n";

  if(context.role == SERVER) {
    ioArr[0] = new sci::NetIO(nullptr, context.port+1);
    ioArr[1] = new sci::NetIO(nullptr, context.port+2);
    ep= new osuCrypto::Session(ios, context.address, context.port + 3, osuCrypto::SessionMode::Server,
                          name);
    chl = ep->addChannel(name, name);
  } else {
    ioArr[0] = new sci::NetIO(context.address.c_str(), context.port+1);
    ioArr[1] = new sci::NetIO(context.address.c_str(), context.port+2);
    ep = new osuCrypto::Session(ios, context.address, context.port + 3, osuCrypto::SessionMode::Client,
                          name);
    chl = ep->addChannel(name, name);
  }

  ResetCommunication(sock, chl, ioArr, context);
  run_circuit_psi(inputs, context, sock, ioArr, chl);
  PrintTimings(context);
  AccumulateCommunicationPSI(sock, chl, ioArr, context);
  PrintCommunication(context);

  //End Connection
  sock->Close();
  chl.close();
  ep->stop();
  ios.stop();

  for (int i = 0; i < 2; i++) {
      delete ioArr[i];
  }
  return EXIT_SUCCESS;
}
