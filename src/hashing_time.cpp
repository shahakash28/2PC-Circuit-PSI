#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/common/hash_table_entry.h"
#include "HashingTables/common/hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include <chrono>
#include<ctime>
#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"

#include "common/functionalities.h"

//using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

clock_t tStart, tEnd;

int main(int argc, char **arg) {
  //Parameters
  int ip_size = 73;
  int dict_size = 21413;
  int nbins = ip_size * 1.27f;
  int nfuns =3;
  std::vector<std::uint64_t> inputs_ch;
  std::vector<std::uint64_t> inputs_sh;

  for(int i=0;i<ip_size;i++){
    inputs_ch.push_back(1000*i);
  }

  for(int i=0;i<dict_size;i++){
    inputs_sh.push_back(1000*i);
  }

  //Cuckoo Hashing Runtime Estimate
  auto hashing_start_time = std::chrono::system_clock::now();
  tStart = clock();
  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(nbins));
  cuckoo_table.SetNumOfHashFunctions(nfuns);
  cuckoo_table.Insert(inputs_ch);
  cuckoo_table.MapElements();
  tEnd = clock();
  auto hashing_end_time = std::chrono::system_clock::now();
  duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  std::cout << "CPU time for execution: " << (double)(tEnd - tStart)/CLOCKS_PER_SEC << " sec\n";
  std::cout <<"Cuckoo Hashing Time (ms): "<<hashing_duration.count()<<std::endl;

  //Simple Hashing Runtime Estimate
  hashing_start_time = std::chrono::system_clock::now();
  tStart = clock();
  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(nbins));
  simple_table.SetNumOfHashFunctions(nfuns);
  simple_table.Insert(inputs_sh);
  simple_table.MapElements();
  tEnd = clock();
  hashing_end_time = std::chrono::system_clock::now();
  hashing_duration = hashing_end_time - hashing_start_time;
  std::cout << "CPU time for execution: " << (double)(tEnd - tStart)/CLOCKS_PER_SEC << " sec\n";
  std::cout <<"Simple Hashing Time (ms): "<<hashing_duration.count()<<std::endl;

  //Communication Time
  std::vector<uint64_t> data;
  int size = 2*2*65*1.27*73;
  data.reserve(size);

  std::string address;
  int port;
  uint32_t party;
  party = atoi (arg[1]);
  address = arg[2];
	port = atoi (arg[3]);
  std::unique_ptr<CSocket> sock =
      ENCRYPTO::EstablishConnection(address, port, static_cast<e_role>(party));
  hashing_start_time = std::chrono::system_clock::now();
  tStart = clock();
  if(party == 0) {
    for(int i=0; i<size; i++){
      data.push_back(size);
    }
    sock->Send(data.data(), size * sizeof(uint64_t));
  } else {
    sock->Receive(data.data(), size * sizeof(uint64_t));
  }
  tEnd = clock();
  hashing_end_time = std::chrono::system_clock::now();
  hashing_duration = hashing_end_time - hashing_start_time;
  std::cout << "CPU time for execution: " << (double)(tEnd - tStart)/CLOCKS_PER_SEC << " sec\n";
  std::cout <<"Communication Time (ms): "<<hashing_duration.count()<<std::endl;
  uint64_t sentBytes, recvBytes;

  sentBytes = sock->getSndCnt();
  recvBytes = sock->getRcvCnt();
  double sentinKB, recvinKB;

  sentinKB = sentBytes/((1.0*(1ULL<<10)));
  recvinKB = recvBytes/((1.0*(1ULL<<10)));

  std::cout<< "Sent Data (KB): "<<sentinKB<<std::endl;
  std::cout<< "Received Data (KB): "<<recvinKB<<std::endl;

  sock->Close();

    return 0;
}
