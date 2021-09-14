An implementation of 2-Party Circuit-PSI protocol with linear computation and communication, accepted at PoPETs'22 \[[https://eprint.iacr.org/2021/034](https://ia.cr/2021/034)\].

Code based on the implementation of 2-Party Circuit-PSI available at \[[encryptogroup/OPPRF-PSI](https://github.com/encryptogroup/OPPRF-PSI)\] and Cryptflow 2.0 \[[mpc-msri/EzPC/SCI](https://github.com/mpc-msri/EzPC/tree/master/SCI)\].

## Required packages:
 - g++ (version >=8)
 - libboost-all-dev (version >=1.74)
 - libgmp-dev
 - libssl-dev
 - libntl-dev

## Compilation
```
mkdir build
cd build
cmake ..
Copy aux/hash/cuckoo/hashing.cpp and aux/hash/cuckoo/hashing.h into extern/HashingTables/cuckoo/hashing
make
// or make -j for faster compilation
```

## Run
Example:
```
Server: bin/gcf_psi -r 0 -n 65536 -b 58 -m 5 -y PSM2
Client: bin/gcf_psi -r 1 -a <server_ip_address> -n 65536 -b 58 -m 5 -y PSM2
```
See 'src/circuit_psi.cpp' file for description of the parameters and refer our paper to set the parameters. 

## Contact
For any queries, contact Akash Shah (akashshah08 at outlook.com).
