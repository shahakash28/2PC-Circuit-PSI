An implementation of 2-Party Circuit-PSI protocol, accepted at PoPETs'22 \[[https://eprint.iacr.org/2021/034](https://ia.cr/2021/034)\].

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
Copy aux\_hash/cuckoo\_hashing.cpp and aux\_hash/cuckoo\_hashing.h into extern/HashingTables/cuckoo\_hashing
make
// or make -j for faster compilation

```
