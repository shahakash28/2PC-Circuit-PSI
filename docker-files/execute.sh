#!/bin/bash
wget -O boost_1_74_0.tar.gz https://sourceforge.net/projects/boost/files/boost/1.74.0/boost_1_74_0.tar.gz/download
tar xzvf boost_1_74_0.tar.gz
cd boost_1_74_0
./bootstrap.sh --prefix=/usr/
./b2
./b2 install
cd ..
git clone https://github.com/shahakash28/2PC-Circuit-PSI.git
cd 2PC-Circuit-PSI
mkdir build && cd build
cmake ..
cp ../aux_hash/* ../extern/HashingTables/cuckoo_hashing/.
make
