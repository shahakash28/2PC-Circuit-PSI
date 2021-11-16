An implementation of 2-Party Circuit-PSI protocol with linear computation and communication, accepted at PoPETs'22 \[[https://eprint.iacr.org/2021/034](https://ia.cr/2021/034)\].

Code based on the implementation of 2-Party Circuit-PSI available at \[[encryptogroup/OPPRF-PSI](https://github.com/encryptogroup/OPPRF-PSI)\] and Cryptflow 2.0 \[[mpc-msri/EzPC/SCI](https://github.com/mpc-msri/EzPC/tree/master/SCI)\].

## Required packages:
 - g++ (version >=8)
 - libboost-all-dev (version >=1.74)
 - libgmp-dev
 - libssl-dev
 - libntl-dev
 - pkg-config
 - libglib2.0-dev

## Compilation
```
mkdir build
cd build
cmake ..
cp ../aux_hash/* ../extern/HashingTables/cuckoo_hashing/.
make
// or make -j for faster compilation
```

## Run
Run from `build` directory.
Example:
```
Server: bin/gcf_psi -r 0 -p 31000 -n 65536 -b 58 -m 5 -y PSM2
Client: bin/gcf_psi -r 1 -a <server_ip_address> -p 31000 -n 65536 -b 58 -m 5 -y PSM2
```
Description of Parameters:
```
-r: role (0: Server/1: Client)
-a: ip-address
-p: port number
-n: number of elements in input set
-b: bitlength (40+2+log_2(n))
-m: radix for PSM functionality
-y: PSM Type (PSM1/PSM2)
```

## Execution Environment
The code was tested on Ubuntu 18.04/20.04 and Intel x86_64 architecture.

To create a docker image, find `docker-files/DockerFile` in docker-files folder. Copy and run `docker-files/execute.sh` file in docker image.

```
cd docker-files
docker build -t psi-image .
docker run -it psi-image bash
#Copy docker-files/execute.sh in docker-image
chmod +x execute.sh
./execute.sh
```

## Contact
For any queries, contact Akash Shah (akashshah08 at outlook.com).
