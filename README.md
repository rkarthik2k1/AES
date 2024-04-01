# AES
AES modes using Crypto++ API. This does CBC encrypt/decryt using PKSC#5 padding

There are mainly three key files
   1. AesClass..h - Definitions for CBC and CTR mode methods
   2. AesClass.cpp - Implements CBC and CTR mode methods
   3. Main.cpp - Implements Test vectors to test AesClass and outputs results in a text file
The project uses Crypto++ API (cryptopp850) for the AES implementation and is not included in this repo. The cryptopp850 project can be downloaded from www.cryptopp.com 
This project  is in Visual C++ but the three files mentioned above can also be compiled in Linux w/o any changes. Following command was used to build Aes.o on Linux (Ubuntu)
g++ -o Aes.o Main.cpp AesClass.cpp -I ../cryptopp/ -L/usr/local/lib -l:libcryptopp.a
libcryptopp.a library was built after downloading the cryptopp project from www.cryptopp.com. The article 'https://www.cryptopp.com/wiki/GNUmakefile#Installing_the_Library' mentions how to build and install the library on Linux
The implementation assumes 128 bit keys
