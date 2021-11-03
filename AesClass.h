#pragma once
#include <stdio.h>
#include <string>
#include "osrng.h"
//#include "cryptlib.h"
using namespace CryptoPP;
using namespace std;

typedef unsigned char UINT8;
typedef unsigned int UINT32;

#define BLOCK_SIZE 16
class clsAES
{
	UINT8 m_ui8Ctr[BLOCK_SIZE];
   UINT8 m_ui8Key[BLOCK_SIZE];
   UINT8 m_ui8IV[BLOCK_SIZE];
	void incrementData(UINT8* pData, UINT8 len);
   
public:
	clsAES();
	~clsAES();
public:
	void Init() { memset(m_ui8Ctr, 0, BLOCK_SIZE); }
   void SetKeyIV(UINT8* pKey, UINT8* pIV)
   {
      if (pKey != NULL)
      {
         memcpy(m_ui8Key, pKey, BLOCK_SIZE);
      }

      if (pIV != NULL)
      {
         memcpy(m_ui8IV, pIV, BLOCK_SIZE);
      }
   }
   bool CtrEncrypt(UINT8* pPlain, UINT32 iLen, UINT8* pCipherText);
   bool CtrDecrypt(UINT8* pCipherText, UINT32 iLen, UINT8* pPlain);

	bool CbcEncrypt(UINT8* pPlain, UINT32 iLen, UINT8* pCipherText);
	bool CbcDecrypt(UINT8* pCipherText, UINT32 uiLen, UINT8* pPlain, UINT8& uiPad);

   void HexStringToByteArray(string &strHex, UINT8* pByteArray);
   void ByteArrayToHexString(UINT8* pByteArray, UINT8 iLen, string &strHex);
};

