#include "AesClass.h"
#include <string>
#include <fstream>
#include <iostream>

using namespace std;

void TestCBCEncrypt();
void TestCBCDecrypt();
void TestCTREncrypt();
void TestCTRDecrypt();
string ToAscii(UINT8* pData, uint16_t uiLen );

typedef struct
{
   string strKey;
   string strIV;
   string strText;
} TEST_VEC_T;

typedef vector<TEST_VEC_T> VecList;


int main()
{
   ////////////////////////////////////////////
   // Run tests
   ////////////////////////////////////////////
   // TestCBCEncrypt();
   // TestCTREncrypt();
   // TestCBCDecrypt();
   TestCTRDecrypt();
   cin.get();
   return 0;
}

void TestCBCEncrypt()
{
   // Test vector
   //string keyStr = "2b7e151628aed2a6abf7158809cf4f3c";
   //string ivStr = "000102030405060708090A0B0C0D0E0F";
   //string plainStr = "6bc1bee22e409f96e93d7e117393172a";
   //string testCipherText = "7649abac8119b246cee98e9b12e9197d";
   string keyStr =         "140b41b22a29beb4061bda66b6747e14";
   string ivStr =          "4ca00ff4c898d61e1edbf1800618fb28";
   string plainStr =       "426173696320434243206d6f646520656e6372797074696f6e206e656564732070616464696e672e";
   string testCipherText = "28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
   UINT8 key[BLOCK_SIZE];
   UINT8 iv[BLOCK_SIZE];
   clsAES aes;
   int len = plainStr.length() / 2;
   int pad = BLOCK_SIZE - (len % BLOCK_SIZE);
   if (pad == 0)
      pad = 16;
   UINT8* cipher = new UINT8[len + pad];
   UINT8* plain = new UINT8[len];
   memset(plain, 0, len);
   memset(cipher, 0, len + pad);

   aes.HexStringToByteArray(keyStr, key);
   aes.HexStringToByteArray(ivStr, iv);
   aes.HexStringToByteArray(plainStr, plain);
   string strOut;
   aes.SetKeyIV(key, iv);
   aes.CbcEncrypt(plain, len, cipher);
   aes.ByteArrayToHexString(cipher, len+pad, strOut);
   cout << "Ciphertext: " << strOut.c_str();
   delete[] plain;
   delete[] cipher;

}


void TestCBCDecrypt()
{
   
   VecList vectorList;
   
   // test vector 1
   TEST_VEC_T testVector;
   testVector.strKey =  "2b7e151628aed2a6abf7158809cf4f3c";
   testVector.strIV =   "000102030405060708090A0B0C0D0E0F";
   testVector.strText = "7649abac8119b246cee98e9b12e9197d8964e0b149c10b7b682e6e39aaeb731c";
   //string plainStr = "6bc1bee22e409f96e93d7e117393172a";
   
   vectorList.push_back(testVector);

   // test vector 2
   testVector.strKey =  "140b41b22a29beb4061bda66b6747e14";
   testVector.strIV =   "4ca00ff4c898d61e1edbf1800618fb28";
   testVector.strText = "28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
   vectorList.push_back(testVector);

   // test vector 3
   testVector.strKey =  "140b41b22a29beb4061bda66b6747e14";
   testVector.strIV =   "5b68629feb8606f9a6667670b75b38a5";
   testVector.strText = "b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
   vectorList.push_back(testVector);
   
   UINT8 key[BLOCK_SIZE];
   UINT8 iv[BLOCK_SIZE];
   UINT8* cipher = NULL;
   UINT8* plain = NULL;

   // Perform decryption for each vector in the list
   for (UINT8 i = 0; i < vectorList.size(); i++)
   {
      memset(key, 0, BLOCK_SIZE);
      memset(iv, 0, BLOCK_SIZE);
      clsAES aes;
      int len = vectorList[i].strText.length() / 2;
      int pad = BLOCK_SIZE - (len % BLOCK_SIZE);
      UINT8* cipher = new UINT8[len];
      UINT8* plain = new UINT8[len];
   
      memset(cipher, 0, len);
      memset(plain, 0, len-pad);
      aes.HexStringToByteArray(vectorList[i].strKey, key);
      aes.HexStringToByteArray(vectorList[i].strIV, iv);
      aes.HexStringToByteArray(vectorList[i].strText, cipher);
      string strOut;
      aes.SetKeyIV(key, iv);
      UINT8 uiPad = 16;
      aes.CbcDecrypt(cipher, len, plain, uiPad);
      //strOut = ToAscii(plain, len - uiPad);
      aes.ByteArrayToHexString(plain, len-uiPad, strOut);
      ofstream file;
      file.open("TestResultCBCDecryption.txt", ios::app);
      file << "Plaintext" << i << ": " << strOut << endl;
      file.close();
      delete[] plain;
      delete[] cipher;
   }
}

void TestCTREncrypt()
{
   // Test vector
   //string keyStr = "2b7e151628aed2a6abf7158809cf4f3c";
   //string ivStr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
   //string plainStr = "6bc1bee22e409f96e93d7e117393172a";
   //string testCipherText = "874d6191b620e3261bef6864990db6ce";
   string keyStr =         "36f18357be4dbd77f050515c73fcf9f2";
   string ivStr =          "770b80259ec33beb2561358a9f2dc617";
   string plainStr =       "416c776179732061766f696420746865b80846836a46de0000065d6fd2ab";
   string testCipherText = "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
   UINT8 key[BLOCK_SIZE];
   UINT8 iv[BLOCK_SIZE];
   clsAES aes;
   int len = plainStr.length() / 2;
   UINT8* cipher = new UINT8[len];
   UINT8* plain = new UINT8[len];
   memset(plain, 0, len);
   memset(cipher, 0, len);

   aes.HexStringToByteArray(keyStr, key);
   aes.HexStringToByteArray(ivStr, iv);
   aes.HexStringToByteArray(plainStr, plain);
   string strOut;
   aes.SetKeyIV(key, iv);
   aes.CtrEncrypt(plain, len, cipher);
   aes.ByteArrayToHexString(cipher, len, strOut);
   cout << "Ciphertext: " << strOut.c_str();
   delete[] plain;
   delete[] cipher;

}


void TestCTRDecrypt()
{
   VecList vectorList;

   // test vector 1
   TEST_VEC_T testVector;
   
   // test vector 1
   testVector.strKey =  "2b7e151628aed2a6abf7158809cf4f3c";
   testVector.strIV =   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
   testVector.strText = "874d6191b620e3261bef6864990db6ce";
   string plainStr = "6bc1bee22e409f96e93d7e117393172a";
   vectorList.push_back(testVector);

   // test vector 2
   testVector.strKey =  "36f18357be4dbd77f050515c73fcf9f2";
   testVector.strIV =   "69dda8455c7dd4254bf353b773304eec";
   testVector.strText = "0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
   vectorList.push_back(testVector);

   // test vector 3
   testVector.strKey =  "36f18357be4dbd77f050515c73fcf9f2";
   testVector.strIV =   "770b80259ec33beb2561358a9f2dc617";
   testVector.strText = "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
   vectorList.push_back(testVector);

   // Perform decryption for each vector in the list
   for (UINT8 i = 0; i < vectorList.size(); i++)
   {
      UINT8 key[BLOCK_SIZE];
      UINT8 iv[BLOCK_SIZE];
      clsAES aes;
      int len = vectorList[i].strText.length() / 2;
      UINT8* cipher = new UINT8[len];
      UINT8* plain = new UINT8[len];
      aes.HexStringToByteArray(vectorList[i].strKey, key);
      aes.HexStringToByteArray(vectorList[i].strIV, iv);
      aes.HexStringToByteArray(vectorList[i].strText, cipher);
      string strOut;
      aes.SetKeyIV(key, iv);
      aes.CtrDecrypt(cipher, len, plain);
      aes.ByteArrayToHexString(plain, len, strOut);
      //strOut = ToAscii(plain, len);
      ofstream file;
      file.open("TestResultCTRDecryption.txt", ios::app);
      file << "Plaintext" << i << ": " << strOut << endl;
      file.close();
      delete[] plain;
      delete[] cipher;
   }
}

string ToAscii(UINT8* pData, uint16_t uiLen)
{
   string strAscii;
   for (uint16_t i = 0; i < uiLen; i++)
   {
      strAscii.push_back( (char)(pData[i]));
   }
   return strAscii;
}
