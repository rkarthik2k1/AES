#include "AesClass.h"
#include "aes.h"

clsAES::clsAES()
{
   Init();
}


clsAES::~clsAES()
{
}

//////////////////////////////////////////////////////////////////////
// Method:      CbcEncrypt
// Description: AES-CBC encryption using PKCS#5 padding
// pPlain:      pointer to Plaintext
// iLen:        plain text (and cipher text) length
// pCipherText: pointer to cipher text
// Return:      true if success, false otherwise
//////////////////////////////////////////////////////////////////////
bool clsAES::CbcEncrypt(UINT8* pPlain, UINT32 uiLen, UINT8* pCipherText)
{
   bool bRet = false;

   try
   {
      if ((pPlain != NULL) && (pCipherText != NULL))
      {
         // The basic AES encryption object 
         AESEncryption encrypt;
         encrypt.SetKey(m_ui8Key, BLOCK_SIZE);

         // Find value and length of pad bytes, which is the number of bytes required 
         // to make the length divisble by BLOCK_SIZE 
         UINT8 uiPad = BLOCK_SIZE - (uiLen % BLOCK_SIZE);
         UINT8* pPaddedPlain;

         // There is always an extra block even if uiLen is divisble by BLOCK_SIZE(PKCS#5)
         UINT32 uiNumBlocks = (uiLen / BLOCK_SIZE) + 1;

         // If no padding is required, then the pad is BLOCK_SIZE (PKCS#5)
         if (uiPad == 0)
         {
            uiPad = BLOCK_SIZE;
         }

         // Total length of the plain text and cipher text
         UINT32 uiFinalLen = uiNumBlocks * BLOCK_SIZE;
         pPaddedPlain = new UINT8[uiFinalLen];

         // Copy plain text upto uiLen 
         memcpy(pPaddedPlain, pPlain, uiLen);

         // Copy pad bytes for remaining length (which is uiPad)
         memset(pPaddedPlain + uiLen, uiPad, uiPad);

         // Basically Ci = E(Pi xor Ci-1)
         UINT8 xorBlock[BLOCK_SIZE];

         // C0 is nothing but IV which is the first xor block
         memcpy(xorBlock, m_ui8IV, BLOCK_SIZE);
         for (UINT32 i = 0; i < uiNumBlocks; i++)
         {
            // Pi xor Ci-1, C0 is IV
            for (UINT32 j = 0; j < BLOCK_SIZE; j++)
            {
               pPaddedPlain[(i * BLOCK_SIZE) + j] = pPaddedPlain[(i * BLOCK_SIZE) + j] ^ xorBlock[j];
            }

            // Encrypt plain text into pCipherText
            encrypt.ProcessBlock(pPaddedPlain + (i * BLOCK_SIZE), pCipherText + (i * BLOCK_SIZE) );

            if (i < (uiNumBlocks - 1))
            {
               // pCipherText becomes the next xor block
               memcpy(xorBlock, pCipherText + (i * BLOCK_SIZE), BLOCK_SIZE);
            }
         }
         bRet = true;
      }
   }
   catch (Exception e)
   {
   }
   return bRet;
}

//////////////////////////////////////////////////////////////////////
// Method:      CbcDecrypt
// Description: AES-CBC decryption using PKCS#5 padding
// pCipherText: pointer to cipher text
// iLen:        cipher text (and plain text) length
// pPlain:      pointer to plain text
// Return:      true if success, false otherwise
//////////////////////////////////////////////////////////////////////
bool clsAES::CbcDecrypt(UINT8* pCipherText, UINT32 uiLen, UINT8* pPlain, UINT8& uiPadByte)
{
   bool bRet = false;
   try
   {
      if ((pPlain != NULL) && (pCipherText != NULL))
      {
         // The basic AES decryption object 
         AESDecryption decrypt;
         decrypt.SetKey(m_ui8Key, BLOCK_SIZE);

         UINT32 uiNumBlocks = uiLen / BLOCK_SIZE;
         UINT8* pPaddedPlain = new UINT8[uiLen];
         memset(pPaddedPlain, 0, uiLen);

         // Basically Pi = D(Ci) xor Ci-1
         // C0 is nothing but IV which is the first xor block
         UINT8 xorBlock[BLOCK_SIZE];
         memcpy(xorBlock, m_ui8IV, BLOCK_SIZE);
         UINT8 pTemp[BLOCK_SIZE];
         memset(pTemp, 0, BLOCK_SIZE);
         for (int i = 0; i < uiNumBlocks; i++)
         {
            memset(pTemp, 0, BLOCK_SIZE);

            // Decrypt pCipherText into a temp block
            decrypt.ProcessBlock(pCipherText + (i * BLOCK_SIZE), pTemp);

            // D(Ci) xor Ci-1, C0 is IV
            for (int j = 0; j < BLOCK_SIZE; j++)
            {
               pPaddedPlain[(i * BLOCK_SIZE) + j] = pTemp[j] ^ xorBlock[j];
            }
            if ( i < (uiNumBlocks - 1) )
            {
               // pCipherText becomes the next xor block
               memcpy(xorBlock, pCipherText + (i * BLOCK_SIZE), BLOCK_SIZE);
            }
         }
         uiPadByte = pPaddedPlain[uiLen - 1];
         if (uiPadByte <= BLOCK_SIZE)
         {
            // Look at the last byte, that indicates the number of pad bytes to remove
            memcpy(pPlain, pPaddedPlain, uiLen - uiPadByte);
            bRet = true;
         }
         delete[] pPaddedPlain;
      }
   }
   catch (Exception e)
   {
   }
   return bRet;
}

void clsAES::incrementData(UINT8* pData, UINT8 len)
{
   if ( pData != NULL )
   {
      UINT8 index = len-1;
      do
      {
         if (++pData[index--] != 0)
            break;
      } while (index > 0);
   }
}

//////////////////////////////////////////////////////////////////////
// Method:      CtrEncrypt
// Description: AES-CTR encryption
// pPlain:      pointer to Plaintext
// iLen:        plain text (and cipher text) length
// pCipherText: pointer to cipher text
// Return:      true if success, false otherwise
//////////////////////////////////////////////////////////////////////
bool clsAES::CtrEncrypt(UINT8* pPlain, UINT32 iLen, UINT8* pCipherText)
{
   bool bRet = true;
   try
   {
      // The basic AES encryption object 
      AESEncryption encrypt;
      encrypt.SetKey(m_ui8Key, BLOCK_SIZE);

      UINT8 uiNumBlocks = (iLen / BLOCK_SIZE);
      UINT8 uiRemBytes = iLen % BLOCK_SIZE;

      UINT8 xorBlock[BLOCK_SIZE];
      UINT8 tempIV[BLOCK_SIZE];
      memset(xorBlock, 0, BLOCK_SIZE);
      memset(tempIV, 0, BLOCK_SIZE);

      // Basically Ci = Pi xor E(IV + i)
      memcpy(tempIV, m_ui8IV, BLOCK_SIZE);
      for (int i = 0; i < uiNumBlocks; i++)
      {
         // Encrypt IV + i ( Encrypt IV, IV + 1, ...) 
         encrypt.ProcessBlock(tempIV, xorBlock);

         // Pi xor xorBlock
         for (int j = 0; j < BLOCK_SIZE; j++)
         {
            pCipherText[(i * BLOCK_SIZE) + j] = pPlain[(i * BLOCK_SIZE) + j] ^ xorBlock[j];
         }

         // Increment IV only if more blocks or remaining bytes to process
         if ( (i < (uiNumBlocks - 1) ) || (uiRemBytes > 0) )
         {
            incrementData(tempIV, BLOCK_SIZE);
         }
      }

      if (uiRemBytes > 0)
      {
         encrypt.ProcessBlock(tempIV, xorBlock);
      }

      // If any remaining bytes, then handle here
      for (int j = 0; j < uiRemBytes; j++)
      {
         pCipherText[ (uiNumBlocks * BLOCK_SIZE) + j] = pPlain[ (uiNumBlocks * BLOCK_SIZE) + j] ^ xorBlock[j];
      }
   }
   catch (Exception e)
   {
      bRet = false;
   }
   return bRet;
}

//////////////////////////////////////////////////////////////////////
// Method:      CtrDecrypt
// Description: AES-CTR decryption
// pCipherText: pointer to cipher text
// iLen:        cipher text (and plain text) length
// pPlain:      pointer to plain text
// Return:      true if success, false otherwise
//////////////////////////////////////////////////////////////////////
bool clsAES::CtrDecrypt(UINT8* pCipherText, UINT32 uiLen, UINT8* pPlain)
{
   bool bRet = false;
   try
   {
      // The basic AES encryption object 
      AESEncryption encrypt;
      encrypt.SetKey(m_ui8Key, BLOCK_SIZE);

      UINT8 uiNumBlocks = (uiLen / BLOCK_SIZE);
      UINT8 uiRemBytes = uiLen % BLOCK_SIZE;

      UINT8 xorBlock[BLOCK_SIZE];
      UINT8 tempIV[BLOCK_SIZE];
      memset(xorBlock, 0, BLOCK_SIZE);
      memset(tempIV, 0, BLOCK_SIZE);

      // Basically Pi = E(IV + i) xor Ci
      memcpy(tempIV, m_ui8IV, BLOCK_SIZE);
      for (int i = 0; i < uiNumBlocks; i++)
      {
         // Encrypt IV + i 
         encrypt.ProcessBlock(tempIV, xorBlock);

         // IV xor xorBlock
         for (int j = 0; j < BLOCK_SIZE; j++)
         {
            pPlain[(i * BLOCK_SIZE) + j] = pCipherText[(i * BLOCK_SIZE) + j ] ^ xorBlock[j];
         }

         // Increment IV only if more blocks or remaining bytes to process
         if ( (i < (uiNumBlocks - 1) ) || (uiRemBytes > 0))
         {
            // increment the IV
            incrementData(tempIV, BLOCK_SIZE);
            memset(xorBlock, 0, BLOCK_SIZE);
         }
      }

      if (uiRemBytes > 0)
      {
         encrypt.ProcessBlock(tempIV, xorBlock);
      }

      // If any remaining bytes, then handle here
      for (int j = 0; j < uiRemBytes; j++)
      {
         pPlain[ (uiNumBlocks * BLOCK_SIZE) + j] = pCipherText[ (uiNumBlocks * BLOCK_SIZE) + j] ^ xorBlock[j];
      }
      bRet = true;
   }
   catch (Exception e)
   {
   }
   return bRet;
}

void clsAES::HexStringToByteArray(string &strHex, byte* pByteArray)
{
   if (pByteArray != NULL)
   {
      for (int i = 0; i < strHex.length(); i += 2)
         pByteArray[i / 2] = strtoul(strHex.substr(i, 2).c_str(), 0, 16);
   }
}

void clsAES::ByteArrayToHexString(UINT8* pByteArray, UINT8 iLen, string &strHex)
{
   if (pByteArray != NULL)
   {
      strHex.clear();
      char ch[3] = { '0', '0', '\0' };
      for (int i = 0; i < iLen; i++)
      {
         sprintf(ch, "%02x", pByteArray[i]);
         strHex += ch;
      }
   }
}