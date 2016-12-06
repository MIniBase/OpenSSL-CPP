#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <iostream>
#include <string>
#include "Encryption.h"

using namespace std;
typedef unsigned char       BYTE;

const static string defaultInitialValue = "";
const static string initialValue = "";
const static string initialValueBak = "";
const static BYTE Keys[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const string encodeMap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static unsigned char cbc_data[40] = {
	'd', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static char decodeMap[256];

Encryption::Encryption()
{
}


Encryption::~Encryption()
{
}

#pragma region BASE64
static void initBase64DecodeMap()
{
	memset(decodeMap, -1, sizeof(decodeMap));
	for (int i = 'A'; i <= 'Z'; ++i) decodeMap[i] = 0 + (i - 'A');
	for (int i = 'a'; i <= 'z'; ++i) decodeMap[i] = 26 + (i - 'a');
	for (int i = '0'; i <= '9'; ++i) decodeMap[i] = 52 + (i - '0');
	decodeMap[(unsigned char)'+'] = 62;
	decodeMap[(unsigned char)'/'] = 63;
	decodeMap[(unsigned char)'='] = 0;
}

string Encode64(unsigned char const* unEncodeChars, unsigned int stringLength) {
	std::string result;
	int i = 0;
	int j = 0;
	unsigned char triChars[3];
	unsigned char qurChars[4];

	while (stringLength--) {
		triChars[i++] = *(unEncodeChars++);
		if (i == 3) {
			qurChars[0] = (triChars[0] & 0xfc) >> 2;
			qurChars[1] = ((triChars[0] & 0x03) << 4) + ((triChars[1] & 0xf0) >> 4);
			qurChars[2] = ((triChars[1] & 0x0f) << 2) + ((triChars[2] & 0xc0) >> 6);
			qurChars[3] = triChars[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				result += encodeMap[qurChars[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			triChars[j] = '\0';

		qurChars[0] = (triChars[0] & 0xfc) >> 2;
		qurChars[1] = ((triChars[0] & 0x03) << 4) + ((triChars[1] & 0xf0) >> 4);
		qurChars[2] = ((triChars[1] & 0x0f) << 2) + ((triChars[2] & 0xc0) >> 6);
		qurChars[3] = triChars[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			result += encodeMap[qurChars[j]];

		while ((i++ < 3))
			result += '=';

	}
	return result;
}

bool Decode64(const string& strIn, string& strOut, bool fCheckInputValid = false)
{
	size_t nInlen = strIn.size();
	if (nInlen < 4 || (nInlen % 4) != 0)
	{
		return false;
	}

	static bool bInit = false;
	if (!bInit)
	{
		initBase64DecodeMap();
		bInit = true;
	}

	if (fCheckInputValid)
	{
		for (size_t i = 0; i < nInlen; ++i)
		{
			if (decodeMap[(unsigned char)strIn[i]] == -1)
			{
				return false;
			}
		}
	}
	size_t nOutLen = (nInlen * 3) / 4;
	string strTmpOut;
	strTmpOut.resize(nOutLen);
	size_t nLoopLen = nOutLen / 3;
	for (size_t i = 0; i < nLoopLen; ++i)
	{
		strTmpOut[i * 3] = ((decodeMap[strIn[i * 4]] << 2) & 0xFC) | ((decodeMap[strIn[i * 4 + 1]] >> 4) & 0x03);
		strTmpOut[i * 3 + 1] = ((decodeMap[strIn[i * 4 + 1]] << 4) & 0xF0) | ((decodeMap[strIn[i * 4 + 2]] >> 2) & 0x0F);
		strTmpOut[i * 3 + 2] = ((decodeMap[strIn[i * 4 + 2]] << 6) & 0xC0) | (decodeMap[strIn[i * 4 + 3]] & 0x3F);
	}

	if (strIn[nInlen - 1] == '=')
	{
		nOutLen--;
		if (strIn[nInlen - 2] == '=')
		{
			nOutLen--;
		}
	}
	const char* pData = strTmpOut.data();
	strOut.clear();
	strOut.append(pData, pData + nOutLen);
	return true;
}
#pragma endregion BASE64

#pragma region DES
string Encryption::DESEncrypt(string encryptString){
	return DESEncrypt(encryptString, "");
}

//DES加密
//encryptString
string Encryption::DESEncrypt(string encryptString, string initialValue)
{
	string rgbIVString = defaultInitialValue;
	if (initialValue.size() > 0 && initialValue.size() < 32)
	{
		rgbIVString = initialValue;
	}
	int strsize = encryptString.size();
	unsigned char * encryptChars = (unsigned char *)malloc(strsize);
	memcpy(encryptChars, encryptString.c_str(), strsize);

	int outsize = (7 + strsize) / 8 * 8;
	unsigned char * encodedChars = (unsigned char *)malloc(outsize);
	memset(encodedChars, 0, outsize);

	unsigned char * key = (unsigned char*)malloc(8);
	memcpy(key, Keys, 8);
	unsigned char * iv = (unsigned char*)malloc(rgbIVString.size());
	memcpy(iv, rgbIVString.c_str(), rgbIVString.size());

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, key, iv);

	EVP_CIPHER_CTX_set_padding(&ctx, 8);
	int ou1 = 0;
	int ou2 = 0;
	EVP_EncryptUpdate(&ctx, encodedChars, &ou1, encryptChars, strsize);
	EVP_EncryptFinal_ex(&ctx, encodedChars + ou1, &ou2);
	ou1 += ou2;

	string str = Encode64(encodedChars, ou1);
	int replaceCount = replaceString(str, "+", "-") + replaceString(str, "/", "_") + replaceString(str, "=", "");
 	//clearOpenSSL();
	free(encryptChars);
	free(encodedChars);
	free(key);
	free(iv);
	encryptChars=NULL;
	encodedChars=NULL;
	key=NULL;
	iv=NULL;
	return str;
}

string Encryption::DESDecrypt(string decryptString)
{
	return DESDecrypt(decryptString, "", "");
}

string Encryption::DESDecrypt(string decryptString, string initialValue)
{
	return DESDecrypt(decryptString, initialValue, "");
}

string Encryption::DESDecrypt(string decryptString, string initialValue, string backupInitialValue){
	string tempContent = decryptString;
	string decoded64Content;
	string result = decryptString;
	char *decrypted = (char *)malloc(tempContent.size());
	memset(decrypted, 0, tempContent.size());
	int contentReplace = replaceString(tempContent, "-", "+") + replaceString(tempContent, "_", "/");
	while (tempContent.size() % 4 != 0)
	{
		tempContent += "=";
	}
	try
	{
		string rgbIVString = defaultInitialValue;
		if (initialValue.size() > 0 && initialValue.size() < 32)
		{
			rgbIVString = initialValue;
		}
		Decode64(tempContent, decoded64Content);
		int strsize = tempContent.size()*3/4/8*8;
		unsigned char * encryptChars = (unsigned char *)malloc(strsize+8);
		memcpy(encryptChars, decoded64Content.c_str(), strsize+8);

		unsigned char * decodedChars = (unsigned char *)malloc(strsize);
		memset(decodedChars, 0, strsize);

		DES_cblock * key = (DES_cblock*)malloc(8);
		memcpy(key, Keys, 8);
		DES_key_schedule schedule;
		DES_set_odd_parity(key);
		DES_set_key_checked(key, &schedule);

		DES_cblock * iv = (DES_cblock*)malloc(rgbIVString.size());
		memcpy(iv, rgbIVString.c_str(), rgbIVString.size());

		DES_cbc_encrypt(encryptChars, decodedChars, strsize, &schedule, iv, DES_DECRYPT);
		result.clear();
		result.append(decodedChars, decodedChars+strsize);
		//clearOpenSSL();
		free(encryptChars);
		free(decodedChars);
		free(key);
		free(iv);
		encryptChars=NULL;
		decodedChars=NULL;
		key=NULL;
		iv=NULL;
	}
	catch (...)
	{
		try
		{
			string rgbIVString = defaultInitialValue;
			if (backupInitialValue.size() > 0 && backupInitialValue.size() < 32)
			{
				rgbIVString = backupInitialValue;
			}
			Decode64(tempContent, decoded64Content);
			int strsize = tempContent.size() * 3 / 4/8*8;
			unsigned char * encryptChars = (unsigned char *)malloc(strsize + 8);
			memcpy(encryptChars, decoded64Content.c_str(), strsize + 8);

			unsigned char * decodedChars = (unsigned char *)malloc(strsize);
			memset(decodedChars, 0, strsize);

			DES_cblock * key = (DES_cblock*)malloc(8);
			memcpy(key, Keys, 8);
			DES_key_schedule schedule;
			DES_set_odd_parity(key);
			DES_set_key_checked(key, &schedule);

			DES_cblock * iv = (DES_cblock*)malloc(rgbIVString.size());
			memcpy(iv, rgbIVString.c_str(), rgbIVString.size());

			DES_cbc_encrypt(encryptChars, decodedChars, strsize, &schedule, iv, DES_DECRYPT);
			result.clear();
			result.append(decodedChars, decodedChars+strsize);
			//clearOpenSSL();
			free(encryptChars);
			free(decodedChars);
			free(key);
			free(iv);
			encryptChars=NULL;
			decodedChars=NULL;
			key=NULL;
			iv=NULL;
		}
		catch (...)
		{
		}
	}
	clearOpenSSL();
	free(decrypted);
	decrypted=NULL;
	return result;
}
#pragma endregion DES

#pragma region RSA
///RSA加密,content为要加密内容,publicKey为加密字符串
string Encryption::RSAEncrypt(string content, string publicKey)
{
	RSA * rsa = NULL;
	BIO * keyBio;
	string decoded64Key;
	string base64Encrypted = content;
	unsigned char * encrypted = (unsigned char *)malloc(content.length() * 16);
	int keyReplace = replaceString(publicKey, " ", "") + replaceString(publicKey, "\n", "") + replaceString(publicKey, "\r", "");
	try
	{
		Decode64(publicKey, decoded64Key);

		int decodedSize = decoded64Key.size();
		for (int i = 0; i < decodedSize / 64; i++){
			decoded64Key.insert(65 * i + 64, "\n");
		}
		decoded64Key = "-----BEGIN PUBLIC KEY-----\n" + decoded64Key + "\n-----END PUBLIC KEY-----\n";

		keyBio = BIO_new_mem_buf(const_cast<unsigned char*>((const unsigned char*)decoded64Key.c_str()), -1);
		if (keyBio == NULL){
		}
		rsa = PEM_read_bio_RSA_PUBKEY(keyBio, &rsa, NULL, NULL);
		if (!rsa){
		}
		int result = RSA_public_encrypt(content.size(), const_cast<unsigned char*>((const unsigned char*)content.c_str()), (unsigned char *)encrypted, rsa, RSA_PKCS1_PADDING);
		base64Encrypted = Encode64((unsigned char *)encrypted, result);
		int replaceCount = replaceString(base64Encrypted, "+", "-") + replaceString(base64Encrypted, "/", "_") + replaceString(base64Encrypted, "=", "");
	}
	catch (...)
	{
	}
	RSA_free(rsa);
	BIO_free(keyBio);
	rsa=NULL;
	keyBio=NULL;
	return base64Encrypted;
}

string Encryption::RSADecrypt(string content, string privateKey)
{
	return RSADecrypt(content, privateKey, "");
}

string Encryption::RSADecrypt(string content, string privateKey, string backupPrivateKey)
{
	RSA * rsa = NULL;
	BIO * keyBio;
	string tempContent = content;
	string decoded64Key;
	string decoded64Content;
	char *decrypted = (char *)malloc(content.size() * 8);
	memset(decrypted, 0, content.size() * 8);
	int contentReplace = replaceString(tempContent, "-", "+") + replaceString(tempContent, "_", "/");
	while (tempContent.size() % 4 != 0)
	{
		tempContent += "=";
	}
	int keyReplace = replaceString(privateKey, " ", "") + replaceString(privateKey, "\n", "") + replaceString(privateKey, "\r", "");
	try
	{
		Decode64(privateKey, decoded64Key);
		Decode64(tempContent, decoded64Content);
		int decodedSize = decoded64Key.size();
		for (int i = 0; i < decodedSize / 64; i++){
			decoded64Key.insert(65 * i + 64, "\n");
		}
		decoded64Key = "-----BEGIN RSA PRIVATE KEY-----\n" + decoded64Key + "\n-----END RSA PRIVATE KEY-----\n";
		
		keyBio = BIO_new_mem_buf(const_cast<unsigned char*>((const unsigned char*)decoded64Key.c_str()), -1);
		if (keyBio == NULL){
		}
		rsa = PEM_read_bio_RSAPrivateKey(keyBio, &rsa, NULL, NULL);
		if (!rsa){
		}
		int result = RSA_private_decrypt(decoded64Content.size(), const_cast<unsigned char*>((const unsigned char*)decoded64Content.c_str()), (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
		if (result == -1)
		{
			throw -1;
		}
		content=decrypted;
	}
	catch (...)
	{
		try
		{
			Decode64(backupPrivateKey, decoded64Key);
			Decode64(tempContent, decoded64Content);
			int decodedSize = decoded64Key.size();
			for (int i = 0; i < decodedSize / 64; i++){
				decoded64Key.insert(65 * i + 64, "\n");
			}


			decoded64Key = "-----BEGIN RSA PRIVATE KEY-----\n" + decoded64Key + "\n-----END RSA PRIVATE KEY-----\n";

			keyBio = BIO_new_mem_buf(const_cast<unsigned char*>((const unsigned char*)decoded64Key.c_str()), -1);
			if (keyBio == NULL){
			}
			rsa = PEM_read_bio_RSAPrivateKey(keyBio, &rsa, NULL, NULL);
			if (!rsa){
			}
			int result = RSA_private_decrypt(decoded64Content.size(), const_cast<unsigned char*>((const unsigned char*)decoded64Content.c_str()), (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
			content=decrypted;
		}
		catch (...)
		{
		}
	}
	RSA_free(rsa);
	BIO_free(keyBio);
	free(decrypted);
	keyBio=NULL;
	rsa=NULL;
	decrypted=NULL;
	return content;
}
#pragma endregion RSA


int Encryption::replaceString(string &sourceString, const string &src, const string &dest)
{
	int counter = 0;
	string::size_type pos = 0;
	while ((pos = sourceString.find(src, pos)) != string::npos) {
		sourceString.replace(pos, src.size(), dest);
		++counter;
		pos += dest.size();
	}
	return counter;
}

void Encryption::clearOpenSSL()
{
	EVP_cleanup();                 //For EVP
	CRYPTO_cleanup_all_ex_data();  //generic 
	ERR_remove_state(0);           //for ERR
	ERR_free_strings();            //for ERR
}