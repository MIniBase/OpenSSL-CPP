#pragma once
#include<string>

using namespace std;

class Encryption
{
public:
	Encryption();
	~Encryption();
	static string DESEncrypt(string encryptString);
	static string DESEncrypt(string encryptString, string initialValue);
	static string DESDecrypt(string decryptString);
	static string DESDecrypt(string decryptString, string initialValue);
	static string DESDecrypt(string decryptString, string initialValue, string backupInitialValue);
	static string RSAEncrypt(string content, string publicKey);
	static string RSADecrypt(string content, string privateKey);
	static string RSADecrypt(string content, string privateKey, string backupPrivateKey);
private:
	static int replaceString(string &sourceString, const string &src, const string &dest);
	static void clearOpenSSL();
};

