#pragma once

/* ----------------------------------------------------------------------------- *
 * This Sample Code is provided for  the purpose of illustration only and is not * 
 * intended  to be used in a production  environment.  THIS SAMPLE  CODE AND ANY * 
 * RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER * 
 * EXPRESSED OR IMPLIED, INCLUDING  BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF * 
 * MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.                      * 
 * ----------------------------------------------------------------------------- */

 class AzureStorageAuthenticationHelper
{
private:
	typedef struct _keyvalue
	{
		char *key;
		char *value;
	} keyvalue;
	static const char *CODES;

	static int compKey(const void *l, const void *r);
	static int compParm(const void * l, const void * r);
	static char *stristr2(const char *haystack, const char *needle); 	
	static size_t append(char * output, size_t outputLength, size_t currentLength, const char * string, bool addLinefeed = true);
	static size_t appendChar(char * output, size_t outputLength, size_t currentLength, const char c);
	static size_t appendHeaderValue(char *output, size_t outputLength, size_t currentLength, keyvalue *kv, size_t headerCount, const char *key);
	static void freeHeaders(keyvalue **kvIn, size_t headerCount);
	static int parseHeaders(keyvalue **kvOut, const char *headers[], size_t headerCount);
public:
	static int GetAuthorizationHeader(
		char *output,
		size_t outputLength,
		const char *storageAccountName,
		const char *storageAccountKey,
		const char *httpMethod,
		const char *headers[],
		size_t headerCount,
		const char *queryString);
	static int encodeBase64(const char *input, int inputLength, char *output, int outputLen);
	static int decodeBase64(const char *input, char *output, int outputLen);
	static int hashIt(const char *data, size_t dataLen, const char *key, size_t keyLength, char *output, int outputLen);
	static int urlEncode(const char *url, char *output, size_t outputLength);
};
