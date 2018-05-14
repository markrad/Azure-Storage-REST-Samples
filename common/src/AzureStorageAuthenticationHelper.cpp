/* ----------------------------------------------------------------------------- *
 * This Sample Code is provided for  the purpose of illustration only and is not * 
 * intended  to be used in a production  environment.  THIS SAMPLE  CODE AND ANY * 
 * RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER * 
 * EXPRESSED OR IMPLIED, INCLUDING  BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF * 
 * MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.                      * 
 * ----------------------------------------------------------------------------- */

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "AzureStorageAuthenticationHelper.h"
#include "sha256.h"

// Suppress warnings about strcat
#if (defined WIN32) || (defined WIN64) 
#pragma warning(disable : 4996)
#endif

#ifdef __GNUC__
#define stricmp strcasecmp
#define strnicmp strncasecmp
#endif

// Used by Base64 conversion functions
const char *AzureStorageAuthenticationHelper::CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

// Passed to qsort to sort an array of key/value structures
int AzureStorageAuthenticationHelper::compKey(const void *l, const void *r)
{
	keyvalue *kvl = (keyvalue *)l;
	keyvalue *kvr = (keyvalue *)r;

	return strcmp(kvl->key, kvr->key);
}

// Passed to qsort to sort an array of HTTP headers by their key
int AzureStorageAuthenticationHelper::compParm(const void *l, const void *r)
{
	const char *lstr = *((const char **)l);
	const char *rstr = *((const char **)r);

	while (*lstr && *rstr)
	{
		if (*lstr == '=' && *rstr == '=')
		{
			// Both equals then the keys are equal
			break;
		}
		else if (*lstr == '=')
		{
			// Left key is exhausted
			return -1;
		}
		else if (*rstr == '=')
		{
			// Right key is exhausted
			return 1;
		}
		else if (*lstr != *rstr)
		{
			// Characters do not match
			return *lstr - *rstr;
		}
	}

	return 0;
}

// Helper function used to safely append a string to the signature string 
size_t AzureStorageAuthenticationHelper::append(char *output, size_t outputLength, size_t currentLength, const char *string, bool addLinefeed)
{
	if (currentLength < 0)
		return -1;

	int extra = addLinefeed ? 2 : 1;

	if (string != NULL)
	{
		if (strlen(string) + currentLength + extra > outputLength)
			return -1;

		strcat(output, string);
	}

	if (addLinefeed)
		strcat(output, "\n");

	return strlen(output);
}

// Helper function used to safely append a character to the signature string
size_t AzureStorageAuthenticationHelper::appendChar(char *output, size_t outputLength, size_t currentLength, const char c)
{
	if (currentLength < 0)
		return -1;

	if (currentLength + 2 > outputLength)
			return -1;

	output[currentLength++] = c;
	output[currentLength] = 0x00;

	return currentLength;
}

// Helper function to safely append a header value to the signature string if it is in the array of headers
size_t AzureStorageAuthenticationHelper::appendHeaderValue(char *output, size_t outputLength, size_t currentLength, keyvalue *kv, size_t headerCount, const char *key)
{
	for (size_t i = 0; i < headerCount; i++)
	{
		if (0 == stricmp(kv[i].key, key))
		{
			return append(output, outputLength, currentLength, kv[i].value);
		}
	}

	return append(output, outputLength, currentLength, "\n", false);
}

// Helper function that implements a case insensitive strstr function
char *AzureStorageAuthenticationHelper::stristr2(const char *haystack, const char *needle)
{
	int c = tolower((unsigned char)*needle);

	if (c == '\0')
		return (char *)haystack;

	for (; *haystack; haystack++) 
	{
		if (tolower((unsigned char)*haystack) == c) 
		{
			for (size_t i = 0;;) 
			{
				if (needle[++i] == '\0')
					return (char *)haystack;
			
				if (tolower((unsigned char)haystack[i]) != tolower((unsigned char)needle[i]))
					break;
			}
		}
	}

	return NULL;
}

// Helper function to free the headers key/value array
void AzureStorageAuthenticationHelper::freeHeaders(keyvalue **kvIn, size_t headerCount)
{
	keyvalue *kv = *kvIn;

	for (size_t i = 0; i < headerCount; i++)
	{
		free(kv[i].key);
		free(kv[i].value);
	}

	free(*kvIn);
	*kvIn = NULL;
}

// Helper function to parse HTTP headers in an array and return a sorted array of key/value structures
int AzureStorageAuthenticationHelper::parseHeaders(keyvalue **kvOut, const char *headers[], size_t headerCount)
{
	const char *start;
	const char *colon;
	const char *end;

	*kvOut = NULL;

	keyvalue *kv = (keyvalue *)malloc(sizeof(keyvalue) * headerCount);

	if (kv == NULL)
		return -3;

	memset(kv, 0, sizeof(keyvalue) * headerCount);

	// Walk the headers and pull out the key and the value
	for (size_t i = 0; i < headerCount; i++)
	{
		start = headers[i];

		// Trim leading key spaces
		while (*start == ' ')
			start++;

		colon = strchr(start, ':');

		if (colon == NULL || colon == start)
			return -2;

		end = colon - 1;

		// Trim trailing key spaces
		while (*end == ' ')
			end--;

		end++;

		// Allocate and copy
		kv[i].key = (char *)malloc(end - start + 1);

		if (kv[i].key == NULL)
		{
			freeHeaders(&kv, headerCount);
			return -3;
		}

		memcpy(kv[i].key, start, end - start);
		kv[i].key[end - start] = 0x00;

		start = colon + 1;

		// Trim leading value spaces
		while (*start == ' ')
			start++;

		end = start + strlen(start);

		if (end == start)
			return -2;

		end--;

		// Trim trailing value spaces
		while (*end == ' ')
			end--;

		end++;

		// Allocate and copy
		kv[i].value = (char *)malloc(end - start + 1);

		if (kv[i].value == NULL)
		{
			freeHeaders(&kv, headerCount);
			return -3;
		}

		memcpy(kv[i].value, start, end - start);
		kv[i].value[end - start] = 0x00;
	}

	qsort(kv, headerCount, sizeof(*kv), compKey);

	*kvOut = kv;

	return 0;
}

// Creates the authorization header for a Azure Storage REST request
//
//	output:					Buffer to receive the authorization header
//	outputLength:			Length of above buffer
//	storageAccountName:		Name of the account as in https://<thisname>.blob.co9re.windows.net
//	storageAccountKey:		The value of the key found in storage account -> access keys in the Azure portal
//	httpMethod:				The intended HTTP method - GET, PUT, etc.
//	headers:				An array that contains the headers to be used. Must contain x-ms-date and x-ms-version headers
//	headerCount:			Number of headers in the previous array
//	queryString:			Query passed as part of the URL such as ?comp=list for example
//
//	Returns the length of the authorization string or a negative number in the case of failure
//
int AzureStorageAuthenticationHelper::GetAuthorizationHeader(
	char * output, 
	size_t outputLength, 
	const char * storageAccountName, 
	const char * storageAccountKey, 
	const char * httpMethod, 
	const char * headers[], 
	size_t headerCount, 
	const char * queryString)
{
	int res;
	size_t currentLength = 0;

	if (outputLength == 0)
		return -1;

	output[0] = 0x00;

	keyvalue *kv = NULL;
	
	// This could be improved. The code assumes the signature string will fit in 200 bytes. If it is longer it
	// will return a failure. This could be much more dynamic.
	int workLen = 200;
	char *work = (char *)malloc(workLen);

	work[0] = 0x00;

	// Parse the headers into a sorted array of key/value structures
	if (0 != (res = parseHeaders(&kv, headers, headerCount)))
		return res;

	// Add HTTP method (GET, PUT, etc.)
	currentLength = append(work, workLen, currentLength, httpMethod);

	if (0 != strcmp(httpMethod, "GET") && 0 != strcmp(httpMethod, "HEAD"))
	{
		// For methods other than GET or HEAD add content-* header if provided
		currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "content-encoding");
		currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "content-language");
		currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "content-length");
		currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "content-md5");
		currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "content-type");
	}
	else
	{
		// For GET or HEAD skip these fields
		currentLength = append(work, workLen, currentLength, "\n\n\n\n\n", false);
	}

	// Add additional optional headers
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "date");
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "if-modified-since");
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "if-match");
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "if-none-match");
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "if-unmodified-since");
	currentLength = appendHeaderValue(work, workLen, currentLength, kv, headerCount, "range");

	const char *startKey = "x-ms-";
	const int startKeyLen = strlen(startKey);

	// Add headers starting with x-ms- to authentication string
	for (size_t i = 0; i < headerCount; i++)
	{
		if (0 == strnicmp(kv[i].key, startKey, startKeyLen))
		{
			currentLength = append(work, workLen, currentLength, kv[i].key, false);
			currentLength = append(work, workLen, currentLength, ":", false);
			currentLength = append(work, workLen, currentLength, kv[i].value);
		}
	}

	// Add storage account
	currentLength = append(work, workLen, currentLength, "/", false);
	currentLength = append(work, workLen, currentLength, storageAccountName, false);
	currentLength = append(work, workLen, currentLength, "/", false);

	// Check for a query string
	if (queryString != NULL && strlen(queryString) > 0)
	{
		char *index = (char *)queryString;
		char **parms;
		size_t parmCount = 0;

		// Count the query string elements
		while (*index)
		{
			if (*index++ == '=')
				parmCount++;
		}

		// Allocate an array for the query string elements
		parms = (char **)malloc(sizeof(parms) * parmCount);

		if (parms == NULL)
		{
			currentLength = -2;
		}

		index = (char *)queryString;

		if (*index == '?')
			*index++;

		// Search the string and store the address of the first byte of each in the array
		for (size_t i = 0; i < parmCount; i++)
		{
			parms[i] = index++;

			while (*++index != '&' && *index);
			
			++index;
		}

		// Sort the pointers by the query string each points to
		qsort(parms, parmCount, sizeof(*parms), compParm);

		// Add the sorted query strings to the signature string
		for (size_t i = 0; i < parmCount; i++)
		{
			index = parms[i];
			currentLength = appendChar(work, workLen, currentLength, '\n');

			while (*index && *index != '&')
			{
				if (*index == '=')
					currentLength = appendChar(work, workLen, currentLength, ':');
				else
					currentLength = appendChar(work, workLen, currentLength, *index);

				index++;
			}
		}

		free(parms);
	}

#ifdef DEBUG
	printf("signature string length = %d\r\n", (int)currentLength);
	printf("signature string\r\n%s\r\n", work);
#endif

	freeHeaders(&kv, headerCount);
	
	// The storage account key is encoded in Base64. Decode it first
	char *decodedKey = NULL;
	char *hashedKey = NULL;
	int keyLen = decodeBase64(storageAccountKey, NULL, 0);

	if (keyLen < 0)
		return keyLen;

	decodedKey = (char *)malloc(keyLen);

	if (decodedKey == NULL)
		return -2;

	keyLen = decodeBase64(storageAccountKey, decodedKey, keyLen);

	if (keyLen < 0)
	{
		free(decodedKey);
		return keyLen;
	}

	// Hash the signature string with the decoded storage access key
	int hashKeyLen = hashIt(work, currentLength, decodedKey, keyLen, NULL, 0);

	hashedKey = (char *)malloc(hashKeyLen);

	if (hashedKey == NULL)
	{
		free(decodedKey);
		return -2;
	}

	hashIt(work, currentLength, decodedKey, keyLen, (char *)hashedKey, hashKeyLen);
	
	// Build the HTTP authorization header to return to the caller
	currentLength = 0;
	currentLength = append(output, outputLength, currentLength, "Authorization: SharedKey ", false);
	currentLength = append(output, outputLength, currentLength, storageAccountName, false);
	currentLength = append(output, outputLength, currentLength, ":", false);
	currentLength = append(output, outputLength, currentLength, hashedKey, false);

	return currentLength;
}

//
// Encode to Base64
int AzureStorageAuthenticationHelper::encodeBase64(const char *input, int inputLength, char *output, int outputLen)
{
	if (output != NULL || outputLen != 0)
		*output = 0x00;
	else
		outputLen = 0;

	char b;
	int len = 0;

	for (int i = 0; i < inputLength; i += 3)
	{
		b = (input[i] & 0xfc) >> 2;
		len++;

		if (outputLen)
			*output++ = CODES[b];

		b = (input[i] & 0x03) << 4;

		if (i + 1 < inputLength)
		{
			b |= (input[i + 1] & 0xF0) >> 4;
			len++;

			if (outputLen)
				*output++ = CODES[b];
			
			b = (input[i + 1] & 0x0F) << 2;

			if (i + 2 < inputLength)
			{
				b |= (input[i + 2] & 0xC0) >> 6;
				len++;

				if (outputLen)
					*output++  = CODES[b];
				
				b = input[i + 2] & 0x3F;
				len++;

				if (outputLen)
					*output++ = CODES[b];
			}
			else
			{
				len += 2;

				if (outputLen)
				{
					*output++ = CODES[b];
					*output++ = '=';
				}
			}
		}
		else
		{
			len += 3;

			if (outputLen)
			{
				*output++ = CODES[b];
				*output++ = '=';
				*output++ = '=';
			}
		}
	}

	len++;

	if (outputLen)
		*output = 0x00;

	return len;
}

//
// Decodes from Base64
int AzureStorageAuthenticationHelper::decodeBase64(const char *input, char * output, int outputLen)
{
	int b[4];
	int inputLen = strlen(input);
	int equalsLoc = 0;
	const char *work;

	work = strchr(input, '=');

	if (work != NULL)
		equalsLoc = work - input;

	if (inputLen % 4 != 0)
		return -1;    // Base64 string's length must be a multiple of 4

	int requiredLen = (inputLen * 3) / 4 - (equalsLoc > 0 ? (inputLen - equalsLoc) : 0);

	if (outputLen == 0 || output == NULL)
		return requiredLen;

	if (requiredLen > outputLen)
		return -2;    // Output buffer is too short

	int j = 0;

	for (int i = 0; i < inputLen; i += 4)
	{
		b[0] = strchr(CODES, input[i + 0]) - CODES;
		b[1] = strchr(CODES, input[i + 1]) - CODES;
		b[2] = strchr(CODES, input[i + 2]) - CODES;
		b[3] = strchr(CODES, input[i + 3]) - CODES;

		output[j++] = ((b[0] << 2) | (b[1] >> 4));

		if (b[2] < 64)
		{
			output[j++] = ((b[1] << 4) | (b[2] >> 2));

			if (b[3] < 64)
			{
				output[j++] = ((b[2] << 6) | b[3]);
			}
		}
	}

	return requiredLen;
}

//
// Encode string for URL
int AzureStorageAuthenticationHelper::urlEncode(const char *url, char *output, size_t outputLength)
{
	static const char *hex = "0123456789ABCDEF";
	static const char *specials = "-._";
	int currentLength = 0;
  
	if (output != NULL && outputLength != 0)
		*output = 0x00;
	else 
		outputLength = 0;
  
	for (int i = 0; i < strlen(url); i++)
	{
		if (('a' <= url[i] && url[i] <= 'z') ||
			('A' <= url[i] && url[i] <= 'Z') ||
			('0' <= url[i] && url[i] <= '9') ||
			(NULL != strchr(specials, url[i])))
		{
			if (currentLength + 1 < outputLength)
			{
				output[currentLength++] = url[i];
				output[currentLength] = 0x00;
			}
		}
		else
		{
			if (currentLength + 1 < outputLength)
			{
				output[currentLength++] = '%';
				output[currentLength] = 0x00;
			}
				
			if (currentLength + 1 < outputLength)
			{
				output[currentLength++] = hex[url[i] >> 4];
				output[currentLength] = 0x00;
			}
				
			if (currentLength + 1 < outputLength)
			{
				output[currentLength++] = hex[url[i] & 15];
				output[currentLength] = 0x00;
			}
		}
	}
}

// Helper function to hash data with key and return in output encoded in Base64
int AzureStorageAuthenticationHelper::hashIt(const char *data, size_t dataLen, const char * key, size_t keyLength, char *output, int outputLen)
{
	uint8_t signedOut[32];
	int encodedLen;

	generateHash(signedOut, (uint8_t *)data, dataLen, (uint8_t *)key, keyLength);
	encodedLen = encodeBase64((char *)signedOut, sizeof(signedOut), NULL, 0);

	if (output == NULL || outputLen == 0)
		return encodedLen;

	if (encodedLen > outputLen)
		return -1;

	encodeBase64((char *)signedOut, sizeof(signedOut), output, outputLen);

	return 0;
}
