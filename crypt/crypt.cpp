#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include "crypt.h"

#define	BUFFER_SIZE	(1024)

/**
	16進文字列化用バッファ
*/
static char hexBuffer[] = "00";

/**
	Base64 文字列変換用テーブル
*/
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

CRYPT_API size_t md5(
	BYTE *dataBody,
	size_t dataSize,
	BYTE *hashBody,
	size_t hashSize
){
	return crypt(CALG_MD5, dataBody, dataSize, hashBody, hashSize);
}

CRYPT_API size_t md5_hex(
	BYTE *dataBody,
	size_t dataSize,
	char *hexBody,
	size_t hexSize
){
	BYTE hashBuffer[BUFFER_SIZE];
	size_t hashSize = crypt(CALG_MD5, dataBody, dataSize, hashBuffer, sizeof(hashBuffer));
	return encode_hex(hashBuffer, hashSize, hexBody, hexSize);
}

CRYPT_API size_t md5_base64(
	BYTE *dataBody,
	size_t dataSize,
	char *b64Body,
	size_t b64Size
){
	BYTE hashBuffer[BUFFER_SIZE];
	size_t hashSize = crypt(CALG_MD5, dataBody, dataSize, hashBuffer, sizeof(hashBuffer));
	return encode_base64(hashBuffer, hashSize, b64Body, b64Size);
}

CRYPT_API size_t sha1(
	BYTE *dataBody,
	size_t dataSize,
	BYTE *hashBody,
	size_t hashSize
){
	return crypt(CALG_SHA1, dataBody, dataSize, hashBody, hashSize);
}

CRYPT_API size_t sha1_hex(
	BYTE *dataBody,
	size_t dataSize,
	char *hexBody,
	size_t hexSize
){
	BYTE hashBuffer[BUFFER_SIZE];
	size_t hashSize = crypt(CALG_SHA1, dataBody, dataSize, hashBuffer, sizeof(hashBuffer));
	return encode_hex(hashBuffer, hashSize, hexBody, hexSize);
}

CRYPT_API size_t sha1_base64(
	BYTE *dataBody,
	size_t dataSize,
	char *b64Body,
	size_t b64Size
){
	BYTE hashBuffer[BUFFER_SIZE];
	size_t hashSize = crypt(CALG_SHA1, dataBody, dataSize, hashBuffer, sizeof(hashBuffer));
	return encode_base64(hashBuffer, hashSize, b64Body, b64Size);
}

CRYPT_API size_t crypt(
	ALG_ID algid,
	BYTE *dataBody,
	size_t dataSize,
	BYTE *hashBody,
	size_t hashSize
){
	DWORD dwStatus = (DWORD)0;	// 処理結果
	HCRYPTPROV hProv = 0;		// Cryptographic Service Provider (CSP) へのハンドル
	HCRYPTHASH hHash = 0;		// Hash オブジェクトへのハンドル
	DWORD cbHash = 0;			// データバッファの長さ

	SetLastError(dwStatus);
	SecureZeroMemory(hashBody, hashSize);

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
		dwStatus = GetLastError();
		goto ErrorExit;
	}
	if (!CryptCreateHash(hProv, algid, 0, 0, &hHash)){
		dwStatus = GetLastError();
		goto ErrorExit;
    }
	if (!CryptHashData(hHash, dataBody, dataSize, 0)){
		dwStatus = GetLastError();
		goto ErrorExit;
	}
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &cbHash, 0)){
		dwStatus = GetLastError();
		goto ErrorExit;
	}
	BYTE *hash = new BYTE[cbHash];
	if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0)){
		memcpy_s(hashBody, min(hashSize, cbHash), hash, cbHash);
    } else {
		dwStatus = GetLastError();
	}
	delete[] hash;

ErrorExit:
	if (hHash){
		CryptDestroyHash(hHash);
	}
	if (hProv){
		CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwStatus);
	return min(hashSize, cbHash);
}

CRYPT_API size_t encode_hex(
	BYTE *dataBody,
	size_t dataSize,
	char *hexBody,
	size_t hexSize
){
	SecureZeroMemory(hexBody, hexSize);
	for(size_t i=0; i<dataSize; ++i){
		sprintf_s(hexBuffer, "%02.2x", dataBody[i]);
		strcat_s(hexBody, hexSize, hexBuffer);
	}
	return strnlen_s(hexBody, hexSize);
}

CRYPT_API size_t encode_base64(
	BYTE *dataBody,
	size_t dataSize,
	char *b64Body,
	size_t b64Size
){
	SecureZeroMemory(b64Body, b64Size);
	if ( dataSize * 4 + 3 < b64Size * 3 ){	// dataSize * 4/3 + 1 < b64Size
		for( size_t i=0, j=0; i < dataSize; i+=3, j+=4 ){
			b64Body[ j   ] = B64[ dataBody[i] >> 2 ];
			b64Body[ j+1 ] = ( i+1 < dataSize )
				? B64[ (dataBody[i] & 0x03)<<4 | (dataBody[i+1]>>4) ]
				: B64[ (dataBody[i] & 0x03)<<4 ];
			b64Body[ j+2 ] = ( i+2 < dataSize )
				? B64[ (dataBody[i+1] & 0x0f)<<2 | (dataBody[i+2] >>6) ]
				: ( i+1 < dataSize
					? B64[ (dataBody[i+1] & 0x0f)<<2 ]
					: '=');
			b64Body[ j+3 ] = ( i+2 < dataSize )
				? B64[ dataBody[i+2] & 0x3f]
				: '=';
		}
	}
	return strnlen_s(b64Body, b64Size);
}

static BYTE getVal(char *buffer, size_t index){
	int ch = buffer[index];
	const char *ptr;

	if ( ch == '=' || ch == '\0' ){
		return 0;
	}
	if ( (ptr = strchr(B64, ch)) != NULL ){
		return ptr - B64;
	}
	return 0;
}

CRYPT_API size_t decode_base64(
	char *b64Body,
	size_t b64Size,
	BYTE *dataBody,
	size_t dataSize
){
	size_t ret = 0;
	SecureZeroMemory(dataBody, dataSize);
	size_t b64Len = strnlen_s(b64Body, b64Size);
	if ( b64Len * 3 + 4 < dataSize * 4 ){	// b64Len * 3/4 + 1 < dataSize
		for( size_t i=0, j=0; i < b64Size; i+=4, j+=3 ){
			dataBody[j  ] = (getVal(b64Body, i) << 2) | ((getVal(b64Body, i+1) & 0x30) >> 4);
			dataBody[j+1] = ((getVal(b64Body, i+1) & 0x0f) << 4) | ((getVal(b64Body, i+2) & 0x3c) >> 2);
			dataBody[j+2] = ((getVal(b64Body, i+2) & 0x03) << 6) | (getVal(b64Body, i+3) & 0x3f);
		}
		if ( b64Len > 0 ){
			size_t b64LenMod4 = b64Len % 4;
			size_t b64LenDiv4 = (b64Len - 1) / 4;
			size_t b64LenBase = b64LenDiv4 * 4;
			if ( b64LenMod4 == 0 ){
				if ( b64Body[b64LenBase + 3] != '=' ){
					ret = b64LenDiv4 * 3 + 3;
				} else if ( b64Body[b64LenBase + 2] != '=' ){
					ret = b64LenDiv4 * 3 + 2;
				} else {
					ret = b64LenDiv4 * 3 + 1;
				}
			} else if ( b64LenMod4 == 3 ){
				if ( b64Body[b64LenBase + 2] != '=' ){
					ret = b64LenDiv4 * 3 + 2;
				} else {
					ret = b64LenDiv4 * 3 + 1;
				}
			} else {
					ret = b64LenDiv4 * 3 + 1;
			}
		}
	}
	return ret;
}

// EOF
