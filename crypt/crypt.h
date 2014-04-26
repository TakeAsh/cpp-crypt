/**
	@file crypt.h

	Hash 関数ライブラリ

	Example C Program: Creating an MD5 Hash from File Content<br>
	http://msdn.microsoft.com/en-us/library/aa382380.aspx
*/

#pragma once

#include <Windows.h>
#include <WinCrypt.h>

#ifdef CRYPT_EXPORTS
	#define CRYPT_API __declspec(dllexport)
	#define EXPIMP_TEMPLATE
#else
	#define CRYPT_API __declspec(dllimport)
	#define EXPIMP_TEMPLATE extern
#endif

/**
	MD5 を計算する。バイナリ版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t md5(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	BYTE *hashBody,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t hashSize		///< [in] バッファの長さ
);

/**
	MD5 を計算する。16進文字列版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t md5_hex(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *hexBody,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t hexSize		///< [in] バッファの長さ
);

/**
	MD5 を計算する。Base64 文字列版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t md5_base64(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *b64Body,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t b64Size		///< [in] バッファの長さ
);

/**
	SHA1 を計算する。バイナリ版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t sha1(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	BYTE *hashBody,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t hashSize		///< [in] バッファの長さ
);

/**
	SHA1 を計算する。16進文字列版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t sha1_hex(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *hexBody,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t hexSize		///< [in] バッファの長さ
);

/**
	SHA1 を計算する。16進文字列版。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t sha1_base64(
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *b64Body,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t b64Size		///< [in] バッファの長さ
);

/**
	アルゴリズムIDを指定してハッシュを計算する。
	@retval	!0	ハッシュ値の長さ
	@retval	0	エラー
*/
CRYPT_API size_t crypt(
	ALG_ID algid,		///< [in] アルゴリズムID
	BYTE *dataBody,		///< [in] ハッシュ計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	BYTE *hashBody,		///< [out] 計算されたハッシュを返すためのバッファ
	size_t hashSize		///< [in] バッファの長さ
);

/**
	バイト列から16進文字列を計算する。
	@retval	!0	16進文字列の長さ
	@retval	0	エラー
*/
CRYPT_API size_t encode_hex(
	BYTE *dataBody,		///< [in] 元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *hexBody,		///< [out] 計算された16進文字列を返すためのバッファ
	size_t hexSize		///< [in] バッファの長さ
);

/**
	バイト列から Base64 文字列を計算する。
	@retval	!0	Base64 文字列の長さ
	@retval	0	エラー
*/
CRYPT_API size_t encode_base64(
	BYTE *dataBody,		///< [in] base64 計算の元となるバイト列
	size_t dataSize,	///< [in] バイト列の長さ
	char *b64Body,		///< [out] 計算された Base64 文字列を返すためのバッファ
	size_t b64Size		///< [in] バッファの長さ
);

/**
	Base64 文字列からバイト列を計算する。
	@retval	!0	バイト列の長さ
	@retval	0	エラー
*/
CRYPT_API size_t decode_base64(
	char *b64Body,		///< [in] Base64 文字列
	size_t b64Size,		///< [in] Base64 文字列の長さ
	BYTE *dataBody,		///< [out] 計算されたバイト列
	size_t dataSize		///< [in] バイト列の長さ
);

// EOF
