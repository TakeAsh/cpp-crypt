/**
	@file crypt_TestData.h
*/

#pragma once

/**
	crypt 関数群テスト用構造体
*/
struct Crypt_TestCase {
	char *src;			///< 変換元文字列
	size_t srcSize;		///< 変換元文字列の長さ
	char *hex;			///< 16進文字列期待値
	size_t hexSize;		///< 16進文字列期待値の長さ
	char *b64;			///< Base64 文字列期待値
	size_t b64Size;		///< Base64 文字列期待値の長さ
	char *md5Hex;		///< MD5 16進文字列期待値
	size_t md5HexSize;	///< MD5 16進文字列期待値の長さ
	char *md5B64;		///< MD5 Base64 文字列期待値
	size_t md5B64Size;	///< MD5 Base64 文字列期待値の長さ
	char *sha1Hex;		///< SHA1 16進文字列期待値
	size_t sha1HexSize;	///< SHA1 16進文字列期待値の長さ
	char *sha1B64;		///< SHA1 Base64 文字列期待値
	size_t sha1B64Size;	///< SHA1 Base64 文字列期待値の長さ
};

/**
	テスト値配列
*/
extern Crypt_TestCase testCases[24];

// EOF
