// crypt_Test.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

#include "stdafx.h"
#include <ctype.h>
#include <string.h>
#include "../crypt/crypt.h"
#include "crypt_TestData.h"

#pragma warning(push)
// warning C4793(ネイティブ関数としてコンパイルされました) を抑制
#pragma warning(disable: 4793)
#include <WinUnit.h>
#pragma warning(pop)

// 「'初期化中' : 定数値が切り捨てられました。」を抑制。
#pragma warning (disable : 4309)

#pragma comment(lib, "crypt.lib")

const size_t bufferSize = 1024;

/**
	変換結果格納用
*/
char buffer[bufferSize];

/**
	バイト列を比較する。
	@retval	true	一致
	@retval	false	不一致
*/
bool isSame(
	BYTE *str1,
	size_t len1,
	BYTE *str2,
	size_t len2
){
	bool ret = true;
	if ( len1 == len2 ){
		for(size_t i=0; i<len1; ++i){
			if ( *str1++ != *str2++ ){
				ret = false;
				break;
			}
		}
	} else {
		ret = false;
	}
	return ret;
}

/**
	印刷用バッファ
*/
char printBuffer[bufferSize];

/**
	印字できない文字をエスケープする。
	@return	エスケープ後文字列
*/
char *escapeStr(
	char *str		///< [in] エスケープする文字列
){
	SecureZeroMemory(printBuffer, sizeof(printBuffer));
	char cnvBuffer[] = "\\x00";
	for(size_t i=0; i<strlen(str); ++i){
		BYTE ch = (BYTE)*(str + i);
		if ( ch > 0x7f || !isalnum(ch) ){
			sprintf_s(cnvBuffer, "\\x%02x", ch);
			strcat_s(printBuffer, cnvBuffer);
		} else {
			sprintf_s(cnvBuffer, "%c", ch);
			strcat_s(printBuffer, cnvBuffer);
		}
	}
	return printBuffer;
}

BEGIN_TEST(001_encode_hex)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"encode_hex('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.hex, test.hexSize
		);
		size_t actualSize = encode_hex((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.hexSize, actualSize, _T("%d: encode_hex(size)"), index);
		bool same = isSame((BYTE*)test.hex, test.hexSize, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: encode_hex(body)"), index);
	}
}
END_TEST

BEGIN_TEST(002_encode_base64)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"encode_base64('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.b64, test.b64Size
		);
		size_t actualSize = encode_base64((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.b64Size, actualSize, _T("%d: encode_base64(size)"), index);
		bool same = isSame((BYTE*)test.b64, test.b64Size, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: encode_base64(body)"), index);
	}
}
END_TEST

BEGIN_TEST(003_decode_base64)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"decode_base64('%s', %d) -> '%s', %d\n",
			test.b64, test.b64Size, escapeStr(test.src), test.srcSize
		);
		size_t actualSize = decode_base64(test.b64, test.b64Size, (BYTE*)buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.srcSize, actualSize, _T("%d: decode_base64(size)"), index);
		bool same = isSame((BYTE*)test.src, test.srcSize, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: decode_base64(body)"), index);
	}
}
END_TEST

BEGIN_TEST(004_md5_hex)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"md5_hex('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.md5Hex, test.md5HexSize
		);
		size_t actualSize = md5_hex((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.md5HexSize, actualSize, _T("%d: md5_hex(size)"), index);
		bool same = isSame((BYTE*)test.md5Hex, test.md5HexSize, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: md5_hex(body)"), index);
	}
}
END_TEST

BEGIN_TEST(005_md5_base64)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"md5_base64('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.md5B64, test.md5B64Size
		);
		size_t actualSize = md5_base64((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.md5B64Size, actualSize, _T("%d: md5_base64(size)"), index);
		bool same = isSame((BYTE*)test.md5B64, test.md5B64Size, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: md5_base64(body)"), index);
	}
}
END_TEST

BEGIN_TEST(006_sha1_hex)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"sha1_hex('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.sha1Hex, test.sha1HexSize
		);
		size_t actualSize = sha1_hex((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.sha1HexSize, actualSize, _T("%d: sha1_hex(size)"), index);
		bool same = isSame((BYTE*)test.sha1Hex, test.sha1HexSize, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: sha1_hex(body)"), index);
	}
}
END_TEST

BEGIN_TEST(007_sha1_base64)
{
	for(size_t index=0; index < _countof(testCases); ++index){
		Crypt_TestCase test = testCases[index];
		WIN_TRACE(
			"sha1_base64('%s', %d) -> '%s', %d\n",
			escapeStr(test.src), test.srcSize, test.sha1B64, test.sha1B64Size
		);
		size_t actualSize = sha1_base64((BYTE*)test.src, test.srcSize, buffer, sizeof(buffer));
		WIN_ASSERT_EQUAL(test.sha1B64Size, actualSize, _T("%d: sha1_base64(size)"), index);
		bool same = isSame((BYTE*)test.sha1B64, test.sha1B64Size, (BYTE*)buffer, actualSize);
		WIN_ASSERT_TRUE(same, _T("%d: sha1_base64(body)"), index);
	}
}
END_TEST
