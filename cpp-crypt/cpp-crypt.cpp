/**
	@mainpage ハッシュ関数ライブラリのテスト
*/
// cpp-crypt.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"
#include <string.h>
#include "../crypt/crypt.h"

#pragma comment(lib, "crypt.lib")

#define	BUFFER_SIZE	(1024)

int _tmain(int argc, _TCHAR* argv[])
{
	char hex[BUFFER_SIZE];
	char b64Enc[BUFFER_SIZE];
	char md5Hex[BUFFER_SIZE];
	char md5B64[BUFFER_SIZE];
	char sha1Hex[BUFFER_SIZE];
	char sha1B64[BUFFER_SIZE];

	if ( argc < 2 ){
		printf("usage: CreateMD5Hash <string>\n");
		exit(-1);
	}

	BYTE *str = (BYTE*)argv[1];
	size_t strSize = strlen(argv[1]);

	size_t hexSize		= encode_hex(str, strSize, hex, sizeof(hex));
	size_t b64EncSize	= encode_base64(str, strSize, b64Enc, sizeof(b64Enc));
	size_t md5HexSize	= md5_hex(str, strSize, md5Hex, sizeof(md5Hex));
	size_t md5B64Size	= md5_base64(str, strSize, md5B64, sizeof(md5B64));
	size_t sha1HexSize	= sha1_hex(str, strSize, sha1Hex, sizeof(sha1Hex));
	size_t sha1B64Size	= sha1_base64(str, strSize, sha1B64, sizeof(sha1B64));

	printf(
		"'%s':%d\n"
		"  Hex:\t\t'%s':%d\n"
		"  B64:\t\t'%s':%d\n"
		"  MD5Hex:\t'%s':%d\n"
		"  MD5B64:\t'%s':%d\n"
		"  SHA1Hex:\t'%s':%d\n"
		"  SHA1B64:\t'%s':%d\n",
		str, strSize,
		hex,		hexSize,
		b64Enc,		b64EncSize,
		md5Hex,		md5HexSize,
		md5B64,		md5B64Size,
		sha1Hex,	sha1HexSize,
		sha1B64,	sha1B64Size
	);

	return 0;
}

