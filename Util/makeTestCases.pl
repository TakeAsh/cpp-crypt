#!/usr/bin/perl
# Base64 検証用データ作成

use strict;
use warnings;
use utf8;
use Encode;
use Win32::Unicode::Native;
use YAML::Syck;
use MIME::Base64;
use String::Util qw(trim);
use Digest::MD5  qw(md5 md5_hex md5_base64);
use Digest::SHA1  qw(sha1 sha1_hex sha1_base64);

$YAML::Syck::ImplicitUnicode = 1;

my @sources = (
	"", "\x09\x0d\x0a\x20\x1a", "Hello", "Hello, world!",
	"0123456789abcdef", "01234567890123456789",
	qw( A AB ABC ABCD ABCDE ABCDEF ABCDEFG ABCDEFGH ABCDEFGHI ABCDEFGHIJ ),
	"\xa0", "\xa0\xb0", "\xa0\xb0\xc0", "\xa0\xb0\xc0\xd0", 
	"\xa0\xb0\xc0\xd0\xe0", "\xa0\xb0\xc0\xd0\xe0\xf0", 
	"\xa0\xb0\xc0\xd0\xe0\xf0\xf1", "\xa0\xb0\xc0\xd0\xe0\xf0\xf1\xf2", 
	"\xa0\xb0\xc0\xd0\xe0\xf0\xf1\xf2\xf3", "\xa0\xb0\xc0\xd0\xe0\xf0\xf1\xf2\xf3\xf4", 
);

for(my $index=0; $index < @sources; ++$index){
	my $src = $sources[$index];
	my $hex = unpack("H*", $src);
	my $b64 = trim(encode_base64($src));
	$b64 .= "=" x (3 - (length($b64) + 3) % 4);
	my $md5Hex = md5_hex($src);
	my $md5B64 = md5_base64($src);
	$md5B64 .= "=" x (3 - (length($md5B64) + 3) % 4);
	my $sha1Hex = sha1_hex($src);
	my $sha1B64 = sha1_base64($src);
	$sha1B64 .= "=" x (3 - (length($sha1B64) + 3) % 4);
	printf(
		"\t{\t// %d\n"
		. "\t\t/* src */\t\t\"%s\", %d,\n"
		. "\t\t/* hex */\t\t\"%s\",\t%d,\n"
		. "\t\t/* b64 */\t\t\"%s\",\t%d,\n"
		. "\t\t/* md5hex */\t\"%s\",\t%d,\n"
		. "\t\t/* md5b64 */\t\"%s\",\t%d,\n"
		. "\t\t/* sha1hex */\t\"%s\",\t%d,\n"
		. "\t\t/* sha1b64 */\t\"%s\",\t%d,\n\t},\n",
		$index,
		escapeStr($src), length($src),
		$hex, length($hex),
		$b64, length($b64),
		$md5Hex, length($md5Hex),
		$md5B64, length($md5B64),
		$sha1Hex, length($sha1Hex),
		$sha1B64, length($sha1B64)
	);
}

sub escapeStr
{
	my $str = shift;
	$str =~ s/([^[:print:]])/sprintf("\\x%02x", ord($1));/ge;
	return $str;
}

# EOF
