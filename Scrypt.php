<?php

namespace alexandernst\Scrypt;

use Yii;
use yii\base\ErrorException;

/**
 * Scrypt key derivation function
 *
 * @author Alexander Nestorov <alexandernst@gmail.com>
 * @version 0.0.1
 */

class Pbkdf2
{
	/**
	 * Generate the new key
	 *
	 * @param string $hash The hash algorithm to be used by HMAC
	 * @param string $password The source password/key
	 * @param string $salt Salt
	 * @param int $iterations The number of iterations
	 * @param int $length The output size
	 * @throws \yii\base\ErrorException
	 * @return string
	 */
	public static function calc($hash, $password, $salt, $iterations, $length)
	{
		if (!Hmac::isSupported($hash)) {
			throw new ErrorException("The hash algorithm $hash is not supported by " . __CLASS__);
		}
		$num	= ceil($length / Hmac::getOutputSize($hash, Hmac::OUTPUT_BINARY));
		$result = '';
		for ($block = 1; $block <= $num; $block++) {
			$hmac = hash_hmac($hash, $salt . pack('N', $block), $password, Hmac::OUTPUT_BINARY);
			$mix  = $hmac;
			for ($i = 1; $i < $iterations; $i++) {
				$hmac = hash_hmac($hash, $hmac, $password, Hmac::OUTPUT_BINARY);
				$mix ^= $hmac;
			}
			$result .= $mix;
		}
		return substr($result, 0, $length);
	}
}

class Hmac
{

	const OUTPUT_STRING = false;
	const OUTPUT_BINARY = true;

	/**
	 * Performs a HMAC computation given relevant details such as Key, Hashing
	 * algorithm, the data to compute MAC of, and an output format of String,
	 * or Binary.
	 *
	 * @param string $key
	 * @param string $hash
	 * @param string $data
	 * @param bool $output
	 * @throws \yii\base\ErrorException
	 * @return string
	 */

	public static function compute($key, $hash, $data, $output = self::OUTPUT_STRING)
	{
		if (empty($key)) {
			throw new ErrorException('Provided key is null or empty');
		}
		if (!$hash || !static::isSupported($hash)) {
			throw new ErrorException("Hash algorithm is not supported on this PHP installation; provided '{$hash}'");
		}
		return hash_hmac($hash, $data, $key, $output);
	}

	/**
	 * Get the output size according to the hash algorithm and the output format
	 *
	 * @param string $hash
	 * @param bool $output
	 * @return int
	 */
	public static function getOutputSize($hash, $output = self::OUTPUT_STRING)
	{
		return strlen(static::compute('key', $hash, 'data', $output));
	}

	/**
	 * Is the hash algorithm supported?
	 *
	 * @param string $algorithm
	 * @return bool
	 */
	public static function isSupported($algorithm)
	{
		return in_array(strtolower($algorithm), hash_algos(), true);
	}
}

/**
 * Scrypt key derivation function
 *
 * @see	 http://www.tarsnap.com/scrypt.html
 * @see	 https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01
 */

class Scrypt
{
	/**
	 * Execute the scrypt algorithm
	 *
	 * @param string $password
	 * @param string $salt
	 * @param int $n CPU/Memory cost parameter, must be larger than 1, a power of 2 and less than 2^(128 * r / 8)
	 * @param int $r Block size
	 * @param int $p Parallelization parameter, a positive integer less than or equal to ((2^32-1) * hLen) / MFLen where hLen is 32 and MFlen is 128 * r
	 * @param int $length Length of the output key
	 * @throws \yii\base\ErrorException
	 * @return string
	 */
	public static function calc($password, $salt, $n, $r, $p, $length)
	{
		if ($n == 0 || ($n & ($n - 1)) != 0) {
			throw new ErrorException("N must be > 0 and a power of 2");
		}
		if ($n > PHP_INT_MAX / 128 / $r) {
			throw new ErrorException("Parameter n is too large");
		}
		if ($r > PHP_INT_MAX / 128 / $p) {
			throw new ErrorException("Parameter r is too large");
		}

		$b = Pbkdf2::calc('sha256', $password, $salt, 1, $p * 128 * $r);

		$s = '';
		for ($i = 0; $i < $p; $i++) {
			$s .= self::scryptROMix(substr($b, $i * 128 * $r, 128 * $r), $n, $r);
		}

		return Pbkdf2::calc('sha256', $password, $s, 1, $length);
	}

	/**
	 * scryptROMix
	 *
	 * @param string $b Input octet vector of length 128 * r octets
	 * @param int $n Cpu/memory cost, must be larger than 1, a power of 2 and less than 2^(128 * r / 8)
	 * @param int $r Block size
	 * @return string
	 * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-4
	 */
	private static function scryptROMix($b, $n, $r)
	{
		$v = array();
		for ($i = 0; $i < $n; $i++) {
			$v[$i] = $b;
			$b = self::scryptBlockMix($b, $r);
		}
		for ($i = 0; $i < $n; $i++) {
			list(, $k) = unpack(PHP_INT_SIZE === 8 ? 'V' : 'v', substr($b, -64));
			$t = $b ^ $v[$k % $n];
			$b = self::scryptBlockMix($t, $r);
		}
		return $b;
	}

	/**
	 * scryptBlockMix
	 *
	 * @param string $b input vector of 2 * r 64-octet blocks
	 * @param int $r block size
	 * @return string
	 * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-3
	 */
	private static function scryptBlockMix($b, $r)
	{
		$x	= substr($b, -64);
		$even = '';
		$odd  = '';
		$len  = 2 * $r;

		for ($i = 0; $i < $len; $i++) {
			$x = self::salsa208($x ^ substr($b, 64 * $i, 64));
			if ($i % 2 == 0) {
				$even .= $x;
			} else {
				$odd .= $x;
			}
		}
		return $even . $odd;
	}

	private static function rotate($x1, $x2, $i)
	{
		static $_mods = array(0x7f, 0x1ff, 0x1fff, 0x3ffff);
		static $_mods_i = 0;

		$d = ($x1 + $x2);
		if (PHP_INT_SIZE === 4) {
			$x = ($d << $i) | ($d >> (32 - $i)) & $_mods[$_mods_i++];
			$_mods_i = $_mods_i === 3 ? 0 : $_mods_i;
		} else {
			$d &= 0xffffffff;
			$x = ($d << $i) | ($d >> (32 - $i));
		}

		return $x;
	}

	/**
	 * Salsa 20/8 core (32 and 64 bit version)
	 *
	 * @param string $b
	 * @return string
	 * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-2
	 * @see http://cr.yp.to/salsa20.html
	 */
	private static function salsa208($b)
	{
		$b32 = array();
		for ($i = 0; $i < 16; $i++) {
			list(, $b32[$i]) = unpack("V", substr($b, $i * 4, 4));
		}

		$x = $b32;
		for ($i = 0; $i < 8; $i += 2) {
			$x[ 4] ^= Scrypt::rotate($x[ 0], $x[12],  7);	$x[ 8] ^= Scrypt::rotate($x[ 4], $x[ 0],  9);
			$x[12] ^= Scrypt::rotate($x[ 8], $x[ 4], 13);	$x[ 0] ^= Scrypt::rotate($x[12], $x[ 8], 18);
			$x[ 9] ^= Scrypt::rotate($x[ 5], $x[ 1],  7);	$x[13] ^= Scrypt::rotate($x[ 9], $x[ 5],  9);
			$x[ 1] ^= Scrypt::rotate($x[13], $x[ 9], 13);	$x[ 5] ^= Scrypt::rotate($x[ 1], $x[13], 18);
			$x[14] ^= Scrypt::rotate($x[10], $x[ 6],  7);	$x[ 2] ^= Scrypt::rotate($x[14], $x[10],  9);
			$x[ 6] ^= Scrypt::rotate($x[ 2], $x[14], 13);	$x[10] ^= Scrypt::rotate($x[ 6], $x[ 2], 18);
			$x[ 3] ^= Scrypt::rotate($x[15], $x[11],  7);	$x[ 7] ^= Scrypt::rotate($x[ 3], $x[15],  9);
			$x[11] ^= Scrypt::rotate($x[ 7], $x[ 3], 13);	$x[15] ^= Scrypt::rotate($x[11], $x[ 7], 18);
			$x[ 1] ^= Scrypt::rotate($x[ 0], $x[ 3],  7);	$x[ 2] ^= Scrypt::rotate($x[ 1], $x[ 0],  9);
			$x[ 3] ^= Scrypt::rotate($x[ 2], $x[ 1], 13);	$x[ 0] ^= Scrypt::rotate($x[ 3], $x[ 2], 18);
			$x[ 6] ^= Scrypt::rotate($x[ 5], $x[ 4],  7);	$x[ 7] ^= Scrypt::rotate($x[ 6], $x[ 5],  9);
			$x[ 4] ^= Scrypt::rotate($x[ 7], $x[ 6], 13);	$x[ 5] ^= Scrypt::rotate($x[ 4], $x[ 7], 18);
			$x[11] ^= Scrypt::rotate($x[10], $x[ 9],  7);	$x[ 8] ^= Scrypt::rotate($x[11], $x[10],  9);
			$x[ 9] ^= Scrypt::rotate($x[ 8], $x[11], 13);	$x[10] ^= Scrypt::rotate($x[ 9], $x[ 8], 18);
			$x[12] ^= Scrypt::rotate($x[15], $x[14],  7);	$x[13] ^= Scrypt::rotate($x[12], $x[15],  9);
			$x[14] ^= Scrypt::rotate($x[13], $x[12], 13);	$x[15] ^= Scrypt::rotate($x[14], $x[13], 18);
		}
		for ($i = 0; $i < 16; $i++) {
			$t = $b32[$i] + $x[$i];
			$b32[$i] = PHP_INT_SIZE === 4 ? $t : $t & 0xffffffff;
		}
		$result = '';
		for ($i = 0; $i < 16; $i++) {
			$result .= pack("V", $b32[$i]);
		}

		return $result;
	}

	/**
	 * Convert hex string in a binary string
	 *
	 * @param  string $hex
	 * @return string
	 */
	private static function c_hex2bin($hex)
	{
		if (PHP_VERSION_ID >= 50400) {
			return hex2bin($hex);
		}
		$result = '';
		for ($i = 0; $i < strlen($hex); $i+=2) {
			$result .= chr(hexdec($hex[$i] . $hex[$i+1]));
		}
		return $result;
	}

	/**
	 * Test the crypto functions
	 *
	 * @throws \yii\base\ErrorException
	 */
	public static function test()
	{
		/*****************************************************************************\
		|                                                                             |
		| Salsa 20/8 test                                                             |
		| https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-7         |
		|                                                                             |
		\*****************************************************************************/

		$input = self::c_hex2bin(str_replace(" ", "",
			"7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26" .
			"ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d" .
			"ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32" .
			"76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e"
		));

		$output =  self::c_hex2bin(str_replace(" ", "",
			"a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05" .
			"04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29" .
			"b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba" .
			"e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81"
		));

		$x = self::salsa208($input);

		if ($x !== $output) {
			throw new ErrorException("Salsa 20/8 test failed.");
		}

		/*****************************************************************************\
		|                                                                             |
		| scryptBlockMix test                                                         |
		| https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-8         |
		|                                                                             |
		\*****************************************************************************/

		$input = self::c_hex2bin(str_replace(" ", "",
			"f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd" .
			"77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad" .
			"89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29" .
			"09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7" .

			"89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb" .
			"cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0" .
			"67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b" .
			"7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89"
		));

		$output = self::c_hex2bin(str_replace(" ", "",
			"a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05" .
			"04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29" .
			"b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba" .
			"e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81" .

			"20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c" .
			"21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7" .
			"7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6" .
			"5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25"
		));

		$x = self::scryptBlockMix($input, 1);

		if ($x !== $output) {
			throw new ErrorException("scryptBlockMix test failed.");
		}

		/*****************************************************************************\
		|                                                                             |
		| scryptROMix test                                                            |
		| https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-9         |
		|                                                                             |
		\*****************************************************************************/

		$input = self::c_hex2bin(str_replace(" ", "",
			"f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd" .
			"77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad" .
			"89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29" .
			"09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7" .
			"89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb" .
			"cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0" .
			"67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b" .
			"7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89"
		));

		$output = self::c_hex2bin(str_replace(" ", "",
			"79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6" .
			"2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46" .
			"d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26" .
			"a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71" .
			"ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c" .
			"ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4" .
			"ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f" .
			"4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e"
		));

		$x = self::scryptROMix($input, 16, 1);

		if ($x !== $output) {
			throw new ErrorException("scryptROMix test failed.");
		}

		/*****************************************************************************\
		|                                                                             |
		| PBKDF2 HMAC SHA 256 test                                                    |
		| https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-10        |
		|                                                                             |
		\*****************************************************************************/

		$output = self::c_hex2bin(str_replace(" ", "",
			"55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05" .
			"f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc" .
			"49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31" .
			"7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83"
		));

		$output2 = self::c_hex2bin(str_replace(" ", "",
			"4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9" .
			"64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56" .
			"a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17" .
			"6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d"
		));

		$x = Pbkdf2::calc("sha256", "passwd", "salt", 1, 64);
		$x2 = Pbkdf2::calc("sha256", "Password", "NaCl", 80000, 64);

		if ($x !== $output || $x2 !== $output2) {
			throw new ErrorException("PBKDF2 HMAC SHA 256 test failed.");
		}

		/*****************************************************************************\
		|                                                                             |
		| Scrypt test                                                                 |
		| https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-11        |
		|                                                                             |
		\*****************************************************************************/

		$output = self::c_hex2bin(str_replace(" ", "",
			"77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97" .
			"f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42" .
			"fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17" .
			"e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06"
		));

		$output2 = self::c_hex2bin(str_replace(" ", "",
			"fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe" .
			"7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62" .
			"2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da" .
			"c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40"
		));

		$output3 = self::c_hex2bin(str_replace(" ", "",
			"70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb" .
			"fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2" .
			"d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9" .
			"e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87"
		));

		$output4 = self::c_hex2bin(str_replace(" ", "",
			"21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81" .
			"ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47" .
			"8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3" .
			"37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4"
		));

		$x = self::calc("", "", 16, 1, 1, 64);
		$x2 = self::calc("password", "NaCl", 1024, 8, 16, 64);
		//$x3 = self::calc("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64);
		//$x4 = self::calc("pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64);

		if ($x !== $output || $x2 !== $output2 /*&& $x3 === $output3 && $x4 === $output4*/) {
			throw new ErrorException("Scrypt test failed.");
		}
	}
}
