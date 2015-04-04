# yii2-scrypt

Scrypt key derivation function for Yii2

To use it just require this extension in your composer.json file:

~~~
"alexandernst/yii2-scrypt": "0.0.1",
~~~

And then add it to your components configuration in Yii2:

~~~php
'components' => [
	'Scrypt' => [
		'class' => 'alexandernst\Scrypt\Scrypt'
	],
]
~~~

To derivate a key, use the following method:

~~~php
/**
* Scrypt algorithm
*
* @param  string $password
* @param  string $salt
* @param  int $n CPU/Memory cost parameter, must be larger than 1, a power of 2 and less than 2^(128 * r / 8)
* @param  int $r Block size
* @param  int $p Parallelization parameter, a positive integer less than or equal to ((2^32-1) * hLen) / MFLen where hLen is 32 and MFlen is 128 * r
* @param  int $length Length of the output key
* @throws Exception
* @return string
*/
\Yii::$app->Scrypt::calc("plain password", "salt", 1024, 8, 16, 64);
~~~

This class passes all the tests specified [in the documentation](https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01).
