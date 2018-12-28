<?php
	class JsonWebToken {
		private $alg;
		public $payload;
		private $signAlgorithm;
		private $hashAlgorithm;
		private $valid;

		public function validateAlgorithm($alg) {
			switch($alg) {
				case 'HS256':		return true;
				case 'HS384':		return true;
				case 'HS512':		return true;

				case 'RS256':		return true;
				case 'RS384':		return true;
				case 'RS512':		return true;

				default:		return false;
			}
		}

		public function algorithmGetHash($alg) {
			switch($alg) {
				case 'HS256':			return 'sha256';       /* HMAC as specified in RFC2104 */
				case 'HS384':			return 'sha384';
				case 'HS512':			return 'sha512';

				case 'RS256':			return 'sha256';        /* RSA (does openssl_sign do PKCSv1.5 or OEAP padding?) */
				case 'RS384':			return 'sha384';
				case 'RS512':			return 'sha512';

				default:				return false;
			}
		}

		public function algorithmGetSignalg($alg) {
			switch($alg) {
				case 'HS256':           return 'rfc2104';       /* HMAC as specified in RFC2104 */
				case 'HS384':           return 'rfc2104';
				case 'HS512':           return 'rfc2104';

				case 'RS256':           return 'pkcs1';        /* RSA (does openssl_sign do PKCSv1.5 or OEAP padding?) */
				case 'RS384':           return 'pkcs1';
				case 'RS512':           return 'pkcs1';

				default:                return false;
			}
		}

		public function __construct($algo = false) {
			if($algo) {
				if(!$this->validateAlgorithm($algo)) {
					throw new Exception("Unsupported or ivnalid signature algorithm");
				}

				$this->hashAlgorithm = $this->algorithmGetHash($algo);
				$this->signAlgorithm = $this->algorithmGetSignalg($algo);

				$this->alg = $algo;

				$this->payload = new stdClass();
			} else {
				$this->hashAlgorithm = false;
				$this->signAlgorithm = false;

				$this->payload = new stdClass();

				$this->alg = false;
			}
		}

		public function setPayload($payload) { $this->payload = $payload; }
		public function getPayload() { return $this->payload; }
		public function isValid() { return $this->valid; }

		/*
			Standard fields:

			iss	Issuer		OPTIONAL	Identifies the issuer - the secret is normally bound to the issuer
			sub	Subject		OPTIONAL	Subject (for whom we set the parameters)
			aud	Audience	OPTIONAL	Audience (Who should read this)
			exp	Expires		OPTIONAL	When does the token expire (unix time)
			nbf	Not before	OPTIONAL	Not valid before given time (unix time)
			iat	Issued at	OPTIONAL	The time when this token has been issued
			jti	JWT ID		OPTIONAL	An unique ID - may be used against replay attacks
		*/
		public function sign($keyData, $keyIndex) {
			/* Check if the supplied key is present */
			if(!is_array($keyData)) {
				throw new Exception("Failed to sign without key data");
			}
			if($keyIndex >= count($keyData)) {
				throw new Exception("Signature key index out of bounds");
			}

			$this->alg = strtoupper($keyData[$keyIndex]->algo);
			if(!$this->validateAlgorithm($this->alg)) {
				throw new Exception("Unsupported or invalid signature algorithm ".$this->alg." selected");
			}
			$this->hashAlgorithm = $this->algorithmGetHash($this->alg);
			$this->signAlgorithm = $this->algorithmGetSignalg($this->alg);			


			/* First build serialized version */

			if(!is_object($this->payload)) {
				$this->payload = new stdClass();
			}
			if(isset($keyData[$keyIndex]->iss)) {
				$this->payload->iss = $keyData[$keyIndex]->iss;
			}
			$this->payload->iat = time();

			$parts = array(
			str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), base64_encode(json_encode(array(
					'typ' => 'JWT',
					'alg' => $this->alg
				)))),
			str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), base64_encode(json_encode($this->payload))));
			$signInput = implode('.', $parts);

			$signature = false;
			switch($this->alg) {
				case 'HS256': $signature = hash_hmac('sha256', $signInput, $keyData[$keyIndex]->shared, true); break;
				case 'HS384': $signature = hash_hmac('sha384', $signInput, $keyData[$keyIndex]->shared, true); break;
				case 'HS512': $signature = hash_hmac('sha512', $signInput, $keyData[$keyIndex]->shared, true); break;

				case 'RS256':
					if(!openssl_sign($signInput, $signature, $keyData[$keyIndex]->privkey, OPENSSL_ALGO_SHA256)) {
						throw new Exception("OpenSSL sign failed");
					}
					break;
				case 'RS384':
					if(!openssl_sign($signInput, $signature, $keyData[$keyIndex]->privkey, OPENSSL_ALGO_SHA384)) {
						throw new Exception("OpenSSL sign failed");
					}
					break;
				case 'RS512':
					if(!openssl_sign($signInput, $signature, $keyData[$keyIndex]->privkey, OPENSSL_ALGO_SHA512)) {
						throw new Exception("OpenSSL sign failed");
					}
				break;
			}

			array_push($parts, str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), base64_encode($signature)));

			return implode('.', $parts);
		}


		private static function verifySingle($keyData, $payload, $signedData, $signature) {
			$sigValid = false;
			$metaValid = true;

			if(
				($keyData->algo == 'HS256')
				|| ($keyData->algo == 'HS384')
				|| ($keyData->algo == 'HS512')
			) {
				/* Create compare hash */
				$hash = false;
				switch($keyData->algo) {
					case 'HS256':	$hash = hash_hmac('sha256', $signedData, $keyData->shared, true); break;
					case 'HS384':	$hash = hash_hmac('sha384', $signedData, $keyData->shared, true); break;
					case 'HS512':	$hash = hash_hmac('sha512', $signedData, $keyData->shared, true); break;
					default:
						throw new Exception("Unsupported configured hash algorithm");
				}

				$sigValid = hash_equals($signature, $hash);
			} else if(
				($keyData->algo == 'RS256')
				|| ($keyData->algo == 'RS384')
				|| ($keyData->algo == 'RS512')
			) {
				switch($keyData->algo) {
					case 'RS512':	$sigValid = openssl_verify($signedData, $signature, $keyData->pubkey, OPENSSL_ALGO_SHA512); break;
					case 'RS384':	$sigValid = openssl_verify($signedData, $signature, $keyData->pubkey, OPENSSL_ALGO_SHA384); break;
					case 'RS256':	$sigValid = openssl_verify($signedData, $signature, $keyData->pubkey, OPENSSL_ALGO_SHA256); break;
					default:
						throw new Exception("Unsupported configured pubkey algorithm");
				}
			} else if($keyData->algo == 'none') {
				$sigValid = false; /* Unsigned tokens are NEVER correctly signed ... */
			} else {
				throw new Exception('Signature mechanism '.$keyData->algo.' unknown');
			}

			/* Do some metadata validation */

			if(!$sigValid) { return false; }	/* Does this allow any timing attacks? */

			/*
				Check if this key is only valid for a single issuer.
				In this case verify the issuer is correctly set inside
				the token and check it matches.
			*/
			if(isset($keyData->iss)) {
				if(!isset($payload->iss)) {
					$metaValid = false;
				} else if($payload->iss != $keyData->iss) {
					$metaValid = False;
				}
			}

			/*
				If an "exp"ires claim has been set check ...
			*/
			if(isset($payload->exp)) {
				if(!is_numeric($payload->exp)) {
					$metaValid = false;
				} else if($payload->exp < time()) {
					/* The token has already expired */
					$metaValid = false;
				}
			}

			/*
				Check any not before claims
			*/
			if(isset($payload->nbf)) {
				if(!is_numeric($payload->nbf)) {
					$metaValid = false;
				} else if($payload->nbf > time()) {
					/* We are NOT valid */
					$metaValid = false;
				}
			}

			/*
				Check that the token is not a time traveler
			*/
			if(isset($payload->iat)) {
				if(!is_numeric($payload->iat)) {
					$metaValid = false;
				} else if($payload->iat > time()) {
					$metaValid = false;
				}
			}


			return $sigValid && $metaValid;
		}

		/*
			Format of trusted keys:
				Array with key objects.

				{
					'algo' => 'HS256',
					'shared' => 'ajotgiqjoi',
					'iss' => 'Issuer constraint'	
				}

				{
					'algo' => 'RS256',
					'privkey' => 'DATA',
					'pubkey' => 'DATA',
					'iss' => Issuer constraint
				}
		*/
		public static function verify($tokenIn, $trustedKeys) {
			$result = new JsonWebToken();

			$parts = explode('.', $tokenIn);
			if(count($parts) != 3) {
				throw new Exception('Invalid token format');
			}

			$joseHeader = $parts[0];
			$payload = $parts[1];
			$signature = $parts[2];

			$signPayload = $joseHeader.'.'.$payload;

			unset($parts);

			if(($joseHeader = json_decode(base64_decode(str_replace(array('-', '_'), array('+', '/'), $joseHeader)))) === null) {
				throw new Exception('Invalid token format');
			}
			if(($payload = json_decode(base64_decode(str_replace(array('-', '_'), array('+', '/'), $payload)))) === null) {
				throw new Exception('Invalid token format');
			}
			if(($signature = base64_decode(str_replace(array('-', '_'), array('+', '/'), $signature))) === null) {
				throw new Exception('Invalid token format');
			}

			switch(strtoupper($joseHeader->alg)) {
				case 'HS256':			break;
				case 'HS384':			break;
				case 'HS512':			break;

				case 'RS256':			break;
				case 'RS384':			break;
				case 'RS512':			break;

				default:
					throw new Exception('Unsupported token format');
			}
			$result->alg = strtoupper($joseHeader->alg);
			$result->hashAlgorithm = $result->algorithmGetHash($result->alg);
                        $result->signAlgorithm = $result->algorithmGetSignalg($result->alg);
			$result->payload = $payload;

			/* Perform validation depending on the used algorithm */
			$sigValid = false;
			foreach($trustedKeys as $keyset) {
				if($result->alg == $keyset->algo) {
					/* Try this keyset ... */
					if(JsonWebToken::verifySingle($keyset, $payload, $signPayload, $signature)) {
						$sigValid = true;
						break;
					}
				}
			}

			$result->valid = $sigValid;

			/* Return status */
			return $result;
		}

		public static function loadKeyfile($kf) {
			if(!file_exists($kf)) {
				return array();
			} else {
				return json_decode(file_get_contents($kf));
			}
		}
		public static function newkeyHmac(&$kf, $bits = 256, $issuer = false) {
			$alg = false;
			switch($bits) {
				case 256:	$alg = "HS256"; break;
				case 384:	$alg = "HS384"; break;
				case 512:	$alg = "HS512"; break;
				default:
					throw new Exception("Unsupported hash bitsize");
			}

			$newEnt = new stdClass();
			$newEnt->algo = $alg;
			$newEnt->shared = base64_encode(openssl_random_pseudo_bytes(64));
			if($issuer) {
				$newEnt->iss = $issuer;
			}

			array_push($kf, $newEnt);

			return true;
		}

		public static function newkeyRsa(&$kf, $rsabits = 2048, $hashbits = 512, $issuer = false) {
			$digest = false;
			$alg = false;

			switch($hashbits) {
				case 256:
					$alg = "RS256";
					$digest = "sha256";
					break;
				case 384:
					$alg = "RS384";
					$digest = "sha384";
					break;
				case 512:
					$alg = "RS512";
					$digest = "sha512";
					break;
				default:
					throw new Exception("Unsupported hash size");
			}

			$newKeyPair = openssl_pkey_new(array(
				"digest_alg" => $digest,
				"private_key_bits" => $rsabits,
				"private_key_type" => OPENSSL_KEYTYPE_RSA
			));
			if(!$newKeyPair) {
				throw new Exception("Failed to create RSA Keypair: ".openssl_error_string());
			}

			$privKey = false;
			openssl_pkey_export($newKeyPair, $privKey);
			$keyDetails = openssl_pkey_get_details($newKeyPair);
			$pubKey = $keyDetails['key'];

			$newEnt->algo = $alg;
			$newEnt->privkey = $privKey;
			$newEnt->pubkey = $pubKey;
			if($issuer) {
				$newEnt->iss = $issuer;
			}
			array_push($kf, $newEnt);

			return true;
		}

		public static function storeKeyfile($keyData, $kf) {
			file_put_contents($kf, json_encode($keyData));
		}
	}
?>
