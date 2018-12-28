<?php
	require_once("./JsonWebToken.php");

	$kd = JsonWebToken::loadKeyfile("./jwtkeys.json");
	if(count($kd) < 4) {
		/* Creating keys ... */
		if(count($kd) == 0) {
			echo("Creating first (HMAC) key");
			JsonWebToken::newkeyHmac($kd, 384, "TestIssuer");
			JsonWebToken::storeKeyfile($kd, "./jwtkeys.json");
			print_r($kd);
			return;
		}

		if(count($kd) == 1) {
			echo("Creating second (HMAC) key");
			JsonWebToken::newkeyHmac($kd);
			JsonWebToken::storeKeyfile($kd, "./jwtkeys.json");
			print_r($kd);
			return;
		}

		if(count($kd) == 2) {
			echo("Creating third (RSA) key");
			JsonWebToken::newkeyRsa($kd, 2048, 512, "Test Issuer 2");
			JsonWebToken::storeKeyfile($kd, "./jwtkeys.json");
			print_r($kd);
			return;
		}

		if(count($kd) == 3) {
			echo("Creating fourth (RSA) key");
			JsonWebToken::newkeyRsa($kd, 4096, 512);
			JsonWebToken::storeKeyfile($kd, "./jwtkeys.json");
			print_r($kd);
			return;
		}
	}

	if($argc < 2) {
		$testToken = new JsonWebToken();
		$testToken->payload->exp = time()+300;
		$testToken->payload->nbf = time()+120;
		$signedToken = $testToken->sign($kd, 0);
		echo("\nFirst test token: ".$signedToken);

		$testToken = new JsonWebToken();
		$testToken->payload->exp = time()+300;
		$signedToken2 = $testToken->sign($kd, 1);
		echo("\nSecond test token: ".$signedToken2);

		$testToken = new JsonWebToken();
		$testToken->payload->exp = time()+300;
		$testToken->payload->nbf = time()+120;
		$signedToken3 = $testToken->sign($kd, 2);
		echo("\nThird test token: ".$signedToken3);

		$testToken = new JsonWebToken();
		$testToken->payload->exp = time()+300;
		$signedToken4 = $testToken->sign($kd, 3);
		echo("\nFourth test token: ".$signedToken4."\n");
	} else {
		$v = JsonWebToken::verify($argv[1], $kd);
		echo("Verification returned: ".($v->isValid() ? "OK" : "Failed")."\n");
		print_r($v);
	}
?>
