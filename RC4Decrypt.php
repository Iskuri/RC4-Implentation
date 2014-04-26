<?php

@$password = $argv[1];

if(!$password) {
	$password = "test_password";
}

$packets = array();

//$packetCount = 4096*5;

$packetCount = 256*512;

for($i = 0 ; $i < $packetCount ; $i++) {

	$iv = generateIV();

	$crypt = new rc4cryptor(generateRandomString(), $iv.$password);

	$packets[$iv][] = $crypt->output;

	echo "Generating packets: ".round($i/$packetCount*100,2)."%              \r";

}

//start analysing iv stuff

$firstByte = "a";

$charactersFreq = array();

$passSoFar = "";

for($i = 0 ; $i < strlen($password) ; $i++) {

//	FLUHRER CRACK MODE
	$charactersFreq = array();

	foreach($packets as $key => $packet) {

		foreach($packet as $chosen) {

			if(getWeakness($key,strlen($passSoFar))) {

				$firstByteOfKeyStream = $firstByte ^ substr($chosen,0,1);

				$kOut = fluhrerKSA($key.$passSoFar);
				$j = $kOut['j'];
				$s = $kOut['ksa'];

				$out = chr(truemod((ord($firstByteOfKeyStream) - $j - $s[strlen($key.$passSoFar)]),256));

				@$charactersFreq[$out]++;
			}
		}

	}

	$passSoFar .= getHeighestFreq($charactersFreq);

	echo($passSoFar."\n");

}

function getHeighestFreq($frequencies) {

	$highestCount = 0;
	$char = "";

	$sum = 0;

	foreach($frequencies as $key => $val) {

		if($val > $highestCount) {
			$char = $key;
			$highestCount = $val;
//			echo "Trying character: ".$key." : {$val}, it is the current highest\n";
		} else {
//			echo "Trying character: ".$key." : {$val}\n";
		}

		$sum += $val;
	}

	$div = round($highestCount / $sum * 100,2);

//	echo "Percent of this character: {$div}\n";

	return $char;
}

function fluhrerKSA($knownSoFar) {

	$key = str_split($knownSoFar);

	$s = array();

	for($i = 0 ; $i < 256 ; $i++) {
		$s[$i] = $i;
	}

	$j = 0;

	for($i = 0 ; $i < strlen($knownSoFar) ; $i++) {

		$j = truemod(($j + $s[$i] + ord($key[$i])) , 256);

		$currI = $s[$i];
		$currJ = $s[$j];

		$s[$j] = $currI;
		$s[$i] = $currJ;

	}

	return array("ksa" => $s, "j" => $j);

}

function kleinKSA($knownSoFar) {

	$key = str_split($knownSoFar);

	$s = array();

	for($i = 0 ; $i < 256 ; $i++) {
		$s[$i] = $i;
	}

	$j = 0;

	for($i = 0 ; $i < strlen($knownSoFar) ; $i++) {

		$j = truemod(($j + $s[$i] + ord($key[$i])) , 256);

		$currI = $s[$i];
		$currJ = $s[$j];

		$s[$j] = $currI;
		$s[$i] = $currJ;

	}

	return array("ksa" => $s, "j" => $j);
}

function getWeakness($iv,$pointAt) {

	$exp = str_split($iv);

	if(ord($exp[1]) == 255 && ord($exp[0]) == ($pointAt + 3)) {

		return true;
	} else {
		return false;
	}

}

function generateIV() {

	$iv = "";

	$iv .= chr(rand(3,64));
//	$iv .= chr(rand(0,255));
//	$iv .= chr(rand(0,255));
	$iv .= chr(255);
	$iv .= chr(rand(0,255));

	return $iv;
}

function generateRandomString() {

	$rand = rand(5,64);

	// deterministic first character for reasons
	$string = "aaa";

	for($i = 0 ; $i < $rand ; $i++) {
		$string .= chr(rand(65,126));
	}

//	echo $string."\n\n\n\n";

	return $string;

}

function PRGA($ksa, $string) {

	$stream = str_split($string);

	$kChar = "";

	$ni = 0;
	$nj = 0;

	foreach($stream as $char) {

		$ni = truemod(($ni + 1) , 256);
		$nj = truemod(($nj + $ksa[$ni]) , 256);

		$currI = $ksa[$ni];
		$currJ = $ksa[$nj];

		$ksa[$nj] = $currI;
		$ksa[$ni] = $currJ;

		$kChar .= $char ^ chr($ksa[truemod(($ksa[$ni] + $ksa[$nj]) , 256)]);

	}

	return $kChar;

}

function truemod($num, $mod) {
	return ($mod + ($num % $mod)) % $mod;
}

class rc4cryptor {

	public $output;

	public function __construct($input,$key) {

		$ksa = $this->rc4($key);

		$stream = str_split($input);

		$kChar = "";

		$ni = 0;
		$nj = 0;

		foreach($stream as $char) {

			$ni = truemod(($ni + 1) , 256);
			$nj = truemod(($nj + $ksa[$ni]) , 256);

			$currI = $ksa[$ni];
			$currJ = $ksa[$nj];

			$ksa[$nj] = $currI;
			$ksa[$ni] = $currJ;

			$kChar .= $char ^ chr($ksa[truemod(($ksa[$ni] + $ksa[$nj]) , 256)]);

		}

		$this->output = $kChar;

	}

	public function rc4($password) {

		$s = array();

		$key = str_split($password);

		for($i = 0 ; $i < 256 ; $i++) {
			$s[$i] = $i;
		}

		$j = 0;

		for($i = 0 ; $i < 256 ; $i++) {

			$j = truemod(($j + $s[$i] + ord($key[$i%count($key)])) , 256);

			$currI = $s[$i];
			$currJ = $s[$j];

			$s[$j] = $currI;
			$s[$i] = $currJ;
		}

		return $s;
	}


}

?>
