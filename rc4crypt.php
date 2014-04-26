<?php

@$password = $argv[1];

if(!$password) {
	die("Please put in a password!!\n");
}

$file = fopen("php://stdin","r");

$ni = 0;
$nj = 0;

$ksa = rc4($password);

while(!feof($file)) {

	$ni = truemod(($ni + 1) , 256);
	$nj = truemod(($nj + $ksa[$ni]) , 256);

	$currI = $ksa[$ni];
	$currJ = $ksa[$nj];

	$ksa[$nj] = $currI;
	$ksa[$ni] = $currJ;

	$kChar = fread($file,1) ^ chr($ksa[truemod(($ksa[$ni] + $ksa[$nj]) , 256)]);

//	$kChar = chr($ksa[($ksa[$ni] + $ksa[$nj]) % 256])."\n";

	echo $kChar;

//	$kChar = str_split($kChar);
//
//	foreach($kChar as $chr) {
//		echo dechex(ord($chr))."\n";
//	}

//	usleep(20000);
}

function truemod($num, $mod) {
	return ($mod + ($num % $mod)) % $mod;
}

function rc4($password) {

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


?>
