<?php

	require_once("SecretStore.class.php");
	$secret=new SecretStore(array("localhost:324", "localhost:325"), "this is a secret key");

	//sample add; data is array but can be any serializable format
	$mySecretData=array("cardNumber" => "1234", "lastPayment" => time());
	$someId=$secret->add("password", $mySecretData);

	//sample change
	$mySecretData["cardNumber"]=1235;
	$secret->set($someId, "password", $mySecretData);

	//sample password change
	$secret->setPassword($someId, "password", "newPass");

	try{
		//test password change
		var_dump($secret->get($someId, "password"));
	}
	catch(Exception $e){
		echo $e->getMessage()."\n";
	}

	//sample get
	var_dump($secret->get($someId, "newPass"));

	//sample delete
	$secret->delete($someId, "newPass");

	//test delete
	try{
		$secret->get($someId, "newPass");
	}
	catch(Exception $e){
		echo $e->getMessage()."\n";
	}
?>