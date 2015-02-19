<?php

class SecretStore
{
	//protocol constants
	protected static
		$method_set=1,
		$method_get=2,
		$method_del=3,
		$method_pass=4,
		$method_master=5,
		$errors=array(
			"Operation successful", //ok message
			"Bad password", "No such resource", "Invalid method", "Internal server error", //server response messages
			250 => "Read error", "Write error", "Data size mismatch" //client error messages
		);

	//instance parameters
	protected
		$code=0,
		$timeout=5,
		$sources=Array(),
		$persistent=true;

	protected static
		$devRandHandle=null;

	//write $string to $fp in as many chunks as it takes. returns true if the entire string was written, false otherwise 
	protected static function write($fp, $string)
	{
		for($written=0;$written<strlen($string);$written+=$fwrite)
			if(($fwrite=fwrite($fp, substr($string, $written)))===false)
				return false;
		return true;
	}

	//read a string consisting of $len bytes from $fp, in as many chunks as it takes. returns the string on success, boolean false otherwise
	protected static function read($fp, $len)
	{
		for($read="";$len>0;$len-=strlen($fread),$read.=$fread)
			if(($fread=fread($fp, $len))===false)
				return false;
		return $read;
	}

	//php sucks so we wrapped around the unpack function
	protected static function getByte($str)
	{
		$x=unpack("c1a", $str);
		return $x["a"];
	}

	protected static function getInt($str)
	{
		$x=unpack("N1a", $str);
		return $x["a"];
	}

	//encrypts a string using the supplied 128 bit AES key
	protected function encrypt($str)
	{
		return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $str, MCRYPT_MODE_ECB);
	}

	//decrypts a string of $len bytes from $str and removes any 0 padding
	protected function decrypt($str, $len)
	{
		return substr(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $str, MCRYPT_MODE_ECB), 0, $len);
	}

	//generate a random string with len bytes 
	protected static function randomStr($len)
	{
		if(self::$devRandHandle)//try to read from /dev/random if applicable
			$result=self::read(self::$devRandHandle, $len);
		else//mt_rand will just have to do
		{
			$result="";
			for($i=0;$i<$len;$i++)
				$result.=chr(mt_rand(0, 255));
		}
		return $result;
	}

	//returns the real length of an encrypted message of length $len
	protected static function getMessageLength($len){
		if($len%16)
			return round(16*(1+floor($len/16)));
		return $len;
	} 

	//returns the error message associated with $code
	public static function getErrorMessage($code)
	{
		return isset(self::$errors[$code])?self::$errors[$code]:"Unknown error $code";
	}

	//returns the error code for the last operation 
	public function getLastError()
	{
		return $this->code;	
	}

	//returns the error message for the last operation
	public function getLastErrorMessage()
	{
		return $this->getErrorMessage($this->getLastError());
	}

	//public constructor. connects to the secret sharing servers
	public function __construct($sources, $key, $timeout=5, $persistent=true)
	{
		$this->key=md5($key, true);
		$this->persistent=$persistent;
		$this->sources=array_flip($sources);
		$this->timeout=$timeout;
		if(self::$devRandHandle===null)
			self::$devRandHandle=@fopen("/dev/random", "rb");

		if(count($this->sources)<2)
			throw new Exception("At least two servers are required");

		foreach($this->sources as $source => &$connection)
		{
			list($hostname, $port)=explode(":", $source);
			if($this->persistent)
				$connection=@pfsockopen($hostname, $port, $err, $errStr, $this->timeout);
			else
				$connection=@fsockopen($hostname, $port, $err, $errStr, $this->timeout);
			if(!$connection)
				throw new Exception("Could not connect to $source: $errStr");
		}
	}

	//public destructor; releases non-persistent connections (if any)
	public function __destruct()
	{
		if(!$this->persistent)
			foreach($this->sources as $source => $connection)
				fclose($connection);
	}

	//adds a new entry protected by $password, containing $data and returns it's id
	public function add($password, $data)
	{
		$id=uniqid();
		$this->set($id, $password, $data);
		return $id;
	}

	//changes the data stored entry $id protected by $password (if exists) to $data 
	public function set($id, $password, $data)
	{
		$serial=serialize($data);
		$len=strlen($serial);
		$last=end($this->sources);

		//construct message
		$message=$message=pack("cc", self::$method_set, strlen($id)).$this->encrypt($id).pack("c", strlen($password)).$this->encrypt($password).pack("N", $len);
		foreach($this->sources as $source => $connection)
		{
			if($connection!==$last){
				$current=self::randomStr($len);
				$serial^=$current;
			}
			else
				$current=$serial;

			//send request
			if(!self::write($connection, $message.$this->encrypt($current))){
				$this->code=251;
				throw new Exception("Connection to $source failed while writing");
			}

			//check response code
			if(($str=self::read($connection, 1))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(($this->code=self::getByte($str))!==0)
				throw new Exception("Could not set resource $id on $source: ".$this->getLastErrorMessage());
		}
	}

	//retrieves the data stored in entry $id protected by $password
	public function get($id, $password)
	{
		//construct message
		$message=pack("cc", self::$method_get, strlen($id)).$this->encrypt($id).pack("c", strlen($password)).$this->encrypt($password);
		$serial="";
		foreach($this->sources as $source => $connection)
		{
			//send request
			if(!self::write($connection, $message)){
				$this->code=251;
				throw new Exception("Connection to $source failed while writing");
			}

			//check response code
			if(($str=self::read($connection, 1))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(($this->code=self::getByte($str))!==0)
				throw new Exception("Could not get resource $id on $source: ".$this->getLastErrorMessage());

			//get response length
			if(($str=self::read($connection, 4))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(isset($len)&&$len!==self::getInt($str)){
				$this->code=252;
				throw new Exception("Could not get resource $id on $source: ".$this->getLastErrorMessage());
			}
			else
				$len=self::getInt($str);

			//get response message 
			if(($str=self::read($connection, self::getMessageLength($len)))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if($serial)
				$serial^=$this->decrypt($str, $len);
			else
				$serial=$this->decrypt($str, $len);
		}
		return unserialize($serial);
	}

	//deletes entry $id protected by $password
	public function delete($id, $password)
	{
		//construct message
		$message=pack("cc", self::$method_del, strlen($id)).$this->encrypt($id).pack("c", strlen($password)).$this->encrypt($password);
		foreach($this->sources as $source => $connection)
		{
			//send request
			if(!self::write($connection, $message)){
				$this->code=251;
				throw new Exception("Connection to $source failed while writing");
			}

			//check response code
			if(($str=self::read($connection, 1))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(($this->code=self::getByte($str))!==0)
				throw new Exception("Could not delete resource $id on $source: ".$this->getLastErrorMessage());
		}
	}

	//changes the password protecting entry $id to $newPassword
	public function setPassword($id, $password, $newPassword)
	{
		//construct message
		$message=pack("cc", self::$method_pass, strlen($id)).$this->encrypt($id).pack("c", strlen($password)).$this->encrypt($password).pack("c", strlen($newPassword)).$this->encrypt($newPassword);
		foreach($this->sources as $source => $connection)
		{
			//send request
			if(!self::write($connection, $message)){
				$this->code=251;
				throw new Exception("Connection to $source failed while writing");
			}

			//check response code
			if(($str=self::read($connection, 1))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(($this->code=self::getByte($str))!==0)
				throw new Exception("Could not set password for resource $id on $source: ".$this->getLastErrorMessage());
		}
	}

	//changes the master password to $newPassword
	public function setMasterPassword($password, $newPassword)
	{
		//construct message
		$message=pack("cc", self::$method_master, strlen($password)).$this->encrypt($password).pack("c", strlen($newPassword)).$this->encrypt($newPassword);
		foreach($this->sources as $source => $connection)
		{
			//send request
			if(!self::write($connection, $message)){
				$this->code=251;
				throw new Exception("Connection to $source failed while writing");
			}

			//check response code
			if(($str=self::read($connection, 1))===false){
				$this->code=250;
				throw new Exception("Connection to $source failed while reading");
			}
			if(($this->code=self::getByte($str))!==0)
				throw new Exception("Could not set master password on $source: ".$this->getLastErrorMessage());
		}
	}
}

?>