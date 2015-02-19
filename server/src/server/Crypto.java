package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Crypto
{
	protected static MessageDigest sha=null;
	protected SecretKey key;
	protected Cipher encrypt, decrypt;

	public Crypto(final String key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		this.key=new SecretKeySpec(Utils.md5(key.getBytes("utf-8")), "AES");
		this.encrypt=Cipher.getInstance("AES/ECB/NoPadding");
		this.decrypt=Cipher.getInstance("AES/ECB/NoPadding");

		this.encrypt.init(Cipher.ENCRYPT_MODE, this.key);
		this.decrypt.init(Cipher.DECRYPT_MODE, this.key);
	}

	public byte[] read(final DataInputStream is, final int length) throws IOException, IllegalBlockSizeException, BadPaddingException
	{
		if(length%16!=0)
		{
			final byte[] data=new byte[16*(1+length/16)];
			is.readFully(data);
			return Arrays.copyOf(this.decrypt.doFinal(data), length);
		}
		else
		{
			final byte[] data=new byte[16];
			is.readFully(data);
			return this.decrypt.doFinal(data);
		}
	}

	public void write(final DataOutputStream os, final byte[] data) throws IOException
	{
		if(data.length%16!=0)
			os.write(this.encrypt.update(Arrays.copyOf(data, 16*(1+data.length/16))));
		else
			os.write(this.encrypt.update(data));
	}
}