package server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils
{
	protected static MessageDigest sha=null, md5=null;

	public static String toHexString(final byte[] data)
	{
		if(data==null)
			return null;

		final String HEXES="0123456789abcdef";
		final StringBuilder hex=new StringBuilder(2*data.length);

		for(final byte b:data)
			hex.append(HEXES.charAt((b&0xF0)>>4)).append(HEXES.charAt((b&0x0F)));
		return hex.toString();
	}

	public static byte[] toByteArray(final String data) throws IllegalArgumentException
	{
		if(data.length()%2==1)
			throw new IllegalArgumentException();

		final int len=data.length();
		final byte[] bin=new byte[len/2];
		for(int i=0; i<len; i+=2)
			bin[i/2]=(byte)((Character.digit(data.charAt(i), 16)<<4)+Character.digit(data.charAt(i+1), 16));
		return bin;
	}

	public static synchronized byte[] sha256(final byte[] data, final byte[] salt)
	{
		try
		{
			if(Utils.sha==null)
				Utils.sha=MessageDigest.getInstance("sha-256");
			else
				Utils.sha.reset();
			if(salt!=null)
				Utils.sha.update(salt);
			return Utils.sha.digest(data);
		}
		catch(final NoSuchAlgorithmException e)
		{
			return null;
		}
	}

	public static byte[] sha256(final byte[] data)
	{
		return Utils.sha256(data, null);
	}

	public static synchronized byte[] md5(final byte[] data)
	{
		try
		{
			if(Utils.md5==null)
				Utils.md5=MessageDigest.getInstance("md5");
			else
				Utils.md5.reset();
			return Utils.md5.digest(data);
		}
		catch(final NoSuchAlgorithmException e)
		{
			return null;
		}
	}

	public static String randomString(final int length)
	{
		final String alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+,./<>?;'[]\\:\"";
		final StringBuilder result=new StringBuilder();
		for(int i=0; i<length; i++)
			result.append(alphabet.charAt((int)(Math.random()*alphabet.length())));
		return result.toString();
	}

	public static String randomString()
	{
		return Utils.randomString(10+(int)(Math.random()*22));
	}
}