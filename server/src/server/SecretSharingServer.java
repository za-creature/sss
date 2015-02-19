package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Socket;
import java.net.SocketException;
import java.util.Properties;

class InvalidMethodException extends Exception
{
	private static final long serialVersionUID=-4987271428008492516L;
}

public class SecretSharingServer extends SocketServer
{
	protected static final int
		METHOD_SET=1,
		METHOD_GET=2,
		METHOD_DELETE=3,
		METHOD_PASS=4,
		METHOD_MASTER=5, 
		RESPONSE_OK=0,//all is peachy
		RESPONSE_PASS=1,//bad password
		RESPONSE_KEY=2,//bad key
		RESPONSE_METHOD=3,//bad method
		RESPONSE_INTERNAL=4;//request is fine but the server fucked up

	protected int timeout, linger, max, connections=0;

	protected Database db;
	protected Logger log;
	protected Crypto crypto;

	public SecretSharingServer(final Database db, final Properties config) throws Exception
	{
		super(Integer.parseInt(config.getProperty("port", "325")));//default port is 325
		this.timeout=Integer.parseInt(config.getProperty("timeout", "500000"));//keep connections alive for 500 seconds by default
		this.linger=Integer.parseInt(config.getProperty("linger", "5"));//allow for up to 5 seconds for the final error code to be sent
		this.max=Integer.parseInt(config.getProperty("max_packet", ""+Integer.MAX_VALUE));//maximum data chunk size
		this.connections=Integer.parseInt(config.getProperty("max_connections", "64"));//default at least 64 connections
		this.crypto=new Crypto(config.getProperty("encryption_key", "blablabla"));
		this.log=new Logger(config);
		this.db=db;
		System.out.println("Listening for connections on "+config.getProperty("port", "325"));
	}

	@Override
	protected void connect(final Socket client)
	{
		//check connection limit
		synchronized(this)
		{
			if(--this.connections==0)
			{
				try
				{
					client.close();
				}
				catch(final Exception e)
				{
					/* Stub */
				}
				this.connections++;
				return;
			}
		}

		final StringBuffer message=new StringBuffer().append("[").append(client.getInetAddress().getCanonicalHostName()).append("(").append(client.getInetAddress().getHostAddress()).append(")]: ");
		final int length=message.length();
		try
		{
			//set socket properties
			client.setSoLinger(this.linger!=0, this.linger);
			client.setSoTimeout(this.timeout);

			//get associated streams
			final DataInputStream is=new DataInputStream(client.getInputStream());
			final DataOutputStream os=new DataOutputStream(client.getOutputStream());
			while(client.isConnected()&&!client.isClosed())
			{
				message.setLength(length);//reset message 
				try
				{
					final int code=is.read();

					if(code==SecretSharingServer.METHOD_SET)
					{
						final byte[] key=this.crypto.read(is, is.read());
						final byte[] pass=this.crypto.read(is, is.read());
						final byte[] data=this.crypto.read(is, is.readInt());

						message.append("Set ").append(new String(key)).append(": ");
						this.db.set(key, pass, data);
						os.write(SecretSharingServer.RESPONSE_OK);
						this.log.write(0, message.append("Ok").toString());
					}
					else if(code==SecretSharingServer.METHOD_GET)
					{
						final byte[] key=this.crypto.read(is, is.read());
						final byte[] pass=this.crypto.read(is, is.read());

						message.append("Get ").append(new String(key)).append(": ");
						final byte[] data=this.db.get(key, pass);
						os.write(SecretSharingServer.RESPONSE_OK);
						os.writeInt(data.length);
						this.crypto.write(os, data);
						this.log.write(0, message.append("Ok").toString());
					}
					else if(code==SecretSharingServer.METHOD_DELETE)
					{
						final byte[] key=this.crypto.read(is, is.read());
						final byte[] pass=this.crypto.read(is, is.read());

						message.append("Delete ").append(new String(key)).append(": ");
						this.db.delete(key, pass);
						os.write(SecretSharingServer.RESPONSE_OK);
						this.log.write(0, message.append("Ok").toString());
					}
					else if(code==SecretSharingServer.METHOD_PASS)
					{
						final byte[] key=this.crypto.read(is, is.read());
						final byte[] pass=this.crypto.read(is, is.read());
						final byte[] newPass=this.crypto.read(is, is.read());

						message.append("Change password ").append(new String(key)).append(": ");
						this.db.setPassword(key, pass, newPass);
						os.write(SecretSharingServer.RESPONSE_OK);
						this.log.write(0, message.append("Ok").toString());
					}
					else if(code==SecretSharingServer.METHOD_MASTER)
					{
						final byte[] pass=this.crypto.read(is, is.read());
						final byte[] newPass=this.crypto.read(is, is.read());

						message.append("Change master password ").append(": ");
						this.db.setMasterPassword(pass, newPass);
						os.write(SecretSharingServer.RESPONSE_OK);
						this.log.write(0, message.append("Ok").toString());
					}
					else
						throw new InvalidMethodException();//bad method
				}
				catch(final Throwable e)
				{
					if(e instanceof EntryNotFoundException)
					{
						this.log.write(1, message.append("Failed: Bad key").toString());
						os.write(SecretSharingServer.RESPONSE_KEY);
					}
					else if(e instanceof IllegalArgumentException)
					{
						this.log.write(1, message.append("Failed: Bad password").toString());
						os.write(SecretSharingServer.RESPONSE_PASS);
					}
					else if(e instanceof SocketException)
						throw (SocketException)e;
					else if(e instanceof IOException)
					{
						this.log.write(1, message.append("Failed: Internal IO error").toString());
						os.write(SecretSharingServer.RESPONSE_INTERNAL);
					}
					else if(e instanceof InvalidMethodException||e instanceof OutOfMemoryError)
					{
						this.log.write(1, message.append("Invalid query. Connection closed").toString());
						os.write(SecretSharingServer.RESPONSE_METHOD);
						client.close();
					}
					else
					{
						//store the throwable
						final StringWriter result=new StringWriter();
						e.printStackTrace(new PrintWriter(result));
						this.log.write(2, result.toString());

						//ensure the non-memory related error gets propagated through
						if(e instanceof Exception)
							throw (Exception)e;
						else
							throw (Error)e;
					}
				}
			}
		}
		catch(final Exception e)
		{
			//connection is closed
		}

		//notify master that thread just died
		synchronized(this)
		{
			this.connections++;
		}
	}
}
