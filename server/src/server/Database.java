package server;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.util.Comparator;
import java.util.Properties;
import java.util.TreeMap;

class EntryNotFoundException extends Exception
{
	private static final long serialVersionUID=-4346634710289765702L;
}

class DatabaseRow
{
	byte[] password;
	long pos;

	DatabaseRow(final byte[] password, final long pos)
	{
		this.password=password.clone();
		this.pos=pos;
	}
}

public class Database implements Comparator<byte[]>
{
	protected final RandomAccessFile handle;
	protected byte[] masterPassword;
	protected final byte[] salt;
	protected final Properties config;
	protected final TreeMap<byte[], DatabaseRow> index=new TreeMap<byte[], DatabaseRow>(this);

	public int compare(final byte[] a, final byte[] b)
	{
		int i=0;
		final int m=a.length;
		for(; i<m&&a[i]==b[i]; i++)
			;
		return i<m?a[i]-b[i]:0;
	}

	public Database(final String filename, final Properties config) throws IOException
	{
		System.out.println("Loading settings...");
		this.config=config;
		if(config.getProperty("salt")==null)
			config.setProperty("salt", Utils.randomString());
		this.salt=config.getProperty("salt", "").getBytes("UTF-8");

		final String pass=config.getProperty("password", "");
		if(pass.length()==64)
			this.masterPassword=Utils.toByteArray(pass);
		else
		{
			System.out.println("Could not read master password. Using default");
			this.masterPassword=Utils.sha256("admin".getBytes("UTF-8"), this.salt);
		}
		System.out.println("Building index...");
		final RandomAccessFile handle=this.handle=new RandomAccessFile(filename, "rws");
		final long len=handle.length();
		long pos=0, fragments=0, lost=0, blocks=0;
		final byte buffer[]=new byte[32];
		while(pos<len-4)
		{
			final int blockLen=handle.readInt();
			if(blockLen>0)
			{
				//read id
				handle.readFully(buffer);
				final byte key[]=buffer.clone();
				//read password
				handle.readFully(buffer);
				//read block data segment size
				final int tmp=handle.readInt();
				if(blockLen-tmp>72)
				{
					fragments++;
					lost+=blockLen-tmp-72;
				}

				//add row to index
				this.index.put(key, new DatabaseRow(buffer, pos));
				pos+=blockLen;
				blocks++;
			}
			else
			{
				fragments++;
				lost-=blockLen;
				//skip deleted row
				pos-=blockLen;
			}
			handle.seek(pos);
		}
		if(len==0)
			System.out.println("Created new database");
		else
		{
			System.out.println("Loaded "+this.index.size()+" entr"+(this.index.size()==1?"y":"ies"));
			System.out.println("Database fragmentation: "+lost*100/len+"% ("+fragments+" fragment"+(fragments==1?"":"s")+", "+lost+" bytes)");
		} 
	}

	//only called from synchronized methods; no need for additional lock
	protected final void append(final byte[] key, final byte[] password, final byte[] data) throws IOException
	{
		final long pos=this.handle.length();
		this.handle.seek(pos);
		this.handle.writeInt(data.length+72);
		this.handle.write(key);
		this.handle.write(password);
		this.handle.writeInt(data.length);
		this.handle.write(data);
		this.index.put(key, new DatabaseRow(password, pos));
	}

	protected final void mark(final long pos) throws IOException
	{
		this.handle.seek(pos);
		final int blockLen=this.handle.readInt();
		this.handle.seek(pos);
		this.handle.writeInt(-blockLen);
	}

	public synchronized byte[] get(byte[] key, byte[] password) throws IOException, EntryNotFoundException, IllegalArgumentException
	{
		key=Utils.sha256(key, this.salt);
		password=Utils.sha256(password, this.salt);

		final DatabaseRow row=this.index.get(key);
		if(row==null)
			throw new EntryNotFoundException();

		if(this.compare(password, row.password)!=0&&this.compare(password, this.masterPassword)!=0)
			throw new IllegalArgumentException();

		this.handle.seek(row.pos+68);
		final int size=this.handle.readInt();
		final byte[] result=new byte[size];
		this.handle.readFully(result);
		return result;
	}

	public synchronized void set(byte[] key, byte[] password, final byte[] data) throws IOException, IllegalArgumentException
	{
		key=Utils.sha256(key, this.salt);
		password=Utils.sha256(password, this.salt);

		final DatabaseRow row=this.index.get(key);
		if(row==null)
			this.append(key, password, data);
		else
		{
			if(this.compare(password, row.password)!=0&&this.compare(password, this.masterPassword)!=0)
				throw new IllegalArgumentException();

			this.handle.seek(row.pos);
			final int avail=this.handle.readInt()-72;
			if(avail>=data.length)
			{
				this.handle.seek(row.pos+68);
				this.handle.writeInt(data.length);
				this.handle.write(data);
			}
			else
			{
				//skip identical key
				this.handle.skipBytes(32);
				//copy old password in case the set is being done with administrative privileges
				this.handle.readFully(password);

				this.mark(row.pos);
				this.index.remove(key);
				this.append(key, password, data);
			}
		}
	}

	public synchronized void delete(byte[] key, byte[] password) throws IOException
	{
		key=Utils.sha256(key, this.salt);
		password=Utils.sha256(password, this.salt);

		final DatabaseRow row=this.index.get(key);
		if(row!=null&&(this.compare(password, row.password)==0||this.compare(password, this.masterPassword)==0))
		{
			this.mark(row.pos);
			this.index.remove(key);
		}
	}

	public synchronized void setPassword(byte[] key, byte[] password, byte[] newPassword) throws IOException, EntryNotFoundException, IllegalArgumentException
	{
		key=Utils.sha256(key, this.salt);
		password=Utils.sha256(password, this.salt);
		newPassword=Utils.sha256(newPassword, this.salt);

		final DatabaseRow row=this.index.get(key);
		if(row==null)
			throw new EntryNotFoundException();
		if(this.compare(password, row.password)!=0&&this.compare(password, this.masterPassword)!=0)
			throw new IllegalArgumentException();

		this.handle.seek(row.pos+36);
		this.handle.write(row.password=newPassword);
	}

	public synchronized void setMasterPassword(byte[] password, final byte[] newPassword) throws UnsupportedEncodingException
	{
		//no database IO is performed, however synchronization is required to prevent access faults
		if(password!=null)//exception for local setpassword
		{
			password=Utils.sha256(password, this.salt);
			if(this.compare(password, this.masterPassword)!=0)
				throw new IllegalArgumentException();
		}

		this.masterPassword=Utils.sha256(newPassword, this.salt);
		this.config.setProperty("password", Utils.toHexString(this.masterPassword));
	}

	public synchronized void save(String filename) throws IOException
	{
		RandomAccessFile f=new RandomAccessFile(filename, "rws");
		f.setLength(0);
		for(byte[] key:this.index.keySet())
		{
			final DatabaseRow row=this.index.get(key);
			this.handle.seek(row.pos+68);
			final int length=this.handle.readInt();
			final byte[] buffer=new byte[length];
			this.handle.readFully(buffer);

			f.writeInt(length+72);
			f.write(key);
			f.write(row.password);
			f.writeInt(length);
			f.write(buffer);
		}
		f.close();
	}

	public void close() throws IOException
	{
		this.index.clear();
		this.handle.close();
	}
}