package server;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;

public class PersistentProperties extends Properties
{
	private static final long serialVersionUID=-2202258938338484585L;
	protected final String filename;

	public PersistentProperties(final String filename)
	{
		this.filename=filename;
		try
		{
			final FileInputStream f=new FileInputStream(filename);
			this.load(f);
			f.close();
		}
		catch(final Exception e)
		{
			System.out.println("Warning: could not read configuration file: "+filename+". Using defaults");
		}
	}

	@Override
	public Object setProperty(final String key, final String value)
	{
		final Object result=super.getProperty(key);
		super.setProperty(key, value);
		try
		{
			final FileOutputStream f=new FileOutputStream(this.filename);
			this.store(f, "Generated configuration file. DO NOT MODIFY SALT!");
			f.close();
		}
		catch(final Exception e)
		{
			System.out.println("Warning: could not write configuration file "+this.filename+". ");
		}
		return result;
	}
}