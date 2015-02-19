package server;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.text.DateFormat;
import java.util.Date;
import java.util.Properties;

public class Logger
{
	Writer[] fd=new Writer[3];
	DateFormat date=DateFormat.getInstance();

	public Logger(final Properties config) throws IOException
	{
		this.fd[0]=new FileWriter(config.getProperty("access", "access.log"), true);
		this.fd[1]=new FileWriter(config.getProperty("error", "error.log"), true);
		this.fd[2]=new FileWriter(config.getProperty("internal", "internal.log"), true);
	}

	public synchronized void write(final int priority, final String message) throws IOException
	{
		this.fd[priority].write(this.date.format(new Date())+": "+message+"\n");
		this.fd[priority].flush();
	}
}
