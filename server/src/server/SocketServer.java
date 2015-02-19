package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class SocketServer
{
	protected ServerSocket server;

	protected abstract void connect(Socket client);

	public SocketServer(final int port) throws IOException
	{
		this.server=new ServerSocket(port);
	}

	protected void run() throws IOException
	{
		final SocketServer self=this;
		for(Socket client=this.server.accept(); client!=null; client=this.server.accept())
		{
			final Socket clone=client;
			new Thread(){
				@Override
				public void run()
				{
					self.connect(clone);
				}
			}.start();
		}
	}
}
