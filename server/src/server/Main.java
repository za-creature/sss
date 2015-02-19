package server;

import java.io.File;
import java.util.Properties;

public class Main
{
	public static void main(final String[] args) throws Exception
	{
		String filename="config.ini", newPassword=null;
		boolean rebuild=false, helpScreen=false;

		for(int i=0; i<args.length; i++)
			if(args[i].length()>1&&args[i].charAt(0)=='-'){
				if(i<args.length-1){
					if(args[i].charAt(1)=='c')
						System.out.println("Loading config file "+(filename=args[i+1]));
					else if(args[i].charAt(1)=='p')
						newPassword=args[i+1];
				}
				if(args[i].charAt(1)=='r')
					rebuild=true;
				if(args[i].charAt(1)=='h')
					helpScreen=true;
			}

		final Properties config=new PersistentProperties(filename);
		final String dbname=config.getProperty("database", "data.db");
		final Database db=new Database(dbname, config);

		if(helpScreen){
			System.out.println("Usage: java server.jar [options]");
			System.out.println("Where options is a combination of the following:");
			System.out.println();
			System.out.println("        -c configfile        Loads configuration options from 'configfile'");
			System.out.println("        -p newpassword       Changes the master password to 'newpassword'");
			System.out.println("        -r                   Rebuilds the entire database to remove fragmentation");
			System.out.println("        -h                   Shows this screen");
			System.out.println();
		}
		if(newPassword!=null){
			db.setMasterPassword(null, newPassword.getBytes("utf-8"));
			System.out.println("Master password changed");
		}
		if(rebuild){
			System.out.println("Reindexing...");

			long start=System.currentTimeMillis();
			db.save(dbname+".new");
			db.close();

			new File(dbname+".bak").delete();
			new File(dbname).renameTo(new File(dbname+".bak"));
			new File(dbname+".new").renameTo(new File(dbname));

			System.out.println("Done ("+(System.currentTimeMillis()-start)/1000+"s)");
		}
		if(!helpScreen&&newPassword==null&&!rebuild)
			new SecretSharingServer(db, config).run();
	}
}