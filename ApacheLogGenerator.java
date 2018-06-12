import java.io.File;
import java.io.FileWriter;
import java.util.Date;
import java.util.UUID;

class ApacheLogGenerator extends LogGenerator {
	private final String[] requestURL = {
		"www.interpark.com",
		"ticket.interpark.com"
	};

	private final String[] interparkId = {
		"",
		"guksm",
		"parkci",
		"iris",
		"staryou"
	};

	public ApacheLogGenerator() {}

	private String getRequestURL() {
		StringBuilder strBld = new StringBuilder().append( "\"GET " );

		strBld.append( "http://" )
			.append( requestURL[ random.nextInt(requestURL.length) ] )
			.append( "/page/" )
			.append( random.nextInt(50) ).append( " HTTP/1.1\"" );

		return strBld.toString();
	}

	private String getClientHeader() {
		return "\"Mozilla/5.0 (compatible; MSIE or Firefox mutant; not on Windows server;) Daumoa/4.0\"";
	}

	private String getParameter() {
		StringBuilder strBld = new StringBuilder();

		strBld.append( "\"pcid=; interparkID=" )
			.append( interparkId[ random.nextInt(interparkId.length) ] )
			.append( "; Play_MemID=; interparkSNO=; ippcd=;\"" );

		return strBld.toString();
	}

	public String makeLog() {
		StringBuilder strBld = new StringBuilder();

		strBld.append( getRandomGlobalIP() ).append( " " )
			.append( "-" ).append( " " )
			.append( "-" ).append( " " )
			.append( "[" ).append( getLocalDateTime("dd/MMM/yyyy:HH:mm:ss Z") ).append( "] " )
			.append( getRequestURL() ).append( " " )
			.append( "200" ).append( " " ).append( random.nextInt(100000) );
//			.append( "200 0 \"-\"" ).append( " " );
//			.append( getClientHeader() ).append( " " )
//			.append( getParameter() );

		return strBld.toString();
	}

	/*
		arguments:
		1 - generate count
		2 - generate log file count(If <0 then infinite generate)
		3 - generate file path + filename. If null, current directory
	*/
	public static void main( String ... args ) throws Exception {
		if( args.length != 1 && args.length != 2 && args.length != 3 ) {
			System.out.println( "first parameter is generate count/second(not exactly)" );
			System.out.println( "second parameter is generate log file count. If negative number is infinite" );
			System.out.println( "third parameter is generate file path, name" );
			System.exit(0);
		}

		String filename = null;
		if( args.length == 3 && args[2].length() > 0 )
			filename = args[2];
		else
			filename = "interparkLog";

		int generateCount = 0;
		try {
			generateCount = Integer.parseInt( args[0] );
		} catch( NumberFormatException numEx ) {}

		if( generateCount <= 0 ) {
			System.out.println( "invalid first parameter("+ args[0] +")" );
			System.exit(0);
		}

		ApacheLogGenerator logGenerator = new ApacheLogGenerator();

		int logCount = args.length >= 2 && args[1].length() > 0 ? Integer.parseInt(args[1]) : -1;
		int fileIdx = 0;
		while( true ) {
			if( logCount > 0 && fileIdx >= logCount ) break;

			File file = new File( filename +"_"+ fileIdx++ +".generate" );
			FileWriter writer = new FileWriter( file, false );

			Date startDate = new Date();
			do {
				for( int i = 0; i < generateCount; i++ ) {
					writer.write( logGenerator.makeLog() +"\n" );
				}
				Thread.sleep( 800 );
			} while( logCount < 0 && new Date().getTime() - startDate.getTime() < 60000 );

			writer.flush();
			file.renameTo( new File(file.getAbsolutePath() +".log") );
			writer.close();
		}
	}
}
