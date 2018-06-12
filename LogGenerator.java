import java.math.BigDecimal;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.Arrays;;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

abstract class LogGenerator {
	// default 0.1%
	public static final int DEFAULT_ABNORMAL_PERCENTAGE = 1000;
	public static final String KEY_RAW = "__raw__";

	protected enum IP_TYPE { LOCAL, GLOBAL };
	protected enum IP_REPRESENTATION_TYPE { DOT_STR, NUMERIC };

	protected enum ABNORMAL {
		SITE1( "사이트-1", 1, 1, "192.168.10.5", "192.168.10.6", "192.168.10.7" )
		, SITE2( "사이트-2", 3, 2, "172.16.0.11", "172.16.0.12", "172.16.0.13" )
		, SITE5( "사이트-5", 3, 5, "172.16.10.32", "172.16.10.33", "172.16.10.34" )
		, SITE7( "사이트-7", 4, 7, "203.253.25.104", "203.253.25.105" )
		, SITE8( "사이트-8", 4, 8, "203.253.26.101", "203.253.26.102", "203.253.26.103" )
		, SITE10( "사이트-10", 1, 10, "192.168.20.10", "192.168.20.11" )
		, SITE19( "사이트-19", 1, 19, "192.168.30.21", "192.168.30.22", "192.168.30.23" )
		, SITE27( "사이트-27", 3, 27, "172.16.30.51", "172.16.30.52", "172.16.30.53" )
		, SITE29( "사이트-29", 2, 29, "10.0.40.15", "10.0.40.16", "10.0.40.17" )
		, SITE32( "사이트-32", 4, 32, "203.252.20.101", "203.252.20.102", "203.252.20.103" )
		, SITE39( "사이트-39", 1, 39, "192.168.40.32", "192.168.40.33", "192.168.40.34" )
		, SITE41( "사이트-41", 3, 41, "172.16.50.71", "172.16.50.72", "172.16.50.73" )
		, SITE43( "사이트-43", 2, 43, "10.10.0.5", "10.10.0.6", "10.10.0.7" )
		, SITE47( "사이트-47", 4, 47, "203.201.10.10", "203.201.10.11" )
		, SITE53( "사이트-53", 2, 53, "10.0.30.5", "10.0.30.6" )
		, SITE64( "사이트-64", 2, 64, "10.0.50.21", "10.0.50.22", "10.0.50.23" )
		, SITE69( "사이트-69", 4, 69, "203.201.20.101", "203.201.20.111" )
		, SITE75( "사이트-75", 2, 75, "10.20.0.11", "10.20.0.12", "10.20.0.13" )
		, SITE84( "사이트-84", 1, 84, "192.168.50.43", "192.168.50.44" )
		, SITE92( "사이트-92", 3, 92, "172.16.100.2", "172.16.100.3" );

		private final String name;
		private final int id;
		private final int groupId;
		private final String[] ip;
		private final List<Integer> idList = new ArrayList<>();

		ABNORMAL( String name, int groupId, int id, String ... ip ) {
			this.name = name;
			this.id = id;
			this.idList.add( id );
			this.groupId = groupId;
			this.ip = ip;
		}

		public int getGroupId() {
			return groupId;
		}

		public int getId() {
			return id;
		}

		public List<Integer> getIdList() {
			return idList;
		}

		public String getName() {
			return name;
		}

		public String getIp() {
			return ip[ random.nextInt(ip.length) ];
		}
	};

	protected static final Random random = new Random();

	private static final char[] mac = { 'a','b','c','d','e','f','0','1','2','3','4','5','6','7','8','9' };
	private final List<String> prefixLocalIP; 
	private final ABNORMAL[] abnormalArr;
	private final int abnormalPercentage;
	private final List<Integer> abnormalIdList;

	protected LogGenerator() {
		this( DEFAULT_ABNORMAL_PERCENTAGE );
	}

	/**
	 * abnormal percentage 는 여러가지 이유로 인하여 일반적으로 표기되는 방법대로 수행하지 않는다.
	 * 1 일 경우는 100%
	 * 2 일 경우는 50%
	 * 3 일 경우는 33%
	 * 4 일 경우는 25%
	 * 5 일 경우는 20%
	 * 10 일 경우는 10%
	 * 100 일 경우는 1%
	 * 500 일 경우는 0.2%
	 * 1000 일 경우는 0.1%
	 */
	protected LogGenerator( int abnormalPercentage ) {
		prefixLocalIP = new ArrayList<>();
		prefixLocalIP.add( "10.10." );
		prefixLocalIP.add( "192.168." );
		abnormalArr = ABNORMAL.class.getEnumConstants();
		abnormalIdList = new ArrayList<>();
		for( ABNORMAL abnormal : abnormalArr )
			abnormalIdList.add( abnormal.getId() );

		this.abnormalPercentage = abnormalPercentage;
	}

	protected String convertIpToDotStr( long ipValue ) {
		return ((ipValue >> 24) & 0xFF) +"."+ ((ipValue >> 16) & 0xFF) +"."+ ((ipValue >> 8) & 0xFF) +"."+ (ipValue & 0xFF);
	}

	protected String convertIpToNumeric( String dotStrIp ) {
		long numericIp = 0;

		String[] ipArr = dotStrIp.split( "\\." );
		int pow = 3;
		for( String value : ipArr )
			numericIp += (Integer.parseInt(value) * Math.pow(256, pow--));

		return String.valueOf( numericIp );
	}

	protected ABNORMAL getAbnormalInfo() {
		if( random.nextInt(abnormalPercentage) == 0 )
			return abnormalArr[ random.nextInt(abnormalArr.length) ];

		return null;
	}

	abstract int getGeneratorIndex();

	protected String getLocalDateTime( String datePattern ) {
		return ZonedDateTime.now().format( DateTimeFormatter.ofPattern(datePattern, Locale.ENGLISH) );
	}

	protected String getRandomGlobalIP() {
		return getRandomGlobalIP( IP_REPRESENTATION_TYPE.DOT_STR );
	}

	protected String getRandomGlobalIP( IP_REPRESENTATION_TYPE ipRepresentationType ) {
		StringBuilder ip = new StringBuilder();
		do {
			ip.setLength( 0 );
			ip.append( random.nextInt(255) + 1 ).append( "." );
			ip.append( random.nextInt(255) + 1 ).append( "." );
		} while( prefixLocalIP.contains(ip) );

		ip.append( random.nextInt(255)+1 ).append( "." )
			.append( random.nextInt(255)+1 );

		if( ipRepresentationType == IP_REPRESENTATION_TYPE.NUMERIC )
			return convertIpToNumeric( ip.toString() );

		return ip.toString();
	}

	protected String getRandomLocalIP() {
		return getRandomLocalIP( IP_REPRESENTATION_TYPE.DOT_STR );
	}

	protected String getRandomLocalIP( IP_REPRESENTATION_TYPE ipRepresentationType ) {
		StringBuilder ip = new StringBuilder();

		ip.append( prefixLocalIP.get(random.nextInt(prefixLocalIP.size())) )
			.append( random.nextInt(255)+1 ).append( "." )
			.append( random.nextInt(255)+1 );

		if( ipRepresentationType == IP_REPRESENTATION_TYPE.NUMERIC )
			return convertIpToNumeric( ip.toString() );

		return ip.toString();
	}

	protected String getRandomIP( IP_TYPE ipType ) {
		return ipType == IP_TYPE.LOCAL ? getRandomLocalIP() : getRandomGlobalIP();
	}

	protected String getRandomMacAddress() {
		StringBuilder strBld = new StringBuilder();
		for( int i = 0; i < 5; i++ ) {
			strBld.append( mac[random.nextInt(mac.length)] ).append( mac[random.nextInt(mac.length)] ).append( "-" );
		}
		strBld.append( mac[random.nextInt(mac.length)] ).append( mac[random.nextInt(mac.length)] );

		return strBld.toString().toUpperCase();
	}

	protected int getRandomNormalId() {
		int id = -1;
		do {
			id = random.nextInt( 233 ) +1;
		} while( abnormalIdList.contains(id) );

		return id;
	}

	protected String getRandomNumber( int length ) {
		StringBuilder strBld = new StringBuilder();
		for( int i = 0; i < length; i++ )
			strBld.append( random.nextInt(10) );

		return String.valueOf( Integer.parseInt(strBld.toString()) );
	}

	abstract public Map<String, Object> makeLog( Date startDateTime );
}
