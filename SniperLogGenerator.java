import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class SniperLogGenerator extends LogGenerator {
	private final String[] attackNameArr = {
		"(0006)UDP Flooding",
		"(0015)IP Spoofing",
		"(0023)UDP Check Sum Error",
		"(0400)SMB Service connect(tcp-445)",
		"(0240)ARP Reply Poison(havoc)",
		"(0003)FIN Port Scan",
		"(0401)SMB Service sweep(tcp-445)",
		"(0102)FTP Login Brute Force",
		"(0476)DNS Request Flooding",
		"(0601)DHCP Discover Flooding",
		"(0183)SNMP Sweep (community string)",
		"(0113)Secure Shell Brute Force",
		"(5028)/cgi-bin/ HTTP (cgi-bin Directory view)",
		"(5450)index.jsp (JSP Request Source Code Disclosure Vulnerability)",
		"Directory Listing Vulnerability(IIS)",
		"DDoS Session Flooding [목동사내망]"
	};
	private final String[] protocol = { "tcp", "udp" };
	private final String[] risk = { "Low", "Medium", "High" };
	private final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyy/MM/dd HH:mm:ss" );

	public SniperLogGenerator() {
		super();
	}

	public SniperLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 6;
	}

	private String getInformation() {
		if( random.nextInt(100) >= 5 )
			return "";

		return "userid [], passwd []";
	}

	private String getProtocol() {
		StringBuilder strBld = new StringBuilder();
		strBld.append( protocol[random.nextInt(protocol.length)] )
			.append( "/" )
			.append( random.nextInt(65535) );

		return strBld.toString();
	}

	private String getRisk() {
		return risk[ random.nextInt(risk.length) ];
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		ABNORMAL abnormalInfo = getAbnormalInfo();

		Map<String, Object> map = new HashMap<>();
		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		map.put( "type", 1 );
		map.put( "category", 2 );
		map.put( "task_status", 1 );
		map.put( "no", random.nextInt(3) +26 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// Hacker
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// Attack Name
		map.put( "etc1", attackNameArr[random.nextInt(attackNameArr.length)] );
		// Hacker
		map.put( "etc2", map.get("ip") );
		// Victim
		map.put( "etc3", getRandomLocalIP() );
		// Protocol
		map.put( "etc4", getProtocol() );
		// Risk
		map.put( "etc5", getRisk() );
		// Handling
		map.put( "etc6", "Alarm" );
		// Information
		map.put( "etc7", getInformation() );
		// SrcPort
		map.put( "etc8", random.nextInt(65535 +1) );
		map.put( "etc9", null );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		strBld.append( "<36>[SNIPER-2000" ).append( " " )
			.append( "[Attack_Name=" ).append( map.get("etc1") ).append( "]" ).append( ", " )
			.append( "[Time=" ).append( dateFormat.format(map.get("date_created")) ).append( "]" ).append( ", " )
			.append( "[Hacker=" ).append( map.get("etc2") ).append( "]" ).append( ", " )
			.append( "[Victim=" ).append( map.get("etc3") ).append( "]" ).append( ", " )
			.append( "[Protocol=" ).append( map.get("etc4") ).append( "]" ).append( ", " )
			.append( "[Risk=" ).append( map.get("etc5") ).append( "]" ).append( ", " )
			.append( "[Handling=" ).append( map.get("etc6") ).append( "]" ).append( ", " )
			.append( "[Information=" ).append( map.get("etc7") ).append( "]" ).append( ", " )
			.append( "[SrcPort=" ).append( map.get("etc8") ).append( "]" );
		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) throws Exception {
		System.out.println( new SniperLogGenerator().makeLog( new Date() ) );
	}
}
