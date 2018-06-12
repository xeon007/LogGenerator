import java.text.SimpleDateFormat;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class TessTMSLogGenerator extends LogGenerator {
	private final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyyMMddHHmmss" );
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

	public TessTMSLogGenerator() {
		super();
	}

	public TessTMSLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 2;
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		Map<String, Object> map = new HashMap<>();

		ABNORMAL abnormalInfo = getAbnormalInfo();

		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		map.put( "type", 1 );
 		map.put( "category", 2 );
		map.put( "task_status", 1 );
 		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		map.put( "network", random.nextInt(3) +1 );
 		map.put( "description", null );

		int no = random.nextInt( 2 ) +21;
		map.put( "no", no );
		if( no == 21 ) makeDetectLog( map, abnormalInfo );
		else makeTrafficLog( map, abnormalInfo );

		return map;
	}

	private void makeDetectLog( Map<String, Object> baseMap, ABNORMAL abnormalInfo ) {
		// Destination IP
		baseMap.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );

		Date date = (Date)baseMap.get( "date_created" );
		// 최초탐지시간
		// 초 단위는 truncate 하고 분 단위는 1분 전으로...
 		baseMap.put( "etc1", dateFormat.format(Date.from(date.toInstant().truncatedTo(ChronoUnit.SECONDS).minus(1, ChronoUnit.MINUTES))) );
		// 최종탐지시간
		// 초 단위는 0~4 사이 값으로 랜덤하게 더하기
 		baseMap.put( "etc2", dateFormat.format(Date.from(date.toInstant().truncatedTo(ChronoUnit.SECONDS).minus(1, ChronoUnit.MINUTES).plus(random.nextInt(5), ChronoUnit.SECONDS))) );
		// Action
 		baseMap.put( "etc3", "0" );
		// Protocol
		baseMap.put( "etc4", "17" );
		// 탐지건수
		baseMap.put( "etc5", String.valueOf(random.nextInt(10) +1) );
		// 탐지이벤트 개수
		baseMap.put( "etc6", String.valueOf(random.nextInt(5) +1) );
 		// Inbound 여부
		baseMap.put( "etc7", String.valueOf(random.nextInt(2) +1) );
		// CVE 코드
		baseMap.put( "etc8", null );
		// 공격형태명
		baseMap.put( "etc9", attackNameArr[random.nextInt(attackNameArr.length)] );

		baseMap.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		baseMap.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		baseMap.put( "policy_id", null );
		baseMap.put( "name", null );
		baseMap.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		// 기관코드1
		strBld.append( "0" ).append( "|" )
		// 기관코드2
				.append( "1" ).append( "|" )
		// 데이터 생성시간
				.append( dateFormat.format(baseMap.get("date_created")) ).append( "|" )
		// 탐지기간 내 최초 침입탐지시간
				.append( baseMap.get("etc1") ).append( "|" )
		// 최종 침입탐지시간
				.append( baseMap.get("etc2") ).append( "|" )
		// Device IP
				.append( getRandomLocalIP() ).append( "|" )
		// 분류(2: 침입탐지 이벤트)
				.append( "2" ).append( "|" )
		// Source IP
				.append( getRandomGlobalIP() ).append( "|" )
		// Source Port
				.append( random.nextInt(65535) + 1 ).append( "|" )
		// NAT IP???
				.append( "" ).append( "|" )
		// Destination IP
				.append( baseMap.get("ip") ).append( "|" )
		// DestinationSource Port
				.append( random.nextInt(65535) + 1 ).append( "|" )
				.append( baseMap.get("etc4") ).append( "|" )
				.append( baseMap.get("etc7") ).append( "|" )
				.append( baseMap.get("etc3") ).append( "|" )
				.append( baseMap.get("etc9") ).append( "|" )
		// CVE 코드
				.append( baseMap.get("etc8") ).append( "|" )
		// BugTraq 코드
				.append( "0" ).append( "|" )
		// 탐지 이벤트 개수
				.append( baseMap.get("etc6") ).append( "|" )
		// 탐지 건수
				.append( baseMap.get("etc5") ).append( "|" )
		// 탐지 이벤트 바이트 수
				.append( String.valueOf(getRandomNumber(5)) );
		baseMap.put( KEY_RAW, strBld.toString() );
	}

	private void makeTrafficLog( Map<String, Object> baseMap, ABNORMAL abnormalInfo ) {
		// Destination IP
		baseMap.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );

		Date date = (Date)baseMap.get( "date_created" );
		// 종료시간
		// 초 단위는 1 ~ 60 사이 값으로 랜덤하게 더하기
 		baseMap.put( "etc1", dateFormat.format(Date.from(date.toInstant().plus(random.nextInt(60) +1, ChronoUnit.SECONDS))) );
		// 프레임 크기(1: 64이하, 2:65 ~ 128, 3:129 ~ 256, 4:257 ~ 512, 5:513 ~ 1024, 6:1024 초과
 		baseMap.put( "etc2", String.valueOf(random.nextInt(6) +1) );
		// Inbound 프레임 수
 		baseMap.put( "etc3", "0" );
		// Inbound 바이트 수
		baseMap.put( "etc4", "0" );
		// Outbound 프레임 수
		baseMap.put( "etc5", "0" );
		// Outbound 바이트 수
		baseMap.put( "etc6", "0" );
 		// 분류
		baseMap.put( "etc7", "1" );
		// 프로토콜
		baseMap.put( "etc8", "17" );
		// 공격형태명
		baseMap.put( "etc9", null );

		baseMap.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		baseMap.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		baseMap.put( "policy_id", null );
		baseMap.put( "name", null );
		baseMap.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		// 기관코드1
		strBld.append( "0" ).append( "|" )
		// 기관코드2
				.append( "1" ).append( "|" )
		// Node Device
				.append( getRandomLocalIP() ).append( "|" )
		// 분류(1: 트래픽 데이터)
				.append( baseMap.get("etc7") ).append( "|" )
		// 정보 수집 시간
				.append( dateFormat.format(date) ).append( "|" )
		// 종료 시간
				.append( baseMap.get("etc1") ).append( "|" )
		// 포트
				.append( String.valueOf(random.nextInt(65535) + 1) ).append( "|" )
		// Protocol
				.append( baseMap.get("etc8") ).append( "|" )
		// 프레임 크기(1: 64이하, 2:65 ~ 128, 3:129 ~ 256, 4:257 ~ 512, 5:513 ~ 1024, 6:1024 초과
				.append( baseMap.get("etc2") ).append( "|" )
		// Unknown
				.append( "0" ).append( "|" )
		// Inbound 프레임 수
				.append( baseMap.get("etc3") ).append( "|" )
		// Inbound 바이트 수
				.append( baseMap.get("etc4") ).append( "|" )
		// Outbound 프레임 수
				.append( baseMap.get("etc5") ).append( "|" )
		// OutInbound 바이트 수
				.append( baseMap.get("etc6") );

		baseMap.put( KEY_RAW, strBld.toString() );
	}

	public static void main( String ... args ) {
		System.out.println( new TessTMSLogGenerator().makeLog(new Date()) );
	}
}
