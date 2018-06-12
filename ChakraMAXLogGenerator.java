import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class ChakraMAXLogGenerator extends LogGenerator {
	private static final String[] eventLevel = { "Normal", "Warning", "Critical" };
	private static final String[] dbType = { "ORACLE", "MariaDB", "DB2", "MySQL", "MSSQL", "PostgreSQL" };
	private static final String[] policyName = {
		"SYS 계정 접근 경보"
		, "SYSTEM 계정 접근 경보"
		, "ADMIN 계정 접근 경보"
		, "과다 쿼리 경보"
		, "인증 실패 경보"
	};

	public ChakraMAXLogGenerator() {
		super();
	}

	public ChakraMAXLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 4;
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		ABNORMAL abnormalInfo = getAbnormalInfo();

		Map<String, Object> map = new HashMap<>();
		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		map.put( "type", 1 );
		map.put( "category", 3 );
		map.put( "task_status", 1 );
		map.put( "no", random.nextInt(3) +30 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// Client IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// 정책명
		map.put( "etc1", policyName[random.nextInt(policyName.length)] );
		// DB 명
		map.put( "etc2", "ORA901(15)" );
		// DB 타입
		map.put( "etc3", dbType[random.nextInt(dbType.length)] );
		// Application
		map.put( "etc4", "JAVA" );
		// Client port
		map.put( "etc5", random.nextInt(65535) +1 );
		// HostName
		map.put( "etc6", "NEXMAN" );
		// User
		map.put( "etc7", "dms2" );
		// DB User
		map.put( "etc8", "EAI" );
		// 세션시작시간
		map.put( "etc9", startDateTime.getTime() );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		// 정책명
		strBld.append( map.get("etc1") ).append( " ; " )
		// 서버명
				.append( "E20k-b" ).append( " ; " )
		// DB명
				.append( map.get("etc2") ).append( " ; " )
		// 이벤트 레벨
				.append( eventLevel[random.nextInt(eventLevel.length)] ).append( " ; " )
		// DB 타입
				.append( map.get("etc3") ).append( " ; " )
		// Client IP
				.append( map.get("ip") ).append( " ; " )
		// Application Name
				.append( map.get("etc4") ).append( " ; " )
		// User
				.append( map.get("etc7") ).append( " ; " )
		// HostName
				.append( map.get("etc6") ).append( " ; " )
		// DB User
				.append( map.get("etc8") ).append( " ; " )
		// 세션시작시간
				.append( String.valueOf(startDateTime.getTime()) ).append( " ; " )
		// 발생시간
				.append( String.valueOf(startDateTime.toInstant().plus(random.nextInt(2), ChronoUnit.SECONDS).toEpochMilli()) );
		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new ChakraMAXLogGenerator().makeLog(new Date()) );
	}
}
