import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class PetaCiperLogGenerator extends LogGenerator {
	private static final String[] alertType = {
		"DBSECU_SECUSVR_ALERT"
		, "DBSECU_SECUSVR_WARN"
		, "DBSECU_SECUSVR_CRITICAL"
		, "DBUSE_USEVR_ALERT"
		, "DBUSE_USEVR_WARN"
		, "DBUSE_USEVR_CRITICAL"
	};
	private static final String[] event = {
		"Authentication Fail"
		, "Authentication Error"
		, "Too Many Authentication Fail"
		, "Too Much Select/Insert/Update Query"
		, "Too long Select/Insert/Update Query"	
		, "Too Much Select Return Rows"
		, "Too Much Select Return Data/Traffic"
	};

	private final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyy.MM.dd HH:mm:ss" );

	public PetaCiperLogGenerator() {
		super();
	}

	public PetaCiperLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 5;
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
		map.put( "no", random.nextInt(3) +33 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// Client IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// EVENT
		map.put( "etc1", event[random.nextInt(event.length)] );
		// ALERT_TYPE
		map.put( "etc2", alertType[random.nextInt(alertType.length)] );
		// SQL_TYPE
		map.put( "etc3", "SELECT" );
		// SERVICE_NAME
		map.put( "etc4", "DGDB" );
		// DB_SERVER_IP
		map.put( "etc5", getRandomLocalIP() );
		// DB_NAME
		map.put( "etc6", "SAMPLE" );
		// DB_USER
		map.put( "etc7", "SCOTT" );
		// LAPSE_TIME
		map.put( "etc8", random.nextInt(100) );
		// RETURN_ROWS
		map.put( "etc9", random.nextInt(10000) );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		strBld.append( "(" ).append( "ALERT_TYPE" ).append( "=" ).append( map.get("etc2") ).append( ")" )
				.append( "(" ).append( "SQL_TYPE" ).append( "=" ).append( map.get("etc3") ).append( ")" )
				.append( "(" ).append( "TIME" ).append( "=" ).append( dateFormat.format(map.get("date_created")) ).append( ")" )
				.append( "(" ).append( "EVENT" ).append( "=" ).append( map.get("etc1") ).append( ")" )
				.append( "(" ).append( "LEVEL" ).append( "=" ).append( "" ).append( ")" )
				.append( "(" ).append( "SERVER_IP" ).append( "=" ).append( getRandomLocalIP() ).append( ")" )
				.append( "(" ).append( "SERVICE_NAME" ).append( "=" ).append( map.get("etc4") ).append( ")" )
				.append( "(" ).append( "SERVICE_PORT" ).append( "=" ).append( random.nextInt(65535) +1 ).append( ")" )
				.append( "(" ).append( "SESSION_ID" ).append( "=" ).append( "10" ).append( ")" )
				.append( "(" ).append( "CLIENT_IP" ).append( "=" ).append( map.get("ip") ).append( ")" )
				.append( "(" ).append( "DB_SERVER_IP" ).append( "=" ).append( map.get("etc5") ).append( ")" )
				.append( "(" ).append( "DB_NAME" ).append( "=" ).append( map.get("etc6") ).append( ")" )
				.append( "(" ).append( "DB_USER" ).append( "=" ).append( map.get("etc7") ).append( ")" )
				.append( "(" ).append( "STMT_ID" ).append( "=" ).append( "30" ).append( ")" )
				.append( "(" ).append( "LAPSE_TIME" ).append( "=" ).append( map.get("etc8") ).append( ")" )
				.append( "(" ).append( "ACCESS_PROTOCOL" ).append( "=" ).append( "TCP" ).append( ")" )
				.append( "(" ).append( "CLIENT_PROGRAM" ).append( "=" ).append( "Java_TTC-8.2.0" ).append( ")" )
				.append( "(" ).append( "RETURN_CODE" ).append( "=" ).append( "" ).append( ")" )
				.append( "(" ).append( "RETURN_ROWS" ).append( "=" ).append( map.get("etc9") ).append( ")" )
				.append( "(" ).append( "USER_ID" ).append( "=" ).append( "" ).append( ")" );

		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new PetaCiperLogGenerator().makeLog( new Date() ) );
	}
}
