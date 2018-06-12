import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Locale;

class GiniNACLogGenerator extends LogGenerator {
	private static final String[] proto = { "TCP", "UDP" };
	private static final String[] result = { "SUCCESS", "FAIL" };
	private static final String[] logDetail = {
		"제어정책 할당됨"
		, "새로운 열린포트 감지됨"
		, "ARP SPOOFING 감지됨"
		, "열린포트 해제"
		, "공유 정보 추가 감지됨"
		, "노드 활성화상태 동기화실패"
		, "소프트웨어목록 삭제 감지됨"
		, "비관리 노드 감지됨"
		, "사용자계정 정보 변경 감지됨"
		, "운영체제 정보 변경 감지됨"
		, "인터페이스 상태 UP"
		, "저장장치 정보 삭제 감지됨"
		, "저장장치 정보 추가 감지됨"
		, "저장장치 정보 변경 감지됨"
		, "노드의 속성 변경됨"
	};
	private static final String[] svcName = {
		"NetBIOS 세션 서비스"
		, "RPC"
		, "RTSP"
		, "SMB"
		, "HTTPS"
		, "kdm"
	};
	private static final String[] action = {
		"무선LAN 접속 차단"
		, "운영체제정보 수집"
		, "비인가SW 차단"
		, "공유폴더해제프로그램 설치"
		, "네트워크정보 수집"
		, "원격데스크탑제어"
		, "IP 접속 차단"
		, "비인가 AP 수집"
		, "에이전트 삭제"
		, "저장장치 연결 수집"
		, "장치 제어"
	};

	private final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyy-MM-dd HH:mm:ss Z", Locale.ENGLISH );

	public GiniNACLogGenerator() {
		super();
	}

	public GiniNACLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 3;
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
		map.put( "no", random.nextInt(3) +23 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );

		// LOG_MSG
		map.put( "etc1", "에이전트액션 결과" );
		// PROTO
		map.put( "etc2", proto[random.nextInt(proto.length)] );
		// PORT
		map.put( "etc3", String.valueOf(random.nextInt(65535) +1) );
		// SVCNAME
		map.put( "etc4", svcName[random.nextInt(svcName.length)] );
		// ACTION
		map.put( "etc5", action[random.nextInt(action.length)] );
		// RESULT
		map.put( "etc6", result[random.nextInt(result.length)] );
		// TYPE
		map.put( "etc7", "NEW" );
		// LOG_DETAIL
		map.put( "etc8", logDetail[random.nextInt(logDetail.length)] );
		// LOG_EXTRAINFO
		map.put( "etc9", "" );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );


		StringBuilder strBld = new StringBuilder();
		strBld.append( "\"LOG_TIME\"" ).append( ":" ).append( "\"" ).append( dateFormat.format(map.get("date_created")) ).append( "\"" ).append( "," )
				.append( "\"LOG_SENSORIPSTR\"" ).append( ":" ).append( "\"" ).append( "" ).append( "\"" ).append( "," )
				.append( "\"LOG_MSG\"" ).append( ":" ).append( "\"" ).append( map.get("etc1") ).append( "\"" ).append( "," )
				.append( "\"ROLE/ID/NODEGRP\"" ).append( ":" ).append( "\"" ).append( "(인증)미인증 단말 차단정책" ).append( "\"" ).append( "," )
				.append( "\"BY\"" ).append( ":" ).append( "\"" ).append( "인증만료" ).append( "\"" ).append( "," )
				.append( "\"LOG_PARENTID\"" ).append( ":" ).append( "\"" ).append( java.util.UUID.randomUUID().toString() ).append( "\"" ).append( "," )
				.append( "\"IP\"" ).append( ":" ).append( "\"" ).append( map.get("ip") ).append( "\"" ).append( "," )
				.append( "\"PROTO\"" ).append( ":" ).append( "\"" ).append( map.get("etc2") ).append( "\"" ).append( "," )
				.append( "\"PORT\"" ).append( ":" ).append( map.get("etc3") ).append( "," )
				.append( "\"SVCNAME\"" ).append( ":" ).append( "\"" ).append( map.get("etc4") ).append( "\"" ).append( "," )
				.append( "\"ACTION\"" ).append( ":" ).append( "\"" ).append( map.get("etc5") ).append( "\"" ).append( "," )
				.append( "\"RESULT\"" ).append( ":" ).append( "\"" ).append( map.get("etc6") ).append( "\"" ).append( "," )
				.append( "\"TYPE\"" ).append( ":" ).append( "\"" ).append( map.get("etc7") ).append( "\"" ).append( "," )
				.append( "\"LOG_IP\"" ).append( ":" ).append( convertIpToNumeric((String)map.get("ip")) ).append( "," )
				.append( "\"LOG_EXTRAINFO\"" ).append( ":" ).append( "\"" ).append( map.get("etc9") ).append( "\"" ).append( "," )
				.append( "\"LOG_IDX\"" ).append( ":" ).append( "43698749" ).append( "," )
				.append( "\"LOG_PARENTNAME\"" ).append( ":" ).append( "\"" ).append( "" ).append( "\"" ).append( "," )
				.append( "\"LOG_MAC\"" ).append( ":" ).append( "\"" ).append( getRandomMacAddress() ).append( "\"" ).append( "," )
				.append( "\"LOG_DETAIL\"" ).append( ":" ).append( "\"" ).append( map.get("etc8") ).append( "\"" ).append( "," )
				.append( "\"LOG_USERNAME\"" ).append( ":" ).append( "\"" ).append( "" ).append( "\"" ).append( "," )
				.append( "\"LOG_TYPE\"" ).append( ":" ).append( "\"" ).append( "" ).append( "\"" );

		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new GiniNACLogGenerator().makeLog(new Date()) );
	}
}
