import java.text.SimpleDateFormat;
import java.time.temporal.ChronoUnit;;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class V3InternetSecurityLogGenerator extends LogGenerator {
	private static final String[] detectType = { "스파이웨어검사", "시스템검사", "시스템감시", "수동검사" };
	private static final String[] cureType = { "삭제", "치료가능", "치료" };
	private static final String[] patternName = {
		"Worm.Win32.Conficker.174326[h]"
		, "X97M.Laroux.DR[h]"
		, "X97M.Joke[h]"
		, "X97M.Joker[h]"
		, "Win32.Polip.Gen.A[h]"
		, "ackTool.WindowsActivation.2723328[h]"
		, "Grayware.PatchUpPlus.FV"
		, "Grayware.PCClearPlus.FV"
		, "HackTool.SLICToolkit.344064[h]"
		, "HackTool.Agent.273920[h]"
		, "HackTool.WindowsActivation.2723328[h]"
		, "Keygen.1257277[h]"
	};
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyyMMddHHmmss" );

	public V3InternetSecurityLogGenerator() {
		super();
	}

	public V3InternetSecurityLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 8;
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		ABNORMAL abnormalInfo = getAbnormalInfo();

		Map<String, Object> map = new HashMap<>();
		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		map.put( "type", 1 );
		map.put( "category", 4 );
		map.put( "task_status", 1 );
		map.put( "no", random.nextInt(2) +40 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.LOCAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// 파일명
		map.put( "etc1", "C:\\PROGRA~1\\TABBRO~1\\TABBRO~1.DLL" );
		// 패턴명
		map.put( "etc2", patternName[random.nextInt(patternName.length)] );
		// 검사타입
		map.put( "etc3", detectType[random.nextInt(detectType.length)] );
		// 치료여부
		map.put( "etc4", cureType[random.nextInt(cureType.length)] );
		// 시스템명
		map.put( "etc5", "SAMSUNG-0F7A7DF" );
		// 처리시간
		map.put( "etc6", dateFormat.format(Date.from(startDateTime.toInstant().plus(random.nextInt(5), ChronoUnit.SECONDS))) );
		map.put( "etc7", null );
		map.put( "etc8", null );
		map.put( "etc9", null );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		// 아이디
		strBld.append( "16057" ).append( ";" )
		// 서버버전
				.append( "0013.7710.12B2-win2k" ).append( ";" )
		// 패턴명
				.append( map.get("etc2") ).append( ";" )
		// 파일명
				.append( map.get("etc1") ).append( ";" )
		// 치료여부
				.append( map.get("etc4") ).append( ";" )
		// 검사타입
				.append( map.get("etc3") ).append( ";" )
		// IP
				.append( getRandomGlobalIP() ).append( ";" )
		// 부서명
				.append( "본사" ).append( ";" )
		// 이름
				.append( "..." ).append( ";" )
		// 시스템명
				.append( map.get("etc5") ).append( ";" )
		// 검사시간
				.append( dateFormat.format(map.get("date_created")) ).append( ";" )
		// 처리시간
				.append( map.get("etc6") ).append( ";" );
		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new V3InternetSecurityLogGenerator().makeLog(new Date()) );
	}
}
