import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class SecureInfraLogGenerator extends LogGenerator {
	private static final String[] eventLevel = { "Normal", "Warning", "Critical" };
	private static final String[] dbType = { "ORACLE", "MariaDB", "DB2", "MySQL", "MSSQL", "PostgreSQL" };
	private static final String[] message = {
		"프린터 출력허용 : [사용자] 에서 [문서파일명]의 [프린터명] 로 인쇄를 허용합니다"
		, "프린터 출력차단 : [사용자] 에서 [문서파일명]의 [프린터명] 로 인쇄를 차단합니다"				
		, "파일 전송허용 : [파일명] 파일 by [프로그램명]"
		, "파일 전송차단 : [파일명] 파일 by [프로그램명]"
		, "공유폴더 접근허용 : [SHARE FOLER] 폴더에 [사용자] 접근 허용합니다."
		, "공유폴더 접근차단 : [SHARE FOLER] 폴더에 [사용자] 접근 차단합니다."
		, "이동장치 접근허용 : [이동장치] 에 [사용자] 접근 허용합니다."
		, "이동장치 접근차단 : [이동장치] 에 [사용자] 접근 허용합니다."
	};
	private static final String[] docuFilename = {
		"일보(최신).XLS", "이벤트정보.hwp", "인사정보.xlsx", "사용자권한정보.hwp", "시험인증정보.hwp"
		, "탐지정책.doc", "장비별이벤트테이블.xls", "정책_파일정보.txt", "지원개발지침.hwp", "이의신청자료.docx"
		, "SCAN_2013.pdf", "최종평가위원회안내문.hwp", "백신로그_하우리.csv", "과제지원지침.hwp"
	};
	private static final String[] printName = {
		"uPrint", "192.168.10.100", "5층 프린터", "6층 컬러프린터", "공유프린터", "7fPrint", "지원프린터"
	};
	private static final String[] programName = {
		"Filezilla.exe", "Winscp.exe", "puttyscp.exe", "mobatexm.exe", "ALFtp.exe"
	};
	private static final String[] sharedFolder = {
		"1팀공유폴더", "Shared Folder", "2팀공유", "3팀공유", "공통", "Media", "자료실", "내부자료_주의"
	};
	private static final String[] removable = {
		"leopark", "zenithhg", "E:", "F:", "I:", "J:"
	};
	private final SimpleDateFormat dateFormat = new SimpleDateFormat( "yyyyMMdd" );
	private final SimpleDateFormat timeFormat = new SimpleDateFormat( "HHmmss" );

	public SecureInfraLogGenerator() {
		super();
	}

	public SecureInfraLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	private String getMessage() {
		String msg = message[ random.nextInt(message.length) ];
		msg = msg.replace( "[문서파일명]", docuFilename[random.nextInt(docuFilename.length)] );
		msg = msg.replace( "[프린터명]", printName[random.nextInt(printName.length)] );
		msg = msg.replace( "[프로그램명]", programName[random.nextInt(programName.length)] );
		msg = msg.replace( "[SHARE FOLER]", sharedFolder[random.nextInt(sharedFolder.length)] );
		msg = msg.replace( "[이동장치]", removable[random.nextInt(removable.length)] );

		return msg;
	}

	@Override
	public int getGeneratorIndex() {
		return 7;
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		ABNORMAL abnormalInfo = getAbnormalInfo();

		Map<String, Object> map = new HashMap<>();
		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		map.put( "type", 1 );
		map.put( "category", 1 );
		map.put( "task_status", 1 );
		map.put( "no", random.nextInt(8) +4 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.GLOBAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// 관리자
		map.put( "etc1", "" );
		// 코드
		map.put( "etc2", "A008" );
		// MSG
		map.put( "etc3", getMessage() );
		map.put( "etc4", null );
		map.put( "etc5", null );
		map.put( "etc6", null );
		map.put( "etc7", null );
		map.put( "etc8", null );
		map.put( "etc9", null );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );

		StringBuilder strBld = new StringBuilder();
		// DATE
		strBld.append( dateFormat.format(map.get("date_created")) ).append( ";" )
		// TIME
				.append( timeFormat.format(map.get("date_created")) ).append( ";" )
		// 부서
				.append( "콜센터" ).append( ";" )
		// 이름
				.append( "" ).append( ";" )
		// 사번
				.append( "21215" ).append( ";" )
		// 관리자
				.append( map.get("etc1") ).append( ";" )
		// IP
				.append( map.get("ip") ).append( ";" )
		// 코드
				.append( map.get("etc2") ).append( ";" )
		// 코드
				.append( map.get("etc3") );
		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new SecureInfraLogGenerator().makeLog( new Date() ) );
	}
}
