import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class TroyCutLogGenerator extends LogGenerator {
	private static final String[] programPath = {
		"D:\\유틸리티\\"
		, "C:\\PROGRAM FILES\\PCCLEARPLUS"
		, "D:\\설치파일\\RSC\\"
		, "F:\\RECYCLER\\S-5-3-42-2819952290-8240758988-879315005-3665\\"
		, "C:\\USERS\\러블리즈"
		, "C:\\USERS\\USER\\APPDATA"
		, "C:\\USERS\\ADMINISTRATOR"
		, "C:\\USERS\\TJANRP"
		, "C:\\USERS\\PC"
		, "D:\\TEMP\\"
		, "D:\\DOWNLOADS\\"
	};
	private static final String[] programName = {
		"WIN7 정품인증.EXE"
		, "PCCLEARPLUSUPDATE.EXE"
		, "RADMIN.EXE"
		, "JWGKVSQ.VMX"
		, "UNINSTALL.EXE"
		, "BIOS.EXE"
		, "일보(최신).XLS"
		, "OFFICEKMS.EXE"
		, "KMSSERVICE.EXE"
		, "OEM.EXE"
		, "MSVCP60.DLL"
	};

	public TroyCutLogGenerator() {
		super();
	}

	public TroyCutLogGenerator( int abnormalPercentage ) {
		super( abnormalPercentage );
	}

	@Override
	public int getGeneratorIndex() {
		return 1;
	}

	@Override
	public Map<String, Object> makeLog( Date startDateTime ) {
		Map<String, Object> map = new HashMap<>();

		ABNORMAL abnormalInfo = getAbnormalInfo();

		// 탐지 일시
		map.put( "date_created", startDateTime );
		map.put( "date_modified", map.get("date_created") );
		// 탐지 플래그
		map.put( "type", 1 );

		int category = random.nextInt( 2 ) +1;
		map.put( "category", category );

		map.put( "task_status", 1 );
		map.put( "no", category == 1 ? random.nextInt(3) +1 : 20 );
		map.put( "level", 3 );
		map.put( "level_value", 3 );
		map.put( "date_received", map.get("date_created") );
		// 내부 IP
		map.put( "ip", abnormalInfo != null ? abnormalInfo.getIp() : getRandomIP(IP_TYPE.LOCAL) );
		map.put( "network", random.nextInt(3) +1 );
		map.put( "description", null );
		// 사용자 MAC
		map.put( "etc1", getRandomMacAddress() );
		// 공인 IP
		map.put( "etc2", getRandomGlobalIP() );
		// 프로그램 경로
		map.put( "etc3", programPath[random.nextInt(programPath.length)] );
		// 프로그램 명
		map.put( "etc4", programName[random.nextInt(programName.length)] );
		// 파일 경로
		map.put( "etc5", programPath[random.nextInt(programPath.length)] );
		// 파일 명
		map.put( "etc6", programName[random.nextInt(programName.length)] );
		// 파일 사이즈
		map.put( "etc7", getRandomNumber(5) );
		// 통신 사이즈
		map.put( "etc8", map.get("etc7") );
		map.put( "etc9", null );
		map.put( "division_id", abnormalInfo != null ? abnormalInfo.getId() : getRandomNormalId() );
		map.put( "division_group_id", abnormalInfo != null ? abnormalInfo.getGroupId() : null );
		map.put( "policy_id", null );
		map.put( "name", null );
		map.put( "prediction_type", "alert" );


		StringBuilder strBld = new StringBuilder();
		strBld.append( "'" ).append( map.get("ip") ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc1") ).append( "'" ).append( "," )
				.append( "'" ).append( new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(map.get("date_created")) ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("type") ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc3") ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc4") ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc5") ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc6") ).append( "'" ).append( "," )
				.append( map.get("etc7") ).append( "," )
				.append( map.get("etc8") ).append( "," )
		// 목적지 IP
				.append( "'" ).append( getRandomGlobalIP() ).append( "'" ).append( "," )
		// 목적지 Port
				.append( "'" ).append( random.nextInt(65535) ).append( "'" ).append( "," )
				.append( "'" ).append( map.get("etc2") ).append( "'" ).append( "," )
		// 회사명
				.append( "'" ).append( "풍산" ).append( "'" ).append( "," )
		// 부서명
				.append( "'" ).append( "풍산" ).append( "'" );
		map.put( KEY_RAW, strBld.toString() );

		return map;
	}

	public static void main( String ... args ) {
		System.out.println( new TroyCutLogGenerator(Integer.parseInt(args[0])).makeLog(new Date()) );
	}
}
