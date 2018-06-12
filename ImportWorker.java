import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.List;
import java.util.Random;
import java.util.UUID;

public class ImportWorker implements Runnable {
	private static final String INSERT_TB_EVENT =
		"INSERT INTO tb_event( DATE_CREATED, DATE_MODIFIED, TYPE, CATEGORY, TASK_STATUS, NO, LEVEL, LEVEL_VALUE, DATE_RECEIVED"
		+"		, IP, NETWORK, DESCRIPTION, ETC0, ETC1, ETC2, ETC3, ETC4, ETC5, ETC6, ETC7, ETC8, ETC9"
		+"		, DIVISION_ID, DIVISION_GROUP_ID, POLICY_ID, NAME, PREDICTION_TYPE )"
		+"	VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?"
		+"			, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?"
		+"			, ?, (SELECT GROUP_ID FROM tb_division WHERE ID = ?), (SELECT ID FROM tb_policy WHERE no = ?), ?, ? )";
	private static final String INSERT_TB_RAW_LOG =
		"INSERT INTO tb_raw_log( ID, DATE_CREATED, DATE_MODIFIED, RAW_LOG_TYPE, RAW_LOG_PATH, RAW_LOG_DESCRIPTION )"
		+"	VALUES( ?, ?, ?, ?, ?, ? )";
	private static final String INSERT_TB_RAW_LOG_CHAIN =
		"INSERT INTO tb_raw_log_chain( DATE_CREATED, DATE_MODIFIED, RAW_LOG_ID, EVENT_ID )"
		+"	VALUES( ?, ?, ?, ? )";

	private final LogGenerator[] generators = {
			new TroyCutLogGenerator( 1 )
			, new TessTMSLogGenerator( 1 )
			, new GiniNACLogGenerator( 1 )
			, new ChakraMAXLogGenerator( 1 )
			, new PetaCiperLogGenerator( 1 )
			, new SniperLogGenerator( 1 )
			, new SecureInfraLogGenerator( 1 )
			, new V3InternetSecurityLogGenerator( 1 )
	};

	private Connection conn;

	public ImportWorker() throws SQLException {
		conn = DriverManager.getConnection( "jdbc:mariadb://localhost:3306/TASDB?user=tasadmin&password=TasDkagh!23" );
		conn.setAutoCommit( false );
	}

	public void run() {
		Map<String, Object> logMap = null;
		while( !Thread.currentThread().isInterrupted() ) {
			try( PreparedStatement pstmtEvent = conn.prepareStatement(INSERT_TB_EVENT, Statement.RETURN_GENERATED_KEYS);
					PreparedStatement pstmtRaw = conn.prepareStatement(INSERT_TB_RAW_LOG);
					PreparedStatement pstmtRawChain = conn.prepareStatement(INSERT_TB_RAW_LOG_CHAIN); ) {
				List<Map<String, Object>> logMapList = new ArrayList<>();
				for( int i = 0; i < 1000; i++ ) {
					LogGenerator generator = selectGenerator();
					logMap = generator.makeLog( new Date() );
					logMap.put( "generator_type", generator.getGeneratorIndex() );
					setParameterEvent( pstmtEvent, logMap );
					pstmtEvent.addBatch();
					setParameterRaw( pstmtRaw, logMap );
					logMapList.add( logMap );
					pstmtRaw.addBatch();
				}

				pstmtEvent.executeBatch();
				pstmtRaw.executeBatch();

				ResultSet rs = pstmtEvent.getGeneratedKeys();
				for( int i = 0; rs.next(); i++ ) {
					setParameterRawChain( pstmtRawChain, logMapList.get(i), rs.getInt(1) );
					pstmtRawChain.addBatch();
				}
				pstmtRawChain.executeBatch();

				conn.commit();
			} catch( SQLException sqlEx ) {
				sqlEx.printStackTrace();
				try { conn.rollback(); } catch( Exception ex ) { ex.printStackTrace(); }
			}
		}
	}

	// generator 랜덤 선별
	private LogGenerator selectGenerator() {
		return generators[ new Random().nextInt(generators.length) ];
	}

	private static void setParameterEvent( final PreparedStatement pstmt, Map<String, Object> logMap ) throws SQLException {
		pstmt.setObject( 1, logMap.get("date_created"), Types.TIMESTAMP );
		pstmt.setObject( 2, logMap.get("date_modified"), Types.TIMESTAMP );
		pstmt.setObject( 3, logMap.get("type"), Types.SMALLINT );
		pstmt.setObject( 4, logMap.get("category"), Types.SMALLINT );
		pstmt.setObject( 5, logMap.get("task_status"), Types.SMALLINT );
		pstmt.setObject( 6, logMap.get("no"), Types.VARCHAR );
		pstmt.setObject( 7, logMap.get("level"), Types.SMALLINT );
		pstmt.setObject( 8, logMap.get("level_value"), Types.DOUBLE );
		pstmt.setObject( 9, logMap.get("date_received"), Types.TIMESTAMP );
		pstmt.setObject( 10, logMap.get("ip"), Types.CHAR );
		pstmt.setObject( 11, logMap.get("network"), Types.SMALLINT );
		pstmt.setObject( 12, logMap.get("description"), Types.LONGVARCHAR );
		pstmt.setObject( 13, logMap.get("etc1"), Types.VARCHAR );
		pstmt.setObject( 14, logMap.get("etc2"), Types.VARCHAR );
		pstmt.setObject( 15, logMap.get("etc3"), Types.VARCHAR );
		pstmt.setObject( 16, logMap.get("etc4"), Types.VARCHAR );
		pstmt.setObject( 17, logMap.get("etc5"), Types.VARCHAR );
		pstmt.setObject( 18, logMap.get("etc6"), Types.VARCHAR );
		pstmt.setObject( 19, logMap.get("etc7"), Types.VARCHAR );
		pstmt.setObject( 20, logMap.get("etc8"), Types.VARCHAR );
		pstmt.setObject( 21, logMap.get("etc9"), Types.VARCHAR );
		pstmt.setObject( 22, logMap.get("division_id"), Types.INTEGER );
		pstmt.setObject( 23, logMap.get("division_id"), Types.INTEGER );
		pstmt.setObject( 24, logMap.get("no"), Types.VARCHAR );
		pstmt.setObject( 25, logMap.get("name"), Types.VARCHAR );
		pstmt.setObject( 26, logMap.get("prediction_type"), Types.VARCHAR );
	}

	private static void setParameterRaw( final PreparedStatement pstmt, Map<String, Object> logMap ) throws SQLException {
		logMap.put( "UUID", UUID.randomUUID().toString() );
		pstmt.setObject( 1, logMap.get("UUID"), Types.VARCHAR );
		pstmt.setObject( 2, logMap.get("date_created"), Types.TIMESTAMP );
		pstmt.setObject( 3, logMap.get("date_modified"), Types.TIMESTAMP );
		pstmt.setObject( 4, logMap.get("generator_type"), Types.SMALLINT );
		pstmt.setObject( 5, logMap.get("raw_log_path"), Types.VARCHAR );
		pstmt.setObject( 6, logMap.get(LogGenerator.KEY_RAW), Types.LONGVARCHAR );
	}

	private static void setParameterRawChain( final PreparedStatement pstmt, Map<String, Object> logMap, int eventId ) throws SQLException {
		pstmt.setObject( 1, logMap.get("date_created"), Types.TIMESTAMP );
		pstmt.setObject( 2, logMap.get("date_modified"), Types.TIMESTAMP );
		pstmt.setObject( 3, logMap.get("UUID"), Types.VARCHAR );
		pstmt.setObject( 4, String.valueOf(eventId), Types.VARCHAR );
	}

	public static void main( String ... args ) throws Exception {
		new Thread( new ImportWorker() ).start();
		new Thread( new ImportWorker() ).start();
		new Thread( new ImportWorker() ).start();
		new Thread( new ImportWorker() ).start();
	}
}
