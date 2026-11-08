package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.lists.imports.ColumnGuess.Guess;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

/** The whole file is on the server (uploaded or downloaded): guess its columns and wait for the user's choice. */
@Component
public class UploadFinish {

    /** How much of the file the column guess and the preview read. */
    static final int SAMPLE_BYTES = 64 * 1024;

    private final JdbcTemplate jdbc;
    private final ListFiles files;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;

    public UploadFinish(JdbcTemplate jdbc, ListFiles files, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.files = files;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    /** {@code caller} null = the server did it (Drive download). Only from UPLOADING or DOWNLOADING. */
    void uploaded(AuthPrincipal caller, ListRow l, long bytes) {
        Guess g = guess(files.path(l.publicId()));
        tx.executeWithoutResult(s -> {
            int n = jdbc.update("update lists set status = 'MAPPING', file_size = ?, received = ?, delimiter = ?, "
                    + "has_header = ?, email_column = ?, columns = ?::jsonb, updated_at = ? where id = ? and status in "
                    + "('UPLOADING', 'DOWNLOADING')", bytes, bytes, ListUploadService.delimiterName(g.delimiter()),
                    g.hasHeader(), g.emailColumn(), ListRow.json(g.columns()), Timestamp.from(clock.instant()), l.id());
            if (n == 1) {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("list", l.publicId().toString());
                d.put("bytes", bytes);
                d.put("source", l.source().name());
                activity.record(ActivityAction.LIST_UPLOADED, caller == null ? Party.label("MasterDB")
                        : Party.of(caller), Party.label(l.name()), d);
            }
        });
    }

    static Guess guess(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            byte[] head = in.readNBytes(SAMPLE_BYTES);
            boolean complete = in.read() < 0;
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE).decode(ByteBuffer.wrap(head)).toString();
            return ColumnGuess.of(text, complete);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
