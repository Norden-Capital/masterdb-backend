package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.validation.engine.EmailAddress;
import org.postgresql.PGConnection;
import org.postgresql.copy.CopyIn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Imports uploaded lists in the background, one at a time, oldest first.
 * The file is streamed (never held in memory): each record's email cell is
 * normalised and checked, and the valid rows are COPYed into the staging
 * table. Then, in chunks with real progress, the rows become contacts (one
 * per address across all lists) and members of the list in file order,
 * duplicates dropped when the list asks for it, and each member gets its part
 * ("split by N"). The state is in the database: after a restart an
 * interrupted import starts again from the file.
 */
@Component
public class ListImporter implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ListImporter.class);
    /** A record longer than this stops the import (a quote that is never closed would swallow the file). */
    static final int MAX_RECORD_CHARS = 1_000_000;
    /** Cells kept per row, and characters per cell (the rest is cut). */
    static final int MAX_CELLS = 200;
    static final int MAX_CELL_CHARS = 1000;

    private final JdbcTemplate jdbc;
    private final DataSource dataSource;
    private final ListFiles files;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final int chunk;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "list-import");
        t.setDaemon(true);
        return t;
    });
    private final AtomicBoolean scheduled = new AtomicBoolean();
    private final Set<Long> cancelled = ConcurrentHashMap.newKeySet();
    private volatile boolean shuttingDown;

    public ListImporter(JdbcTemplate jdbc, DataSource dataSource, ListFiles files, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions, @Value("${app.lists.import-chunk:50000}") int chunk) {
        this.jdbc = jdbc;
        this.dataSource = dataSource;
        this.files = files;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
        this.chunk = chunk;
    }

    /** Stopped on purpose (the list was deleted, or the backend shuts down). */
    static final class Cancelled extends RuntimeException {
        Cancelled() {
            super(null, null, false, false);
        }
    }

    // ---- control -----------------------------------------------------------------

    /** Looks for queued lists (no-op when the worker is already at it). */
    public void wake() {
        if (scheduled.compareAndSet(false, true)) {
            worker.submit(this::drain);
        }
    }

    public void cancel(long listId) {
        cancelled.add(listId);
    }

    /** After a restart: imports that were running start again from their file. */
    @EventListener(ApplicationReadyEvent.class)
    public void resumeAfterRestart() {
        List<Long> interrupted = jdbc.queryForList("select id from lists where status = 'IMPORTING' order by id",
                Long.class);
        for (long id : interrupted) {
            log.info("list {}: import interrupted by a restart, starting it again", id);
            reset(id);
        }
        wake();
    }

    private void reset(long id) {
        tx.executeWithoutResult(s -> {
            jdbc.update("delete from list_parts where list_id = ?", id);
            jdbc.update("delete from list_members where list_id = ?", id);
            jdbc.update("delete from list_import_rows where list_id = ?", id);
            jdbc.update("update lists set status = 'QUEUED', import_phase = null, import_done = 0, import_total = 0 "
                    + "where id = ? and status = 'IMPORTING'", id);
        });
    }

    @Override
    public void destroy() {
        shuttingDown = true;
        worker.shutdownNow();
        try {
            worker.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void drain() {
        try {
            Long next;
            while (!shuttingDown && (next = claim()) != null) {
                run(next);
            }
        } catch (RuntimeException e) {
            log.error("list import worker failed", e);
        } finally {
            scheduled.set(false);
        }
        if (!shuttingDown && Boolean.TRUE.equals(jdbc.queryForObject("select exists (select 1 from lists where "
                + "status = 'QUEUED')", Boolean.class))) {
            wake();
        }
    }

    private Long claim() {
        List<Long> ids = jdbc.queryForList("update lists set status = 'IMPORTING', import_phase = 'READING', "
                + "import_done = 0, import_total = coalesce(file_size, received), import_started_at = ? where id = "
                + "(select id from lists where status = 'QUEUED' order by updated_at, id limit 1 for update skip locked) "
                + "returning id", Long.class, Timestamp.from(clock.instant()));
        return ids.isEmpty() ? null : ids.getFirst();
    }

    private void run(long id) {
        long started = System.nanoTime();
        try {
            Report r = importList(id);
            log.info("list {} imported: {} lines, {} members, {} invalid, {} duplicates in {} ms", id, r.totalLines,
                    r.records, r.invalid, r.duplicates, (System.nanoTime() - started) / 1_000_000);
        } catch (Cancelled e) {
            log.info("list {}: import stopped ({})", id, shuttingDown ? "shutting down" : "list deleted");
            if (!shuttingDown) {
                jdbc.update("delete from list_import_rows where list_id = ?", id);
            }
        } catch (CsvReader.CsvException e) {
            fail(id, e.getMessage());
        } catch (Exception e) {
            if (cancelled.contains(id) || shuttingDown) {
                log.info("list {}: import stopped", id);
            } else {
                log.error("list {}: import failed", id, e);
                fail(id, "The import stopped on an unexpected error. Delete the list and add it again.");
            }
        } finally {
            cancelled.remove(id);
        }
    }

    private void fail(long id, String message) {
        List<ListRow> found = jdbc.query("select * from lists where id = ?", ListRow.MAPPER, id);
        tx.executeWithoutResult(s -> {
            jdbc.update("delete from list_parts where list_id = ?", id);
            jdbc.update("delete from list_members where list_id = ?", id);
            jdbc.update("delete from list_import_rows where list_id = ?", id);
            jdbc.update("update lists set status = 'FAILED', message = ?, import_phase = null, records = 0, parts = 0, "
                    + "updated_at = ? where id = ?", cut(message, 1000), Timestamp.from(clock.instant()), id);
            if (!found.isEmpty()) {
                activity.record(ActivityAction.LIST_IMPORT_FAILED, Party.label("MasterDB"),
                        Party.label(found.getFirst().name()), Map.of("list", found.getFirst().publicId().toString(),
                                "reason", cut(message, 300)));
            }
        });
        if (!found.isEmpty()) {
            files.delete(found.getFirst().publicId());
        }
    }

    // ---- the import ----------------------------------------------------------------

    record Report(long totalLines, long invalid, long valid, long duplicates, int records, int parts,
            long inOtherLists) {
    }

    private void check(long id) {
        if (shuttingDown || cancelled.contains(id) || Thread.currentThread().isInterrupted()) {
            throw new Cancelled();
        }
    }

    Report importList(long id) throws IOException, SQLException {
        ListRow l = jdbc.query("select * from lists where id = ?", ListRow.MAPPER, id).stream().findFirst()
                .orElseThrow(Cancelled::new);
        Path file = files.path(l.publicId());
        if (!Files.exists(file)) {
            throw new CsvReader.CsvException("The uploaded file is no longer on the server. Add the list again.");
        }
        jdbc.update("delete from list_import_rows where list_id = ?", id);

        // 1. Read the file into the staging table (COPY), counting bytes for the progress.
        long[] counts = read(l, file);
        long totalLines = counts[0];
        long invalid = counts[1];
        int valid = (int) counts[2];
        check(id);
        jdbc.execute("analyze list_import_rows");

        // 2. Contacts and members, chunk by chunk.
        jdbc.update("update lists set import_phase = 'SAVING', import_done = 0, import_total = ? where id = ?", valid,
                id);
        int split = l.splitSize();
        int members = 0;
        String dedupe = l.removeDuplicates() ? " and not exists (select 1 from list_import_rows d where d.list_id = "
                + "s.list_id and d.norm = s.norm and d.seq < s.seq)" : "";
        for (int start = 1; start <= valid; start += chunk) {
            check(id);
            int from = start;
            int to = Math.min(valid, start + chunk - 1);
            int base = members;
            Integer added = tx.execute(s -> {
                jdbc.update("insert into contacts (email, domain) select norm, domain from list_import_rows where "
                        + "list_id = ? and seq between ? and ? on conflict (email) do nothing", id, from, to);
                return jdbc.update("insert into list_members (list_id, seq, part_no, contact_id, email, fields) "
                        + "select ?, (? + s.rn)::int, case when ? > 0 then ((? + s.rn - 1) / ? + 1)::int else 1 end, "
                        + "c.id, s.email, s.fields from (select s.*, row_number() over (order by s.seq) as rn from "
                        + "list_import_rows s where s.list_id = ? and s.seq between ? and ?" + dedupe + ") s "
                        + "join contacts c on c.email = s.norm", id, base, split, base, Math.max(split, 1), id, from,
                        to);
            });
            members += added == null ? 0 : added;
            jdbc.update("update lists set import_done = ? where id = ?", to, id);
        }
        check(id);

        // 3. The report, the parts, done.
        long duplicates;
        if (l.removeDuplicates()) {
            duplicates = valid - members;
        } else {
            Long distinct = jdbc.queryForObject("select count(distinct norm) from list_import_rows where list_id = ?",
                    Long.class, id);
            duplicates = valid - (distinct == null ? 0 : distinct);
        }
        Long others = jdbc.queryForObject("select count(distinct m.contact_id) from list_members m where m.list_id = ? "
                + "and exists (select 1 from list_members o where o.contact_id = m.contact_id and o.list_id <> ?)",
                Long.class, id, id);
        long inOtherLists = others == null ? 0 : others;
        int finalMembers = members;
        Report report = new Report(totalLines, invalid, valid, duplicates, members, 0, inOtherLists);
        int parts = tx.execute(s -> {
            check(id);
            int p = jdbc.update("insert into list_parts (list_id, part_no, records, first_seq, last_seq) select ?, "
                    + "part_no, count(*), min(seq), max(seq) from list_members where list_id = ? group by part_no", id,
                    id);
            Timestamp now = Timestamp.from(clock.instant());
            boolean empty = finalMembers == 0;
            int n = jdbc.update("update lists set status = ?, message = ?, import_phase = null, total_lines = ?, "
                    + "invalid = ?, duplicates = ?, in_other_lists = ?, records = ?, parts = ?, imported_at = ?, "
                    + "updated_at = ? where id = ? and status = 'IMPORTING'", empty ? "FAILED" : "READY",
                    empty ? "No valid email address in the chosen column. Delete the list and try again with "
                            + "another column." : null, totalLines, invalid, duplicates, inOtherLists, finalMembers, p,
                    now, now, id);
            if (n == 0) {
                throw new Cancelled();
            }
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("list", l.publicId().toString());
            d.put("lines", totalLines);
            d.put("imported", finalMembers);
            d.put("invalid", invalid);
            d.put("duplicates", duplicates);
            d.put("duplicatesRemoved", l.removeDuplicates());
            d.put("inOtherLists", inOtherLists);
            d.put("parts", p);
            activity.record(empty ? ActivityAction.LIST_IMPORT_FAILED : ActivityAction.LIST_IMPORTED,
                    Party.label("MasterDB"), Party.label(l.name()), d);
            return p;
        });
        jdbc.update("delete from list_import_rows where list_id = ?", id);
        files.delete(l.publicId());
        return new Report(report.totalLines(), report.invalid(), report.valid(), report.duplicates(),
                report.records(), parts, report.inOtherLists());
    }

    /** Streams the file into list_import_rows; returns {lines, invalid, valid}. */
    private long[] read(ListRow l, Path file) throws IOException, SQLException {
        long id = l.id();
        char delimiter = ListUploadService.delimiterChar(l.delimiter());
        int column = l.emailColumn() == null ? 0 : l.emailColumn();
        boolean skipHeader = Boolean.TRUE.equals(l.hasHeader());
        long lines = 0;
        long invalid = 0;
        int seq = 0;
        long lastProgress = System.nanoTime();
        try (CountingStream counted = new CountingStream(new BufferedInputStream(Files.newInputStream(file), 1 << 16));
                CsvReader reader = new CsvReader(new InputStreamReader(counted, StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPLACE)
                        .onUnmappableCharacter(CodingErrorAction.REPLACE)), delimiter, MAX_RECORD_CHARS);
                Connection con = dataSource.getConnection()) {
            CopyIn copy = con.unwrap(PGConnection.class).getCopyAPI().copyIn("COPY list_import_rows (list_id, seq, "
                    + "email, norm, domain, fields) FROM STDIN");
            try {
                StringBuilder batch = new StringBuilder(1 << 20);
                List<String> rec;
                while ((rec = reader.next()) != null) {
                    if (skipHeader) {
                        skipHeader = false;
                        continue;
                    }
                    if (rec.size() == 1 && rec.getFirst().isBlank()) {
                        continue;
                    }
                    lines++;
                    Optional<EmailAddress> email = EmailAddress.parse(column < rec.size() ? rec.get(column) : null);
                    if (email.isEmpty()) {
                        invalid++;
                    } else {
                        seq++;
                        EmailAddress e = email.get();
                        batch.append(id).append('\t').append(seq).append('\t').append(e.address()).append('\t')
                                .append(e.normalized()).append('\t').append(e.domain()).append('\t');
                        if (rec.size() > 1) {
                            batch.append(ListRow.json(cells(rec)).replace("\\", "\\\\"));
                        } else {
                            batch.append("\\N");
                        }
                        batch.append('\n');
                    }
                    if (batch.length() > (1 << 20)) {
                        byte[] bytes = batch.toString().getBytes(StandardCharsets.UTF_8);
                        copy.writeToCopy(bytes, 0, bytes.length);
                        batch.setLength(0);
                    }
                    if ((lines & 0x3FFF) == 0 && System.nanoTime() - lastProgress > 500_000_000L) {
                        check(id);
                        lastProgress = System.nanoTime();
                        jdbc.update("update lists set import_done = ? where id = ?", counted.count(), id);
                    }
                }
                byte[] bytes = batch.toString().getBytes(StandardCharsets.UTF_8);
                if (bytes.length > 0) {
                    copy.writeToCopy(bytes, 0, bytes.length);
                }
                copy.endCopy();
            } finally {
                if (copy.isActive()) {
                    copy.cancelCopy();
                }
            }
            jdbc.update("update lists set import_done = import_total where id = ?", id);
        }
        return new long[] {lines, invalid, seq};
    }

    /** The row's cells for the jsonb column: at most 200, each at most 1,000 characters, no NUL characters. */
    static List<String> cells(List<String> rec) {
        List<String> out = new ArrayList<>(Math.min(rec.size(), MAX_CELLS));
        for (int i = 0; i < rec.size() && i < MAX_CELLS; i++) {
            String v = rec.get(i).trim();
            if (v.indexOf('\0') >= 0) {
                v = v.replace("\0", "");
            }
            out.add(v.length() > MAX_CELL_CHARS ? v.substring(0, MAX_CELL_CHARS) : v);
        }
        return out;
    }

    /** Bytes read so far, for the progress of the reading phase. */
    static final class CountingStream extends FilterInputStream {
        private long count;

        CountingStream(InputStream in) {
            super(in);
        }

        long count() {
            return count;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                count++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                count += n;
            }
            return n;
        }

        @Override
        public long skip(long n) throws IOException {
            long s = super.skip(n);
            count += s;
            return s;
        }
    }

    private static String cut(String v, int max) {
        return v == null ? null : v.length() <= max ? v : v.substring(0, max);
    }
}
