package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.lists.ListHooks;
import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.lists.ListRow.Source;
import ca.nordencapital.masterdb.lists.ListRow.Status;
import ca.nordencapital.masterdb.lists.ListService;
import ca.nordencapital.masterdb.lists.ListService.ListView;
import ca.nordencapital.masterdb.lists.imports.ColumnGuess.Guess;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.unit.DataSize;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Add list: the list's details, then its file, either uploaded from the PC in
 * chunks (each under 4 MB, so it passes the website's proxy and Vercel's body
 * limit) or downloaded by the server from a Google Drive link. Progress is
 * what the server has written to disk, never a guess. Once the whole file is
 * there the list waits in MAPPING: the user confirms the email column (the
 * server's guess is preselected) and the import starts in the background.
 */
@Service
public class ListUploadService implements ListHooks {

    private static final Logger log = LoggerFactory.getLogger(ListUploadService.class);
    public static final int MAX_SPLIT = 10_000_000;

    private final JdbcTemplate jdbc;
    private final ListService lists;
    private final ListFiles files;
    private final ListImporter importer;
    private final DriveDownloader drive;
    private final UploadFinish finish;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final long chunkMax;
    private final Duration uploadExpiry;
    private final Map<UUID, Object> locks = new ConcurrentHashMap<>();

    public ListUploadService(JdbcTemplate jdbc, ListService lists, ListFiles files, ListImporter importer,
            DriveDownloader drive, UploadFinish finish, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions,
            @Value("${app.lists.chunk-max:4MB}") DataSize chunkMax,
            @Value("${app.lists.upload-expiry:48h}") Duration uploadExpiry) {
        this.jdbc = jdbc;
        this.lists = lists;
        this.files = files;
        this.importer = importer;
        this.drive = drive;
        this.finish = finish;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
        this.chunkMax = chunkMax.toBytes();
        this.uploadExpiry = uploadExpiry;
    }

    public record CreateRequest(String name, String esp, String country, String vertical, Boolean removeDuplicates,
            Integer splitBy, Source source, String fileName, Long fileSize, String driveUrl) {
    }

    /** Where an upload stands: bytes the server has on disk out of the file's size. */
    public record UploadState(UUID publicId, Status status, long received, Long size, String message) {
    }

    /** The first rows of the file and the server's guess of how to read it. */
    public record Preview(String delimiter, boolean hasHeader, int emailColumn, List<String> columns,
            List<List<String>> rows, List<Integer> emailsPerColumn) {
    }

    // ---- create ------------------------------------------------------------------

    public ListView create(AuthPrincipal caller, CreateRequest req) {
        String name = text("name", req.name(), true);
        String esp = text("esp", req.esp(), false);
        String country = text("country", req.country(), false);
        String vertical = text("vertical", req.vertical(), false);
        int split = req.splitBy() == null ? 0 : req.splitBy();
        if (split < 0 || split > MAX_SPLIT) {
            throw BadRequestException.validation("splitBy", "must be 0 (no split) to " + MAX_SPLIT);
        }
        boolean dedupe = Boolean.TRUE.equals(req.removeDuplicates());
        Source source = req.source() == null ? Source.FILE : req.source();
        String sourceName;
        Long size = null;
        DriveLink link = null;
        if (source == Source.FILE) {
            String file = req.fileName() == null ? "" : req.fileName().trim();
            String lower = file.toLowerCase(Locale.ROOT);
            if (!lower.endsWith(".txt") && !lower.endsWith(".csv")) {
                throw BadRequestException.validation("fileName", "must be a .txt or .csv file");
            }
            if (file.length() > 255) {
                throw BadRequestException.validation("fileName", "is longer than 255 characters");
            }
            if (req.fileSize() == null || req.fileSize() <= 0) {
                throw BadRequestException.validation("fileSize", "the file is empty");
            }
            if (req.fileSize() > files.maxFileSize()) {
                throw new ListException(HttpStatus.CONTENT_TOO_LARGE, ErrorCode.CONTENT_TOO_LARGE, "This file is over "
                        + DriveDownloader.size(files.maxFileSize()) + ", the most MasterDB takes in one list.");
            }
            sourceName = file;
            size = req.fileSize();
        } else {
            link = DriveLink.parse(req.driveUrl());
            sourceName = req.driveUrl().trim();
        }
        UUID publicId = UUID.randomUUID();
        files.create(publicId, size == null ? 0 : size);
        Timestamp now = Timestamp.from(clock.instant());
        Status status = source == Source.FILE ? Status.UPLOADING : Status.DOWNLOADING;
        Long sizeFinal = size;
        long id;
        try {
            id = tx.execute(s -> {
                Long newId = jdbc.queryForObject("insert into lists (public_id, name, esp, country, vertical, "
                        + "remove_duplicates, split_size, source, source_name, status, file_size, actor_public_id, "
                        + "actor_label, created_at, updated_at) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) returning id",
                        Long.class, publicId, name, esp, country, vertical, dedupe, split, source.name(), sourceName,
                        status.name(), sizeFinal, caller.userPublicId(), cut(caller.email(), 254), now, now);
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("list", publicId.toString());
                d.put("source", source.name());
                d.put("file", source == Source.FILE ? sourceName : "Google Drive");
                if (sizeFinal != null) {
                    d.put("bytes", sizeFinal);
                }
                d.put("removeDuplicates", dedupe);
                d.put("splitBy", split);
                activity.record(ActivityAction.LIST_CREATED, Party.of(caller), Party.label(name), d);
                return newId;
            });
        } catch (RuntimeException e) {
            files.delete(publicId);
            throw e;
        }
        if (link != null) {
            drive.start(id, link);
        }
        return lists.view(lists.find(publicId));
    }

    // ---- chunks ------------------------------------------------------------------

    public UploadState state(UUID publicId) {
        ListRow l = lists.find(publicId);
        return new UploadState(l.publicId(), l.status(), l.received(), l.fileSize(), l.message());
    }

    /**
     * Writes one chunk that starts at byte {@code offset}. A chunk the server
     * already has (sent again after a lost answer) changes nothing; one that
     * overlaps the end is written from where the file stands; one past the end
     * is refused with 409 UPLOAD_OFFSET_MISMATCH and the right offset.
     */
    public UploadState chunk(AuthPrincipal caller, UUID publicId, long offset, InputStream body) {
        synchronized (locks.computeIfAbsent(publicId, k -> new Object())) {
            ListRow l = lists.find(publicId);
            if (l.status() != Status.UPLOADING) {
                throw new ConflictException(l.status() == Status.MAPPING || l.status().busy()
                        || l.status() == Status.READY ? "This file is already uploaded."
                        : "This list is not waiting for a file.");
            }
            long received = l.received();
            long size = l.fileSize();
            if (offset < 0 || offset > received) {
                throw new ListException(HttpStatus.CONFLICT, ErrorCode.UPLOAD_OFFSET_MISMATCH, "The server has "
                        + received + " bytes of this file; go on from there.", Map.of("received", received));
            }
            Path path = files.path(publicId);
            if (!Files.exists(path)) {
                throw new ConflictException("The upload was cancelled. Add the list again.");
            }
            long pos = received;
            try (FileChannel ch = FileChannel.open(path, StandardOpenOption.WRITE)) {
                // Anything past what the database says (a crash after a write) is written again.
                ch.truncate(received);
                long skip = received - offset;
                long read = 0;
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = body.read(buf)) > 0) {
                    read += n;
                    if (read > chunkMax) {
                        ch.truncate(received);
                        throw new ListException(HttpStatus.CONTENT_TOO_LARGE, ErrorCode.CONTENT_TOO_LARGE,
                                "A chunk can be at most " + chunkMax + " bytes.");
                    }
                    int start = 0;
                    if (skip > 0) {
                        start = (int) Math.min(skip, n);
                        skip -= start;
                    }
                    if (n > start) {
                        if (pos + n - start > size) {
                            ch.truncate(received);
                            throw BadRequestException.validation("offset", "this chunk goes past the end of the "
                                    + size + "-byte file");
                        }
                        ByteBuffer bb = ByteBuffer.wrap(buf, start, n - start);
                        while (bb.hasRemaining()) {
                            pos += ch.write(bb, pos);
                        }
                    }
                }
                ch.force(false);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            if (pos != received) {
                jdbc.update("update lists set received = ?, updated_at = ? where id = ?", pos,
                        Timestamp.from(clock.instant()), l.id());
            }
            if (pos == size) {
                finish.uploaded(caller, l, pos);
            }
            return state(publicId);
        }
    }

    // ---- mapping and import ------------------------------------------------------------

    public Preview preview(UUID publicId) {
        ListRow l = lists.find(publicId);
        if (l.status() != Status.MAPPING) {
            throw new ConflictException("The preview is only there between the upload and the import.");
        }
        Guess g = UploadFinish.guess(files.path(l.publicId()));
        List<Integer> perColumn = new ArrayList<>();
        for (int c = 0; c < g.columns().size(); c++) {
            perColumn.add(ColumnGuess.emails(g.rows(), Boolean.TRUE.equals(l.hasHeader()), c));
        }
        List<List<String>> rows = g.rows().stream().limit(11).map(r -> r.stream()
                .map(v -> v.length() > 200 ? v.substring(0, 200) + "…" : v).toList()).toList();
        return new Preview(l.delimiter(), Boolean.TRUE.equals(l.hasHeader()), l.emailColumn(), g.columns(), rows,
                perColumn);
    }

    /** The user's column choice; the import starts in the background. */
    public ListView startImport(AuthPrincipal caller, UUID publicId, Integer emailColumn, Boolean hasHeader) {
        ListRow l = lists.find(publicId);
        if (l.status() != Status.MAPPING) {
            throw new ConflictException(l.status().busy() ? "This list is already being imported."
                    : "This list is not waiting for its column choice.");
        }
        Guess g = UploadFinish.guess(files.path(l.publicId()));
        boolean header = hasHeader == null ? Boolean.TRUE.equals(l.hasHeader()) : hasHeader;
        int column = emailColumn == null ? l.emailColumn() : emailColumn;
        int width = Math.max(1, g.columns().size());
        if (column < 0 || column >= width) {
            throw BadRequestException.validation("emailColumn", "must be a column of the file (0 to "
                    + (width - 1) + ")");
        }
        List<String> names = ColumnGuess.names(header && !g.rows().isEmpty() ? g.rows().getFirst() : List.of(),
                width);
        tx.executeWithoutResult(s -> {
            jdbc.update("update lists set status = 'QUEUED', has_header = ?, email_column = ?, columns = ?::jsonb, "
                    + "message = null, import_phase = null, import_done = 0, import_total = 0, updated_at = ? where id = ?",
                    header, column, ListRow.json(names), Timestamp.from(clock.instant()), l.id());
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("list", l.publicId().toString());
            d.put("emailColumn", names.get(column));
            d.put("header", header);
            activity.record(ActivityAction.LIST_IMPORT_STARTED, Party.of(caller), Party.label(l.name()), d);
        });
        importer.wake();
        return lists.view(lists.find(publicId));
    }

    // ---- housekeeping ------------------------------------------------------------------

    @Override
    public void deleted(ListRow list) {
        importer.cancel(list.id());
        drive.cancel(list.id());
        files.delete(list.publicId());
        locks.remove(list.publicId());
    }

    /** Uploads nobody finished, and column choices nobody made, expire (their files are deleted). */
    @Scheduled(cron = "${app.lists.cleanup-cron:0 20 * * * *}", zone = "UTC")
    public void expire() {
        Instant now = clock.instant();
        List<ListRow> stale = jdbc.query("select * from lists where (status = 'UPLOADING' and updated_at < ?) or "
                + "(status = 'MAPPING' and updated_at < ?)", ListRow.MAPPER,
                Timestamp.from(now.minus(uploadExpiry)), Timestamp.from(now.minus(uploadExpiry.multipliedBy(3))));
        for (ListRow l : stale) {
            jdbc.update("update lists set status = 'FAILED', message = ?, updated_at = ? where id = ? and status = ?",
                    l.status() == Status.UPLOADING ? "The upload was not finished in time. Add the list again."
                            : "The email column was never chosen. Add the list again.",
                    Timestamp.from(now), l.id(), l.status().name());
            files.delete(l.publicId());
            log.info("list {} expired in {}", l.publicId(), l.status());
        }
    }

    // ---- helpers -------------------------------------------------------------------

    static String delimiterName(char d) {
        return switch (d) {
            case ',' -> ",";
            case ';' -> ";";
            case '\t' -> "TAB";
            case '|' -> "|";
            default -> "NONE";
        };
    }

    static char delimiterChar(String name) {
        if (name == null) {
            return 0;
        }
        return switch (name) {
            case "," -> ',';
            case ";" -> ';';
            case "TAB" -> '\t';
            case "|" -> '|';
            default -> 0;
        };
    }

    private static String text(String field, String value, boolean required) {
        String v = value == null ? "" : value.trim();
        if (required && v.isEmpty()) {
            throw BadRequestException.validation(field, "is required");
        }
        if (v.length() > ListService.MAX_TEXT) {
            throw BadRequestException.validation(field, "is longer than " + ListService.MAX_TEXT + " characters");
        }
        return v;
    }

    private static String cut(String v, int max) {
        return v == null ? null : v.length() <= max ? v : v.substring(0, max);
    }
}
