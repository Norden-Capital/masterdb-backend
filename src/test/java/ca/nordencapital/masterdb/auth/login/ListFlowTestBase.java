package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.FakeDriveServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.context.annotation.Import;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared set-up of the List management tests: the DNS test users (Owner,
 * member without permissions) and helpers that put a ready list straight into
 * the database. Only made-up addresses at example.invalid / *.test.
 */
@Import(FakeDriveServer.Config.class)
abstract class ListFlowTestBase extends DnsFlowTestBase {

    static final FakeDriveServer DRIVE = FakeDriveServer.SHARED;
    static final int CHUNK = 64 * 1024;
    private final HttpClient raw = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void setUpLists() {
        cleanLists();
        DRIVE.reset();
    }

    @AfterEach
    void tearDownLists() {
        cleanLists();
    }

    void cleanLists() {
        cleanLists(jdbc);
    }

    static void cleanLists(org.springframework.jdbc.core.JdbcTemplate jdbc) {
        jdbc.update("update validation_jobs set status = 'STOPPED'");
        jdbc.update("delete from validation_jobs");
        jdbc.update("delete from list_import_rows");
        jdbc.update("delete from lists");
        jdbc.update("delete from contacts");
    }

    /**
     * A READY list with these addresses (and, when {@code columns} is given, each
     * row's cells from {@code rows}), split into parts of {@code split}.
     */
    String seedList(String name, String esp, String country, int split, List<String> columns, List<List<String>> rows,
            String... emails) {
        return seed(jdbc, Timestamp.from(clock.instant()), name, esp, country, split, columns, rows, emails);
    }

    static String seed(org.springframework.jdbc.core.JdbcTemplate jdbc, Timestamp now, String name, String esp,
            String country, int split, List<String> columns, List<List<String>> rows, String... emails) {
        UUID publicId = UUID.randomUUID();
        int size = split > 0 ? split : Math.max(1, emails.length);
        int parts = emails.length == 0 ? 0 : (emails.length + size - 1) / size;
        Long id = jdbc.queryForObject("insert into lists (public_id, name, esp, country, vertical, remove_duplicates, "
                + "split_size, source, source_name, status, records, parts, total_lines, columns, email_column, "
                + "has_header, delimiter, imported_at, created_at, updated_at) values (?,?,?,?,'',false,?,'FILE',?,"
                + "'READY',?,?,?,?::jsonb,0,?,',',?,?,?) returning id", Long.class, publicId, name, esp, country, split,
                name + ".csv", emails.length, parts, emails.length, columns == null ? null : json(columns),
                columns != null, now, now, now);
        for (int i = 0; i < emails.length; i++) {
            String norm = emails[i].toLowerCase();
            jdbc.update("insert into contacts (email, domain) values (?, ?) on conflict do nothing", norm,
                    norm.substring(norm.indexOf('@') + 1));
            Long contact = jdbc.queryForObject("select id from contacts where email = ?", Long.class, norm);
            jdbc.update("insert into list_members (list_id, seq, part_no, contact_id, email, fields) values "
                    + "(?,?,?,?,?,?::jsonb)", id, i + 1, i / size + 1, contact, emails[i],
                    rows == null ? null : json(rows.get(i)));
        }
        for (int p = 1; p <= parts; p++) {
            int first = (p - 1) * size + 1;
            int last = Math.min(emails.length, p * size);
            jdbc.update("insert into list_parts (list_id, part_no, records, first_seq, last_seq) values (?,?,?,?,?)", id,
                    p, last - first + 1, first, last);
        }
        return publicId.toString();
    }

    String seedList(String name, String... emails) {
        return seedList(name, "", "", 0, null, null, emails);
    }

    static String json(List<String> values) {
        StringBuilder b = new StringBuilder("[");
        for (String v : values) {
            if (b.length() > 1) {
                b.append(',');
            }
            b.append('"').append(v.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
        }
        return b.append(']').toString();
    }

    // ---- upload helpers ----------------------------------------------------------

    /** POST /api/v1/lists for a file; {@code extra} = more JSON fields (",\"splitBy\":2"). */
    HttpResponse<String> create(String name, String fileName, long size, String extra) throws Exception {
        return post("/api/v1/lists", "{\"name\":\"" + name + "\",\"source\":\"FILE\",\"fileName\":\"" + fileName
                + "\",\"fileSize\":" + size + extra + "}");
    }

    /** PUT one chunk (raw bytes) as the Owner. */
    HttpResponse<String> chunk(String id, long offset, byte[] bytes) throws Exception {
        return chunk(owner, id, offset, bytes);
    }

    HttpResponse<String> chunk(String token, String id, long offset, byte[] bytes) throws Exception {
        return raw.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/lists/" + id
                        + "/upload?offset=" + offset)).header("Cookie", "md_session=" + token)
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofByteArray(bytes)).build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Creates the list and sends the whole file in 64 KB chunks; returns its id (status MAPPING). */
    String upload(String name, String content, String extra) throws Exception {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        HttpResponse<String> created = create(name, name + ".csv", bytes.length, extra);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String id = id(created.body());
        for (int off = 0; off < bytes.length; off += CHUNK) {
            HttpResponse<String> res = chunk(id, off, Arrays.copyOfRange(bytes, off, Math.min(bytes.length,
                    off + CHUNK)));
            assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        }
        return id;
    }

    /** Starts the import with this body (null = the guess) and waits for READY or FAILED. */
    String importAndWait(String id, String body) throws Exception {
        HttpResponse<String> started = post("/api/v1/lists/" + id + "/import", body);
        assertThat(started.statusCode()).as(started.body()).isEqualTo(200);
        return waitFor(id, "\"status\":\"READY\"", "\"status\":\"FAILED\"");
    }

    /** Polls the list until its body contains one of the texts (10 s at most). */
    String waitFor(String id, String... texts) throws Exception {
        Instant end = Instant.now().plus(Duration.ofSeconds(15));
        String body = get("/api/v1/lists/" + id).body();
        while (Arrays.stream(texts).noneMatch(body::contains) && Instant.now().isBefore(end)) {
            Thread.sleep(50);
            body = get("/api/v1/lists/" + id).body();
        }
        assertThat(body).containsAnyOf(texts);
        return body;
    }

    List<String> emails(String id) {
        return jdbc.queryForList("select m.email from list_members m join lists l on l.id = m.list_id where "
                + "l.public_id = ?::uuid order by m.seq", String.class, id);
    }
}
