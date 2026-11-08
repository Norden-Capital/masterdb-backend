package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

/**
 * Shared set-up of the List management tests: the DNS test users (Owner,
 * member without permissions) and helpers that put a ready list straight into
 * the database. Only made-up addresses at example.invalid / *.test.
 */
abstract class ListFlowTestBase extends DnsFlowTestBase {

    @BeforeEach
    void setUpLists() {
        cleanLists();
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
}
