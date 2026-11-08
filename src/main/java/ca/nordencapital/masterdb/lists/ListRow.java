package ca.nordencapital.masterdb.lists;

import org.springframework.jdbc.core.RowMapper;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** One row of {@code lists}, as stored (internal id included: never sent to the API). */
public record ListRow(long id, UUID publicId, String name, String esp, String country, String vertical,
        boolean removeDuplicates, int splitSize, Source source, String sourceName, Status status, String message,
        Long fileSize, long received, String delimiter, Boolean hasHeader, Integer emailColumn, List<String> columns,
        String importPhase, long importDone, long importTotal, long totalLines, long invalid, long duplicates,
        long inOtherLists, int records, int parts, Instant importStartedAt, Instant importedAt,
        Map<String, Integer> validationCounts, Instant validatedAt, UUID actorPublicId, String actorLabel,
        Instant createdAt, Instant updatedAt) {

    /** Where the file came from. */
    public enum Source { FILE, DRIVE }

    /**
     * UPLOADING (chunks from the PC) or DOWNLOADING (from Drive) → MAPPING (the
     * user confirms the email column) → QUEUED → IMPORTING → READY; or FAILED.
     */
    public enum Status {
        UPLOADING, DOWNLOADING, MAPPING, QUEUED, IMPORTING, READY, FAILED;

        /** The background still works on it (nothing to validate yet, the file is still needed). */
        public boolean busy() {
            return this == DOWNLOADING || this == QUEUED || this == IMPORTING;
        }
    }

    static final JsonMapper JSON = JsonMapper.builder().build();

    public static final RowMapper<ListRow> MAPPER = ListRow::map;

    static ListRow map(ResultSet rs, int n) throws SQLException {
        return new ListRow(rs.getLong("id"), rs.getObject("public_id", UUID.class), rs.getString("name"),
                rs.getString("esp"), rs.getString("country"), rs.getString("vertical"),
                rs.getBoolean("remove_duplicates"), rs.getInt("split_size"), Source.valueOf(rs.getString("source")),
                rs.getString("source_name"), Status.valueOf(rs.getString("status")), rs.getString("message"),
                (Long) rs.getObject("file_size"), rs.getLong("received"), rs.getString("delimiter"),
                (Boolean) rs.getObject("has_header"), (Integer) rs.getObject("email_column"),
                strings(rs.getString("columns")), rs.getString("import_phase"), rs.getLong("import_done"),
                rs.getLong("import_total"), rs.getLong("total_lines"), rs.getLong("invalid"),
                rs.getLong("duplicates"), rs.getLong("in_other_lists"), rs.getInt("records"), rs.getInt("parts"),
                ts(rs.getTimestamp("import_started_at")), ts(rs.getTimestamp("imported_at")),
                counts(rs.getString("validation_counts")), ts(rs.getTimestamp("validated_at")),
                rs.getObject("actor_public_id", UUID.class), rs.getString("actor_label"),
                ts(rs.getTimestamp("created_at")), ts(rs.getTimestamp("updated_at")));
    }

    /** A jsonb array of strings (NULL stays null). */
    public static List<String> strings(String json) {
        if (json == null) {
            return null;
        }
        return JSON.readValue(json, new TypeReference<List<String>>() { });
    }

    static Map<String, Integer> counts(String json) {
        if (json == null) {
            return null;
        }
        return JSON.readValue(json, new TypeReference<LinkedHashMap<String, Integer>>() { });
    }

    public static String json(Object value) {
        return value == null ? null : JSON.writeValueAsString(value);
    }

    private static Instant ts(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
