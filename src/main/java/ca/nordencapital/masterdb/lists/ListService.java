package ca.nordencapital.masterdb.lists;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.lists.ListRow.Source;
import ca.nordencapital.masterdb.lists.ListRow.Status;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * List management: the lists table, one list with its parts and members,
 * edit the details, delete, export the members with their own columns.
 * Upload and import live in {@code lists.upload} and {@code lists.imports}.
 */
@Service
public class ListService {

    public static final int MAX_TEXT = 255;

    /** API sort names → columns (fixed strings, never user input). */
    static final Map<String, String> SORT_COLUMNS = Map.of("name", "lower(l.name)", "records", "l.records",
            "esp", "lower(l.esp)", "country", "lower(l.country)", "vertical", "lower(l.vertical)", "parts", "l.parts",
            "createdAt", "l.created_at", "status", "l.status", "source", "l.source");

    private final JdbcTemplate jdbc;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final ObjectProvider<ListHooks> hooks;

    public ListService(JdbcTemplate jdbc, ActivityLog activity, Clock clock, PlatformTransactionManager transactions,
            ObjectProvider<ListHooks> hooks) {
        this.jdbc = jdbc;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
        this.hooks = hooks;
    }

    // ---- views -------------------------------------------------------------------

    public record Upload(Long size, long received) {
    }

    /** Live numbers of a running import: {@code phase} READING (bytes of the file) or SAVING (rows). */
    public record Progress(String phase, long done, long total) {
    }

    /** The import report. {@code imported} = members of the list. */
    public record Report(long totalLines, int imported, long invalid, long duplicates, boolean duplicatesRemoved,
            long inOtherLists) {
    }

    /** The column choice of the file. */
    public record Mapping(String delimiter, boolean hasHeader, int emailColumn, List<String> columns) {
    }

    /** Latest result per address over every validation of the list, and a job running on it now. */
    public record Validation(Map<String, Integer> counts, Instant at, ListHooks.RunningJob running) {
    }

    public record ListView(UUID publicId, String name, String esp, String country, String vertical,
            boolean removeDuplicates, int splitSize, Source source, String sourceName, Status status, String message,
            int records, int parts, Upload upload, Progress progress, Report report, Mapping mapping,
            Validation validation, String createdBy, Instant createdAt, Instant importedAt) {
    }

    public record PartView(UUID publicId, int partNo, int records, int firstSeq, int lastSeq,
            ListHooks.RunningJob running) {
    }

    public record Detail(ListView list, List<PartView> parts) {
    }

    public record Member(int seq, int partNo, String email, List<String> fields) {
    }

    public record Facets(List<String> esp, List<String> country, List<String> vertical) {
    }

    public record Filter(String q, String esp, String country, String vertical, Source source, Status status) {
    }

    public record UpdateRequest(String name, String esp, String country, String vertical) {
    }

    // ---- read --------------------------------------------------------------------

    public ListRow find(UUID publicId) {
        List<ListRow> found = jdbc.query("select * from lists where public_id = ?", ListRow.MAPPER, publicId);
        if (found.isEmpty()) {
            throw new NotFoundException("This list is not in MasterDB.");
        }
        return found.getFirst();
    }

    public ListRow findById(long id) {
        List<ListRow> found = jdbc.query("select * from lists where id = ?", ListRow.MAPPER, id);
        if (found.isEmpty()) {
            throw new NotFoundException("This list is not in MasterDB.");
        }
        return found.getFirst();
    }

    public PageResponse<ListView> page(Filter filter, Pageable pageable) {
        List<Object> args = new ArrayList<>();
        String where = where(filter, args);
        Long total = jdbc.queryForObject("select count(*) from lists l" + where, Long.class, args.toArray());
        StringBuilder order = new StringBuilder(" order by ");
        for (Sort.Order o : pageable.getSort()) {
            order.append(SORT_COLUMNS.get(o.getProperty())).append(o.isAscending() ? " asc" : " desc")
                    .append(" nulls last, ");
        }
        order.append("l.created_at desc, l.id desc");
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<ListView> items = jdbc.query("select l.* from lists l" + where + order + " limit ? offset ?",
                ListRow.MAPPER, args.toArray()).stream().map(this::view).toList();
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    private static String where(Filter f, List<Object> args) {
        List<String> parts = new ArrayList<>();
        if (f.q() != null && !f.q().isBlank()) {
            parts.add("lower(l.name) like ? escape '\\'");
            args.add(like(f.q()));
        }
        for (String[] eq : new String[][] {{"l.esp", f.esp()}, {"l.country", f.country()},
                {"l.vertical", f.vertical()}}) {
            if (eq[1] != null && !eq[1].isEmpty()) {
                parts.add(eq[0] + " = ?");
                args.add(eq[1]);
            }
        }
        if (f.source() != null) {
            parts.add("l.source = ?");
            args.add(f.source().name());
        }
        if (f.status() != null) {
            parts.add("l.status = ?");
            args.add(f.status().name());
        }
        return parts.isEmpty() ? "" : " where " + String.join(" and ", parts);
    }

    public Facets facets() {
        return new Facets(distinct("esp"), distinct("country"), distinct("vertical"));
    }

    private List<String> distinct(String column) {
        return jdbc.queryForList("select distinct " + column + " from lists where " + column + " <> '' order by "
                + column + " limit 500", String.class);
    }

    public Detail detail(UUID publicId) {
        ListRow l = find(publicId);
        List<PartView> parts = jdbc.query("select * from list_parts where list_id = ? order by part_no",
                (rs, n) -> new PartView(rs.getObject("public_id", UUID.class), rs.getInt("part_no"),
                        rs.getInt("records"), rs.getInt("first_seq"), rs.getInt("last_seq"),
                        running(l.id(), rs.getInt("part_no"))), l.id());
        return new Detail(view(l), parts);
    }

    public ListView view(ListRow l) {
        boolean imported = l.status() == Status.READY;
        Report report = l.importedAt() == null && !imported ? null : new Report(l.totalLines(), l.records(),
                l.invalid(), l.duplicates(), l.removeDuplicates(), l.inOtherLists());
        Progress progress = l.status() == Status.IMPORTING || l.status() == Status.QUEUED
                ? new Progress(l.importPhase() == null ? "QUEUED" : l.importPhase(), l.importDone(), l.importTotal())
                : null;
        Mapping mapping = l.emailColumn() == null ? null : new Mapping(l.delimiter(),
                Boolean.TRUE.equals(l.hasHeader()), l.emailColumn(), l.columns());
        ListHooks.RunningJob running = running(l.id(), null);
        Validation validation = l.validationCounts() == null && running == null ? null
                : new Validation(l.validationCounts(), l.validatedAt(), running);
        return new ListView(l.publicId(), l.name(), l.esp(), l.country(), l.vertical(), l.removeDuplicates(),
                l.splitSize(), l.source(), l.sourceName(), l.status(), l.message(), l.records(), l.parts(),
                new Upload(l.fileSize(), l.received()), progress, report, mapping, validation, l.actorLabel(),
                l.createdAt(), l.importedAt());
    }

    private ListHooks.RunningJob running(long listId, Integer part) {
        for (ListHooks h : hooks.orderedStream().toList()) {
            ListHooks.RunningJob r = h.runningJob(listId, part);
            if (r != null) {
                return r;
            }
        }
        return null;
    }

    /** One part of a list (1..parts). */
    public record Part(int partNo, int records, int firstSeq, int lastSeq) {
    }

    public Part part(ListRow l, int partNo) {
        List<Part> found = jdbc.query("select part_no, records, first_seq, last_seq from list_parts where list_id = ? "
                + "and part_no = ?", (rs, n) -> new Part(rs.getInt(1), rs.getInt(2), rs.getInt(3), rs.getInt(4)),
                l.id(), partNo);
        if (found.isEmpty()) {
            throw BadRequestException.validation("part", "this list has no part " + partNo);
        }
        return found.getFirst();
    }

    /** Members in file order. Without a search, a page is read straight by its numbers (fast on any size). */
    public PageResponse<Member> members(UUID publicId, Integer partNo, String q, Pageable pageable) {
        ListRow l = find(publicId);
        int first = 1;
        int last = l.records();
        if (partNo != null) {
            Part p = part(l, partNo);
            first = p.firstSeq();
            last = p.lastSeq();
        }
        List<Member> items;
        long total;
        if (q == null || q.isBlank()) {
            total = Math.max(0, last - first + 1);
            long from = first + pageable.getOffset();
            long to = Math.min(last, from + pageable.getPageSize() - 1);
            items = from > last ? List.of() : jdbc.query("select seq, part_no, email, fields from list_members where "
                    + "list_id = ? and seq between ? and ? order by seq", MEMBER, l.id(), from, to);
        } else {
            Long n = jdbc.queryForObject("select count(*) from list_members where list_id = ? and seq between ? and ? "
                    + "and lower(email) like ? escape '\\'", Long.class, l.id(), first, last, like(q));
            total = n == null ? 0 : n;
            items = jdbc.query("select seq, part_no, email, fields from list_members where list_id = ? and seq between "
                            + "? and ? and lower(email) like ? escape '\\' order by seq limit ? offset ?", MEMBER, l.id(),
                    first, last, like(q), pageable.getPageSize(), pageable.getOffset());
        }
        int pages = (int) ((total + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), total, pages);
    }

    static final org.springframework.jdbc.core.RowMapper<Member> MEMBER = (rs, n) -> new Member(rs.getInt(1),
            rs.getInt(2), rs.getString(3), ListRow.strings(rs.getString(4)));

    /**
     * Streams the members of a list (or one part) in file order, with the
     * file's own columns; returns how many. Logged.
     */
    public int export(AuthPrincipal caller, UUID publicId, Integer partNo, Consumer<List<String>> header,
            Consumer<Member> sink) {
        ListRow l = find(publicId);
        if (l.status() != Status.READY) {
            throw new ConflictException("This list is not imported yet.");
        }
        int first = 1;
        int last = l.records();
        if (partNo != null) {
            Part p = part(l, partNo);
            first = p.firstSeq();
            last = p.lastSeq();
        }
        header.accept(l.columns() == null || l.columns().size() <= 1 ? List.of("email") : l.columns());
        int[] n = {0};
        int from = first;
        int to = last;
        jdbc.query(con -> {
            var ps = con.prepareStatement("select seq, part_no, email, fields from list_members where list_id = ? and "
                    + "seq between ? and ? order by seq");
            ps.setFetchSize(2000);
            ps.setLong(1, l.id());
            ps.setInt(2, from);
            ps.setInt(3, to);
            return ps;
        }, rs -> {
            sink.accept(MEMBER.mapRow(rs, n[0]));
            n[0]++;
        });
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("list", l.publicId().toString());
        d.put("rows", n[0]);
        if (partNo != null) {
            d.put("part", partNo);
        }
        activity.record(ActivityAction.LIST_EXPORTED, Party.of(caller), Party.label(l.name()), d);
        return n[0];
    }

    // ---- change ------------------------------------------------------------------

    public ListView update(AuthPrincipal caller, UUID publicId, UpdateRequest req) {
        ListRow l = find(publicId);
        String name = required("name", req.name());
        String esp = optional("esp", req.esp());
        String country = optional("country", req.country());
        String vertical = optional("vertical", req.vertical());
        tx.executeWithoutResult(s -> {
            jdbc.update("update lists set name = ?, esp = ?, country = ?, vertical = ?, updated_at = ? where id = ?",
                    name, esp, country, vertical, Timestamp.from(clock.instant()), l.id());
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("list", l.publicId().toString());
            changed(d, "name", l.name(), name);
            changed(d, "esp", l.esp(), esp);
            changed(d, "country", l.country(), country);
            changed(d, "vertical", l.vertical(), vertical);
            activity.record(ActivityAction.LIST_UPDATED, Party.of(caller), Party.label(name), d);
        });
        return view(find(publicId));
    }

    /** Deletes the list, its parts and members (contacts stay: they are the master database). */
    public void delete(AuthPrincipal caller, UUID publicId) {
        ListRow l = find(publicId);
        for (ListHooks h : hooks.orderedStream().toList()) {
            String why = h.blocksDelete(l);
            if (why != null) {
                throw new ConflictException(why);
            }
        }
        tx.executeWithoutResult(s -> {
            jdbc.update("delete from list_import_rows where list_id = ?", l.id());
            jdbc.update("delete from lists where id = ?", l.id());
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("list", l.publicId().toString());
            d.put("records", l.records());
            d.put("status", l.status().name());
            activity.record(ActivityAction.LIST_DELETED, Party.of(caller), Party.label(l.name()), d);
        });
        hooks.orderedStream().forEach(h -> h.deleted(l));
    }

    // ---- helpers -------------------------------------------------------------------

    static String required(String field, String value) {
        String v = value == null ? "" : value.trim();
        if (v.isEmpty()) {
            throw BadRequestException.validation(field, "is required");
        }
        if (v.length() > MAX_TEXT) {
            throw BadRequestException.validation(field, "is longer than " + MAX_TEXT + " characters");
        }
        return v;
    }

    static String optional(String field, String value) {
        String v = value == null ? "" : value.trim();
        if (v.length() > MAX_TEXT) {
            throw BadRequestException.validation(field, "is longer than " + MAX_TEXT + " characters");
        }
        return v;
    }

    private static void changed(Map<String, Object> d, String key, String before, String after) {
        if (!before.equals(after)) {
            d.put(key, before + " → " + after);
        }
    }

    static String like(String q) {
        return "%" + q.trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                + "%";
    }

    Instant now() {
        return clock.instant();
    }
}
