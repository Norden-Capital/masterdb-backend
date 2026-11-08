package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.validation.Category;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Validation, job 3: what the jobs found. The addresses of one job (by
 * category, with the reason), its exports, and "List status": every address
 * ever validated in a job, with its latest result, grouped by category.
 */
@Service
public class ResultsService {

    private final JdbcTemplate jdbc;
    private final BulkJobService jobs;

    public ResultsService(JdbcTemplate jdbc, BulkJobService jobs) {
        this.jdbc = jdbc;
        this.jobs = jobs;
    }

    /** One address of a job and its result ({@code category} null = still to check). */
    public record EmailResult(String email, Category category, Integer smtpCode, String mxHost, String reason,
            String reply, String serverName, Instant checkedAt, String jobName, UUID jobId, List<String> fields) {
    }

    private static final RowMapper<EmailResult> ROW = (rs, n) -> new EmailResult(rs.getString("email"),
            rs.getString("category") == null ? null : Category.valueOf(rs.getString("category")),
            (Integer) rs.getObject("smtp_code"), rs.getString("mx_host"), rs.getString("reason"),
            rs.getString("reply"), rs.getString("server_name"), ts(rs.getTimestamp("checked_at")),
            rs.getString("job_name"), rs.getObject("job_public_id", UUID.class), null);

    /** Same, with the list member's own cells (export of a job on a list). */
    private static final RowMapper<EmailResult> ROW_WITH_FIELDS = (rs, n) -> {
        EmailResult r = ROW.mapRow(rs, n);
        return new EmailResult(r.email(), r.category(), r.smtpCode(), r.mxHost(), r.reason(), r.reply(),
                r.serverName(), r.checkedAt(), r.jobName(), r.jobId(), ListRow.strings(rs.getString("member_fields")));
    };

    // ---- one job -------------------------------------------------------------------

    /** {@code category} null = all; "PENDING" is passed as {@code pending = true}. */
    public PageResponse<EmailResult> emails(UUID jobId, Category category, boolean pending, String q,
            Pageable pageable) {
        BulkJobService.Job job = jobs.find(jobId);
        long id = job.id();
        if (!pending && category == null && (q == null || q.isBlank())) {
            // Every address of the job: seq is 1..total, so a page is read straight by its numbers.
            long from = pageable.getOffset() + 1;
            long to = pageable.getOffset() + pageable.getPageSize();
            List<EmailResult> items = jdbc.query("select e.*, j.name as job_name, j.public_id as job_public_id from "
                    + "validation_job_emails e join validation_jobs j on j.id = e.job_id where e.job_id = ? and e.seq "
                    + "between ? and ? order by e.seq", ROW, id, from, to);
            return page(items, (long) job.total(), pageable);
        }
        List<Object> args = new ArrayList<>(List.of(id));
        StringBuilder where = new StringBuilder(" where e.job_id = ?");
        if (pending) {
            where.append(" and e.category is null");
        } else if (category != null) {
            where.append(" and e.category = ?");
            args.add(category.name());
        }
        like(q, where, args);
        Long total = jdbc.queryForObject("select count(*) from validation_job_emails e" + where, Long.class,
                args.toArray());
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<EmailResult> items = jdbc.query("select e.*, j.name as job_name, j.public_id as job_public_id from "
                + "validation_job_emails e join validation_jobs j on j.id = e.job_id" + where
                + " order by e.seq limit ? offset ?", ROW, args.toArray());
        return page(items, total, pageable);
    }

    /** The job's name, for export file names. */
    public String jobName(UUID jobId) {
        return jobs.find(jobId).name();
    }

    /**
     * The columns of the list a job came from (its header, or "Column N"), or
     * null for a pasted job, a list that is gone, or a one-column file.
     */
    public List<String> listColumns(UUID jobId) {
        BulkJobService.Job job = jobs.find(jobId);
        if (job.listId() == null) {
            return null;
        }
        String json = jdbc.query("select columns::text from lists where id = ?", (rs, n) -> rs.getString(1),
                job.listId()).stream().findFirst().orElse(null);
        List<String> found = json == null ? null : ListRow.strings(json);
        return found == null || found.size() <= 1 ? null : found;
    }

    /** Streams the job's addresses of one category (or all, for the detailed CSV) in list order; returns the count. */
    public int export(UUID jobId, Category category, Consumer<EmailResult> sink) {
        long id = jobs.find(jobId).id();
        int[] n = {0};
        String where = category == null ? " where e.job_id = ? and e.category is not null"
                : " where e.job_id = ? and e.category = ?";
        Object[] args = category == null ? new Object[] {id} : new Object[] {id, category.name()};
        jdbc.query(con -> {
            var ps = con.prepareStatement("select e.*, j.name as job_name, j.public_id as job_public_id, m.fields::text "
                    + "as member_fields from validation_job_emails e join validation_jobs j on j.id = e.job_id left join "
                    + "list_members m on m.id = e.member_id" + where + " order by e.seq");
            ps.setFetchSize(1000);
            for (int i = 0; i < args.length; i++) {
                ps.setObject(i + 1, args[i]);
            }
            return ps;
        }, rs -> {
            sink.accept(ROW_WITH_FIELDS.mapRow(rs, n[0]));
            n[0]++;
        });
        return n[0];
    }

    // ---- list status (every job) -----------------------------------------------------

    /** The latest result of each address, over every job (case of the address ignored). */
    private static final String LATEST = "with latest as (select distinct on (lower(e.email)) e.*, j.name as job_name, "
            + "j.public_id as job_public_id from validation_job_emails e join validation_jobs j on j.id = e.job_id "
            + "where e.category is not null order by lower(e.email), e.checked_at desc, e.id desc) ";

    public record Status(int addresses, int jobs, Map<Category, Integer> categories) {
    }

    public Status status() {
        Map<Category, Integer> counts = new EnumMap<>(Category.class);
        for (Category c : Category.values()) {
            counts.put(c, 0);
        }
        int[] total = {0};
        jdbc.query(LATEST + "select category, count(*) from latest group by category", rs -> {
            counts.put(Category.valueOf(rs.getString(1)), rs.getInt(2));
            total[0] += rs.getInt(2);
        });
        Integer jobCount = jdbc.queryForObject("select count(*) from validation_jobs", Integer.class);
        return new Status(total[0], jobCount == null ? 0 : jobCount, counts);
    }

    public PageResponse<EmailResult> latest(Category category, String q, Pageable pageable) {
        List<Object> args = new ArrayList<>();
        StringBuilder where = new StringBuilder(" where true");
        if (category != null) {
            where.append(" and category = ?");
            args.add(category.name());
        }
        like(q, where, args);
        String w = where.toString().replace("e.email", "email");
        Long total = jdbc.queryForObject(LATEST + "select count(*) from latest" + w, Long.class, args.toArray());
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<EmailResult> items = jdbc.query(LATEST + "select * from latest" + w
                + " order by checked_at desc, id desc limit ? offset ?", ROW, args.toArray());
        return page(items, total, pageable);
    }

    // ---- helpers -------------------------------------------------------------------

    private static void like(String q, StringBuilder where, List<Object> args) {
        if (q != null && !q.isBlank()) {
            where.append(" and lower(e.email) like ? escape '\\'");
            args.add("%" + q.trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%");
        }
    }

    private static <T> PageResponse<T> page(List<T> items, Long total, Pageable pageable) {
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    private static Instant ts(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
