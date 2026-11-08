package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.lists.ListHooks;
import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.validation.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Validation as List management sees it: the job running on a list (or a
 * part), a list can't be deleted while one runs, and each list's latest
 * results (the newest answer per address over every job of the list, saved
 * on the list when a job stops or finishes, so the lists table never has to
 * count a million rows).
 */
@Component
public class ListValidation implements ListHooks, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ListValidation.class);

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "list-validation-summary");
        t.setDaemon(true);
        return t;
    });

    public ListValidation(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public RunningJob runningJob(long listId, Integer part) {
        List<RunningJob> found = jdbc.query("select public_id, status, total, pending from validation_jobs where "
                + "list_id = ? and status in ('PREPARING', 'RUNNING')" + (part == null ? "" : " and list_part = ?")
                + " order by id desc limit 1", (rs, n) -> new RunningJob(rs.getObject(1, UUID.class), rs.getString(2),
                rs.getInt(3), rs.getInt(3) - rs.getInt(4)), part == null ? new Object[] {listId}
                : new Object[] {listId, part});
        return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public String blocksDelete(ListRow list) {
        return runningJob(list.id(), null) == null ? null
                : "A validation job is running on this list. Stop it (Validation → Results) before deleting the list.";
    }

    /** Recounts the list's latest results in the background (null = nothing to do). */
    public void refreshLater(Long listId) {
        if (listId != null) {
            worker.submit(() -> {
                try {
                    refresh(listId);
                } catch (RuntimeException e) {
                    log.warn("list {}: validation summary not updated: {}", listId, e.toString());
                }
            });
        }
    }

    /** The newest result per address of the list over all its jobs, by category; saved on the list. */
    public Map<String, Integer> refresh(long listId) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Category c : Category.values()) {
            counts.put(c.name(), 0);
        }
        jdbc.query("select category, count(*) from (select distinct on (e.member_id) e.category from "
                + "validation_job_emails e join validation_jobs j on j.id = e.job_id where j.list_id = ? and "
                + "e.member_id is not null and e.category is not null order by e.member_id, e.checked_at desc, e.id "
                + "desc) t group by category", rs -> {
                    counts.put(rs.getString(1), rs.getInt(2));
                }, listId);
        boolean any = counts.values().stream().anyMatch(n -> n > 0);
        jdbc.update("update lists set validation_counts = ?::jsonb, validated_at = ? where id = ?",
                any ? ListRow.json(counts) : null, any ? Timestamp.from(clock.instant()) : null, listId);
        return counts;
    }

    @Override
    public void destroy() {
        worker.shutdown();
        try {
            worker.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
