package ca.nordencapital.masterdb.dns.health;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.domain.DomainService;
import ca.nordencapital.masterdb.dns.domain.DomainService.Domain;
import ca.nordencapital.masterdb.dns.health.HealthChecks.Result;
import ca.nordencapital.masterdb.dns.health.HealthChecks.Status;
import ca.nordencapital.masterdb.dns.records.DnsRecordService;
import ca.nordencapital.masterdb.dns.records.DnsSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DNS health (job 4): checks a domain against public DNS, stores the result
 * per record, and re-checks every domain daily. Lookups run outside any
 * transaction; only storing the result is one.
 */
@Service
public class DnsHealthService {

    private static final Logger log = LoggerFactory.getLogger(DnsHealthService.class);

    private final JdbcTemplate jdbc;
    private final DomainService domains;
    private final DnsRecordService records;
    private final HealthChecks checks;
    private final PtrExpectations ptr;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final AtomicBoolean dailyRunning = new AtomicBoolean();

    public DnsHealthService(JdbcTemplate jdbc, DomainService domains, DnsRecordService records, DnsLookup dns,
            PtrExpectations ptr, ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.domains = domains;
        this.records = records;
        this.checks = new HealthChecks(dns);
        this.ptr = ptr;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public record Report(String domain, String status, Instant checkedAt, List<Result> records) {
    }

    @Transactional(readOnly = true)
    public Report report(UUID domainId) {
        Domain d = domains.find(domainId);
        List<Result> rows = jdbc.query("select record, status, detail, expected, found from domain_health_checks "
                        + "where domain_id = ? order by array_position(array['A','MX','SPF','DKIM','DMARC','BIMI','PTR'], "
                        + "record::text)", (rs, n) -> new Result(rs.getString(1), Status.valueOf(rs.getString(2)),
                        rs.getString(3), rs.getString(4), rs.getString(5)), d.id());
        return new Report(d.item().name(), d.item().healthStatus(), d.item().healthCheckedAt(), rows);
    }

    /** "Re-check" on one domain. */
    public Report check(AuthPrincipal caller, UUID domainId) {
        Domain d = domains.find(domainId);
        Status status = run(d);
        tx.executeWithoutResult(t -> activity.record(ActivityAction.DNS_HEALTH_CHECKED, Party.of(caller),
                DomainService.party(d), Map.of("status", status.name())));
        return report(domainId);
    }

    /** Daily, every domain one after the other (UTC, {@code app.dns.health-cron}). */
    @Scheduled(cron = "${app.dns.health-cron:0 15 4 * * *}", zone = "UTC")
    public void checkAllDaily() {
        if (!dailyRunning.compareAndSet(false, true)) {
            return;
        }
        try {
            int problems = 0;
            int errors = 0;
            List<Domain> all = domains.all();
            for (Domain d : all) {
                try {
                    Status s = run(d);
                    problems += s == Status.PROBLEM ? 1 : 0;
                    errors += s == Status.ERROR ? 1 : 0;
                } catch (RuntimeException e) {
                    errors++;
                    log.warn("dns health of {} failed: {}", d.item().name(), e.getClass().getSimpleName());
                }
            }
            int checked = all.size();
            int p = problems;
            int er = errors;
            tx.executeWithoutResult(t -> activity.record(ActivityAction.DNS_HEALTH_CHECKED, Party.label("Daily check"),
                    Party.label("All domains"), Map.of("domains", checked, "problems", p, "errors", er)));
            log.info("daily dns health: {} domains, {} with problems, {} lookup errors", checked, p, er);
        } finally {
            dailyRunning.set(false);
        }
    }

    /** Runs the checks and stores them; returns the overall status. */
    Status run(Domain d) {
        DnsSettings s = records.settingsOf(d.id());
        boolean saved = s.updatedAt() != null;
        List<Result> results = checks.all(d.item().name(), s, saved, ptr.forDomain(d.id(), d.item().name()));
        Status overall = HealthChecks.overall(results);
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> {
            jdbc.update("delete from domain_health_checks where domain_id = ?", d.id());
            for (Result r : results) {
                jdbc.update("insert into domain_health_checks (domain_id, record, status, detail, expected, found, "
                                + "checked_at) values (?, ?, ?, ?, ?, ?, ?)", d.id(), r.record(), r.status().name(),
                        cut(r.detail(), 500), cut(r.expected(), 2000), cut(r.found(), 4000), now);
            }
            jdbc.update("update domains set health_status = ?, health_checked_at = ? where id = ?", overall.name(), now,
                    d.id());
        });
        return overall;
    }

    private static String cut(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }
}
