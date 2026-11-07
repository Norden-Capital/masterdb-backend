package ca.nordencapital.masterdb.dns.domain;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapAccountService;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapClient;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapClient.AccountDomain;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Domains (DNS job 2): add by hand, import from Namecheap, list, delete. */
@Service
public class DomainService {

    public static final int IMPORT_MAX = 500;
    private static final Logger log = LoggerFactory.getLogger(DomainService.class);

    /** API sort field → SQL. Nulls (manual domains, never checked) always last. */
    static final Map<String, String> SORT_COLUMNS = Map.of(
            "name", "name",
            "source", "source",
            "expiresAt", "nc_expires",
            "createdAt", "created_at",
            "healthStatus", "health_rank");

    private final JdbcTemplate jdbc;
    private final NamecheapAccountService account;
    private final NamecheapClient namecheap;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;

    public DomainService(JdbcTemplate jdbc, NamecheapAccountService account, NamecheapClient namecheap,
            ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.tx = new TransactionTemplate(transactions);
        this.jdbc = jdbc;
        this.account = account;
        this.namecheap = namecheap;
        this.activity = activity;
        this.clock = clock;
    }

    public enum Source { MANUAL, NAMECHEAP }

    public enum Expiry {
        /** Namecheap says expired, or the date has passed. */
        EXPIRED,
        /** Expires within 30 days. */
        DAYS_30,
        /** Expires within 90 days. */
        DAYS_90,
        /** No expiry known (manual domains). */
        UNKNOWN
    }

    public enum HealthFilter { OK, PROBLEM, ERROR, UNCHECKED }

    public record DomainItem(UUID publicId, String name, Source source, LocalDate registeredAt,
            LocalDate expiresAt, Boolean expired, Boolean autoRenew, Boolean locked, Boolean usesNamecheapDns,
            Instant namecheapSyncedAt, String healthStatus, Instant healthCheckedAt, Instant createdAt,
            Instant updatedAt) {
    }

    /** Internal: with the database id. */
    public record Domain(long id, DomainItem item) {
    }

    public record Filter(String q, Source source, Expiry expiry, HealthFilter health) {
    }

    /** One domain of the Namecheap account, for the import modal. */
    public record AccountDomainView(String name, LocalDate expiresAt, boolean expired, boolean autoRenew,
            boolean locked, boolean usesNamecheapDns, boolean alreadyAdded) {
    }

    public record ImportResult(List<String> added, List<String> updated, List<String> skipped) {
    }

    static final String SELECT = "select d.*, case d.health_status when 'PROBLEM' then 0 when 'ERROR' then 1 "
            + "when 'OK' then 2 else 3 end as health_rank from domains d";

    static final RowMapper<Domain> ROW = (rs, n) -> new Domain(rs.getLong("id"), new DomainItem(
            rs.getObject("public_id", UUID.class), rs.getString("name"), Source.valueOf(rs.getString("source")),
            date(rs.getDate("nc_created")), date(rs.getDate("nc_expires")), (Boolean) rs.getObject("nc_expired"),
            (Boolean) rs.getObject("nc_auto_renew"), (Boolean) rs.getObject("nc_locked"),
            (Boolean) rs.getObject("nc_uses_namecheap_dns"), instant(rs.getTimestamp("nc_synced_at")),
            rs.getString("health_status"), instant(rs.getTimestamp("health_checked_at")),
            instant(rs.getTimestamp("created_at")), instant(rs.getTimestamp("updated_at"))));

    @Transactional(readOnly = true)
    public PageResponse<DomainItem> list(Filter filter, Pageable pageable) {
        List<Object> args = new ArrayList<>();
        String where = where(filter, args);
        Long total = jdbc.queryForObject("select count(*) from domains d" + where, Long.class, args.toArray());
        StringBuilder order = new StringBuilder(" order by ");
        for (Sort.Order o : pageable.getSort()) {
            order.append(SORT_COLUMNS.get(o.getProperty())).append(o.isAscending() ? " asc" : " desc")
                    .append(" nulls last, ");
        }
        order.append("name asc");
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<DomainItem> items = jdbc.query("select * from (" + SELECT + ") d" + where + order + " limit ? offset ?",
                ROW, args.toArray()).stream().map(Domain::item).toList();
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    private String where(Filter f, List<Object> args) {
        List<String> parts = new ArrayList<>();
        if (f.q() != null && !f.q().isBlank()) {
            parts.add("d.name like ? escape '\\'");
            args.add("%" + f.q().trim().toLowerCase().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    + "%");
        }
        if (f.source() != null) {
            parts.add("d.source = ?");
            args.add(f.source().name());
        }
        if (f.expiry() != null) {
            LocalDate today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
            switch (f.expiry()) {
                case EXPIRED -> {
                    parts.add("(d.nc_expired or d.nc_expires < ?)");
                    args.add(Date.valueOf(today));
                }
                case DAYS_30, DAYS_90 -> {
                    parts.add("d.nc_expires >= ? and d.nc_expires <= ? and not coalesce(d.nc_expired, false)");
                    args.add(Date.valueOf(today));
                    args.add(Date.valueOf(today.plusDays(f.expiry() == Expiry.DAYS_30 ? 30 : 90)));
                }
                case UNKNOWN -> parts.add("d.nc_expires is null");
            }
        }
        if (f.health() != null) {
            if (f.health() == HealthFilter.UNCHECKED) {
                parts.add("d.health_status is null");
            } else {
                parts.add("d.health_status = ?");
                args.add(f.health().name());
            }
        }
        return parts.isEmpty() ? "" : " where " + String.join(" and ", parts);
    }

    @Transactional(readOnly = true)
    public Domain find(UUID publicId) {
        List<Domain> found = jdbc.query("select * from (" + SELECT + ") d where d.public_id = ?", ROW, publicId);
        if (found.isEmpty()) {
            throw new NotFoundException("This domain is not in MasterDB.");
        }
        return found.getFirst();
    }

    @Transactional(readOnly = true)
    public List<Domain> all() {
        return jdbc.query(SELECT + " order by d.name", ROW);
    }

    @Transactional
    public DomainItem addManual(AuthPrincipal caller, String input) {
        String name = DomainNames.normalize(input);
        if (name == null) {
            throw BadRequestException.validation("name", "must be a domain name like example.com (no http://, no path)");
        }
        Timestamp now = Timestamp.from(clock.instant());
        try {
            jdbc.update("insert into domains (name, source, created_at, updated_at) values (?, 'MANUAL', ?, ?)",
                    name, now, now);
        } catch (DuplicateKeyException e) {
            throw new ConflictException(name + " is already in MasterDB.");
        }
        Domain d = byName(name);
        activity.record(ActivityAction.DOMAIN_ADDED, Party.of(caller), party(d), Map.of("source", "MANUAL"));
        log.info("domain added by hand: {} by {}", name, caller.userPublicId());
        return d.item();
    }

    /** Every domain on the Namecheap account, each marked when it is already in MasterDB. */
    public List<AccountDomainView> namecheapDomains() {
        List<AccountDomain> remote = namecheap.allDomains(account.credentials());
        Set<String> present = new HashSet<>(jdbc.queryForList("select name from domains", String.class));
        return remote.stream().map(d -> new AccountDomainView(d.name(), d.expires(), d.expired(), d.autoRenew(),
                d.locked(), d.usesNamecheapDns(), present.contains(d.name()))).toList();
    }

    /**
     * Imports only the selected names. The list is fetched again, so only
     * names really on the account are accepted (400 otherwise). New names are
     * added as NAMECHEAP; names already present get fresh Namecheap metadata,
     * and a MANUAL one becomes NAMECHEAP (it is on the account, so its records
     * can now be managed).
     */
    public ImportResult importSelected(AuthPrincipal caller, List<String> names) {
        if (names == null || names.isEmpty()) {
            throw BadRequestException.validation("names", "select at least one domain");
        }
        if (names.size() > IMPORT_MAX) {
            throw BadRequestException.validation("names", "at most " + IMPORT_MAX + " at a time");
        }
        Set<String> wanted = new LinkedHashSet<>();
        for (String n : names) {
            String v = DomainNames.normalize(n);
            if (v == null) {
                throw BadRequestException.validation("names", "contains something that is not a domain name");
            }
            wanted.add(v);
        }
        Map<String, AccountDomain> remote = new LinkedHashMap<>();
        namecheap.allDomains(account.credentials()).forEach(d -> remote.put(d.name(), d));
        List<String> missing = wanted.stream().filter(n -> !remote.containsKey(n)).toList();
        if (!missing.isEmpty()) {
            throw BadRequestException.validation("names", "not on the Namecheap account: "
                    + String.join(", ", missing.subList(0, Math.min(5, missing.size()))));
        }
        // The Namecheap call above runs outside any transaction; only the writes are in one.
        return tx.execute(status -> save(caller, wanted, remote));
    }

    private ImportResult save(AuthPrincipal caller, Set<String> wanted, Map<String, AccountDomain> remote) {
        Timestamp now = Timestamp.from(clock.instant());
        List<String> added = new ArrayList<>();
        List<String> updated = new ArrayList<>();
        for (String name : wanted) {
            AccountDomain d = remote.get(name);
            int changed = jdbc.update("update domains set source = 'NAMECHEAP', nc_created = ?, nc_expires = ?, "
                            + "nc_expired = ?, nc_locked = ?, nc_auto_renew = ?, nc_uses_namecheap_dns = ?, "
                            + "nc_synced_at = ?, updated_at = ? where name = ?",
                    sqlDate(d.created()), sqlDate(d.expires()), d.expired(), d.locked(), d.autoRenew(),
                    d.usesNamecheapDns(), now, now, name);
            if (changed == 0) {
                jdbc.update("insert into domains (name, source, nc_created, nc_expires, nc_expired, nc_locked, "
                                + "nc_auto_renew, nc_uses_namecheap_dns, nc_synced_at, created_at, updated_at) "
                                + "values (?, 'NAMECHEAP', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        name, sqlDate(d.created()), sqlDate(d.expires()), d.expired(), d.locked(), d.autoRenew(),
                        d.usesNamecheapDns(), now, now, now);
                added.add(name);
            } else {
                updated.add(name);
            }
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("added", added.subList(0, Math.min(40, added.size())));
        details.put("addedCount", added.size());
        details.put("updatedCount", updated.size());
        activity.record(ActivityAction.DOMAINS_IMPORTED, Party.of(caller), Party.label("Namecheap account"), details);
        log.info("domains imported from namecheap: {} added, {} refreshed, by {}", added.size(), updated.size(),
                caller.userPublicId());
        return new ImportResult(added, updated, List.of());
    }

    @Transactional
    public void delete(AuthPrincipal caller, UUID publicId) {
        Domain d = find(publicId);
        jdbc.update("delete from domains where id = ?", d.id());
        activity.record(ActivityAction.DOMAIN_DELETED, Party.of(caller), party(d),
                Map.of("source", d.item().source().name()));
        log.info("domain deleted: {} by {}", d.item().name(), caller.userPublicId());
    }

    private Domain byName(String name) {
        return jdbc.query("select * from (" + SELECT + ") d where d.name = ?", ROW, name).getFirst();
    }

    public static Party party(Domain d) {
        return new Party(d.item().publicId(), d.item().name());
    }

    private static Date sqlDate(LocalDate d) {
        return d == null ? null : Date.valueOf(d);
    }

    private static LocalDate date(java.sql.Date d) {
        return d == null ? null : d.toLocalDate();
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
