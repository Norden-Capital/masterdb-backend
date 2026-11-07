package ca.nordencapital.masterdb.dns.records;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.HostRecord;
import ca.nordencapital.masterdb.dns.domain.DomainService;
import ca.nordencapital.masterdb.dns.domain.DomainService.Domain;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapAccountService;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapClient;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapClient.Zone;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapCredentials;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapProperties;
import ca.nordencapital.masterdb.dns.records.ManagedRecords.Change;
import ca.nordencapital.masterdb.dns.records.ManagedRecords.Merge;
import ca.nordencapital.masterdb.dns.records.ManagedRecords.RecordChange;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.FieldViolation;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * DNS job 3: the managed records of a Namecheap domain.
 *
 * <p>Namecheap's setHosts <b>replaces every record</b>. So every write is:
 * read the current set (getHosts), merge (keep everything MasterDB does not
 * manage), show the before/after with a token of what was read, and only on
 * a confirm carrying that token: read again (409 if it changed), save the
 * current set as a snapshot, write, read back to verify. Restoring a
 * snapshot is the same flow with the snapshot as the target.
 */
@Service
public class DnsRecordService {

    static final int MAX_RECORDS = 100;
    static final Set<String> POLICIES = Set.of("none", "quarantine", "reject");
    static final Pattern SELECTOR = Pattern.compile("[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?");
    static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]+={0,2}");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Logger log = LoggerFactory.getLogger(DnsRecordService.class);

    private final JdbcTemplate jdbc;
    private final DomainService domains;
    private final NamecheapAccountService account;
    private final NamecheapClient namecheap;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    /** One write at a time (single backend instance): a second one waits, then sees the first one's result. */
    private final ReentrantLock writeLock = new ReentrantLock();

    public DnsRecordService(JdbcTemplate jdbc, DomainService domains, NamecheapAccountService account,
            NamecheapClient namecheap, ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.domains = domains;
        this.account = account;
        this.namecheap = namecheap;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public record Plan(String domain, String emailType, String token, List<RecordChange> changes,
            List<HostRecord> before, List<HostRecord> after, List<String> warnings) {
    }

    public record WriteResult(boolean verified, List<HostRecord> missing, UUID snapshotId) {
    }

    public record SnapshotView(UUID publicId, Instant createdAt, String actorLabel, String reason, String emailType,
            int recordCount, List<HostRecord> records) {
    }

    // ---- settings ----------------------------------------------------------------

    @Transactional(readOnly = true)
    public DnsSettings settings(UUID domainId) {
        return settingsOf(domains.find(domainId).id());
    }

    public DnsSettings settingsOf(long id) {
        return jdbc.queryForObject("select mail_ip, dkim_selector, dkim_public_key, dmarc_policy, bimi_logo_url, "
                + "bimi_certificate_url, dns_settings_updated_at from domains where id = ?", (rs, n) -> new DnsSettings(
                rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6),
                rs.getTimestamp(7) == null ? null : rs.getTimestamp(7).toInstant()), id);
    }

    @Transactional
    public DnsSettings saveSettings(AuthPrincipal caller, UUID domainId, DnsSettings input) {
        Domain d = domains.find(domainId);
        DnsSettings s = validate(input);
        jdbc.update("update domains set mail_ip = ?, dkim_selector = ?, dkim_public_key = ?, dmarc_policy = ?, "
                        + "bimi_logo_url = ?, bimi_certificate_url = ?, dns_settings_updated_at = ?, updated_at = ? "
                        + "where id = ?", s.mailIp(), s.dkimSelector(), s.dkimPublicKey(), s.dmarcPolicy(),
                s.bimiLogoUrl(), s.bimiCertificateUrl(), Timestamp.from(clock.instant()),
                Timestamp.from(clock.instant()), d.id());
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("mailIp", s.mailIp() == null ? "" : s.mailIp());
        details.put("dkimSelector", s.dkimSelector());
        details.put("dkimKey", s.dkimPublicKey() != null);
        details.put("dmarcPolicy", s.dmarcPolicy());
        details.put("bimi", s.bimiLogoUrl() != null);
        activity.record(ActivityAction.DNS_SETTINGS_CHANGED, Party.of(caller), DomainService.party(d), details);
        return settingsOf(d.id());
    }

    static DnsSettings validate(DnsSettings in) {
        List<FieldViolation> errors = new ArrayList<>();
        String ip = blankToNull(in.mailIp());
        if (ip != null && !NamecheapProperties.isIpv4(ip)) {
            errors.add(new FieldViolation("mailIp", "must be an IPv4 address like 203.0.113.10"));
        }
        String selector = blankToNull(in.dkimSelector());
        selector = selector == null ? "mail" : selector.toLowerCase(Locale.ROOT);
        if (!SELECTOR.matcher(selector).matches()) {
            errors.add(new FieldViolation("dkimSelector", "must be letters, digits, dots, dashes or underscores"));
        }
        String key = blankToNull(in.dkimPublicKey());
        if (key != null) {
            key = dkimKey(key);
            if (!BASE64.matcher(key).matches() || key.length() < 64 || key.length() > 4096 || !decodes(key)) {
                errors.add(new FieldViolation("dkimPublicKey", "must be the base64 public key (the p= part)"));
            }
        }
        String policy = blankToNull(in.dmarcPolicy());
        policy = policy == null ? "quarantine" : policy.toLowerCase(Locale.ROOT);
        if (!POLICIES.contains(policy)) {
            errors.add(new FieldViolation("dmarcPolicy", "must be none, quarantine or reject"));
        }
        String logo = blankToNull(in.bimiLogoUrl());
        String cert = blankToNull(in.bimiCertificateUrl());
        if (logo != null && !https(logo)) {
            errors.add(new FieldViolation("bimiLogoUrl", "must be an https:// URL without ; or spaces"));
        }
        if (cert != null && (logo == null || !https(cert))) {
            errors.add(new FieldViolation("bimiCertificateUrl", logo == null ? "needs a logo URL too"
                    : "must be an https:// URL without ; or spaces"));
        }
        if (!errors.isEmpty()) {
            throw BadRequestException.validation(errors);
        }
        return new DnsSettings(ip, selector, key, policy, logo, cert, null);
    }

    /** The p= value of a pasted DKIM record, or the pasted key, without quotes and whitespace. */
    static String dkimKey(String pasted) {
        java.util.regex.Matcher m = Pattern.compile("(?i)(?:^|;)\\s*p=([^;]*)").matcher(pasted);
        String v = m.find() ? m.group(1) : pasted;
        return v.replaceAll("[\"\\s]", "");
    }

    private static boolean decodes(String b64) {
        try {
            Base64.getDecoder().decode(b64);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean https(String url) {
        if (url.length() > 500 || url.contains(";") || url.contains(" ")) {
            return false;
        }
        try {
            URI u = URI.create(url);
            return "https".equalsIgnoreCase(u.getScheme()) && u.getHost() != null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // ---- setup -------------------------------------------------------------------

    /** Reads Namecheap and shows the before/after of writing the managed records. Writes nothing. */
    public Plan preview(UUID domainId) {
        Domain d = writable(domainId);
        DnsSettings s = settingsForSetup(d);
        Zone zone = zone(d, account.credentials());
        return setupPlan(d, s, zone);
    }

    public WriteResult apply(AuthPrincipal caller, UUID domainId, String token) {
        writeLock.lock();
        try {
            Domain d = writable(domainId);
            DnsSettings s = settingsForSetup(d);
            NamecheapCredentials credentials = account.credentials();
            Zone zone = zone(d, credentials);
            Plan plan = setupPlan(d, s, zone);
            if (!plan.token().equals(token)) {
                throw DnsWriteException.changed();
            }
            UUID snapshot = saveSnapshot(caller, d, zone, "BEFORE_SETUP");
            namecheap.setHosts(credentials, d.item().name(), "MX", plan.after());
            List<HostRecord> missing = ManagedRecords.missing(ManagedRecords.desired(d.item().name(), s),
                    namecheap.getHosts(credentials, d.item().name()).records());
            record(caller, d, ActivityAction.DNS_RECORDS_WRITTEN, plan, snapshot, missing);
            return new WriteResult(missing.isEmpty(), missing, snapshot);
        } finally {
            writeLock.unlock();
        }
    }

    private Plan setupPlan(Domain d, DnsSettings s, Zone zone) {
        List<HostRecord> desired = ManagedRecords.desired(d.item().name(), s);
        Merge merge = ManagedRecords.merge(zone.records(), desired, s);
        List<String> warnings = new ArrayList<>();
        if (!"MX".equals(zone.emailType())) {
            warnings.add("Namecheap mail settings change from " + zone.emailType()
                    + " to Custom MX (the MX record above).");
        }
        if (s.dkimPublicKey() == null) {
            warnings.add("No DKIM key is set, so no DKIM record is written; an existing one stays.");
        }
        checkWritable(merge.after());
        return new Plan(d.item().name(), zone.emailType(), token(zone, "setup:" + desiredKey(desired)),
                merge.changes(), zone.records(), merge.after(), warnings);
    }

    // ---- snapshots ---------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<SnapshotView> snapshots(UUID domainId) {
        Domain d = domains.find(domainId);
        return jdbc.query("select public_id, created_at, actor_label, reason, email_type, record_count from "
                + "dns_snapshots where domain_id = ? order by created_at desc, id desc limit 50", (rs, n) ->
                new SnapshotView(rs.getObject(1, UUID.class), rs.getTimestamp(2).toInstant(), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getInt(6), null), d.id());
    }

    @Transactional(readOnly = true)
    public SnapshotView snapshot(UUID domainId, UUID snapshotId) {
        Domain d = domains.find(domainId);
        List<SnapshotView> found = jdbc.query("select public_id, created_at, actor_label, reason, email_type, "
                + "record_count, hosts::text from dns_snapshots where domain_id = ? and public_id = ?", (rs, n) ->
                new SnapshotView(rs.getObject(1, UUID.class), rs.getTimestamp(2).toInstant(), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getInt(6),
                        List.of(JSON.readValue(rs.getString(7), HostRecord[].class))), d.id(), snapshotId);
        if (found.isEmpty()) {
            throw new NotFoundException("This snapshot does not exist for this domain.");
        }
        return found.getFirst();
    }

    public Plan restorePreview(UUID domainId, UUID snapshotId) {
        Domain d = writable(domainId);
        SnapshotView snap = snapshot(domainId, snapshotId);
        return restorePlan(d, snap, zone(d, account.credentials()));
    }

    public WriteResult restore(AuthPrincipal caller, UUID domainId, UUID snapshotId, String token) {
        writeLock.lock();
        try {
            Domain d = writable(domainId);
            SnapshotView snap = snapshot(domainId, snapshotId);
            NamecheapCredentials credentials = account.credentials();
            Zone zone = zone(d, credentials);
            Plan plan = restorePlan(d, snap, zone);
            if (!plan.token().equals(token)) {
                throw DnsWriteException.changed();
            }
            UUID saved = saveSnapshot(caller, d, zone, "BEFORE_RESTORE");
            namecheap.setHosts(credentials, d.item().name(), snap.emailType(), snap.records());
            List<HostRecord> missing = ManagedRecords.missing(snap.records(),
                    namecheap.getHosts(credentials, d.item().name()).records());
            record(caller, d, ActivityAction.DNS_RECORDS_RESTORED, plan, saved, missing);
            return new WriteResult(missing.isEmpty(), missing, saved);
        } finally {
            writeLock.unlock();
        }
    }

    private Plan restorePlan(Domain d, SnapshotView snap, Zone zone) {
        Merge merge = ManagedRecords.replaceWith(zone.records(), snap.records());
        List<String> warnings = new ArrayList<>();
        if (!snap.emailType().equals(zone.emailType())) {
            warnings.add("Namecheap mail settings change from " + zone.emailType() + " back to " + snap.emailType()
                    + ".");
        }
        checkWritable(merge.after());
        return new Plan(d.item().name(), zone.emailType(), token(zone, "restore:" + snap.publicId()),
                merge.changes(), zone.records(), merge.after(), warnings);
    }

    // ---- helpers -----------------------------------------------------------------

    private Domain writable(UUID domainId) {
        Domain d = domains.find(domainId);
        if (d.item().source() != DomainService.Source.NAMECHEAP) {
            throw DnsWriteException.refused("Records can only be written for domains on the Namecheap account. "
                    + "Import this domain from Namecheap first.");
        }
        return d;
    }

    private DnsSettings settingsForSetup(Domain d) {
        DnsSettings s = settingsOf(d.id());
        if (s.mailIp() == null) {
            throw DnsWriteException.refused("Set the mail server IP under Managed records first.");
        }
        return s;
    }

    private Zone zone(Domain d, NamecheapCredentials credentials) {
        Zone zone = namecheap.getHosts(credentials, d.item().name());
        if (!zone.usingNamecheapDns()) {
            throw DnsWriteException.refused("This domain does not use Namecheap DNS. Its records live at another "
                    + "DNS provider; set them there.");
        }
        for (HostRecord r : zone.records()) {
            if (!ManagedRecords.SUPPORTED.contains(r.type())) {
                throw DnsWriteException.refused("The domain has a " + r.type() + " record that Namecheap's setHosts "
                        + "can't keep. Nothing was changed; edit this domain at Namecheap.");
            }
        }
        return zone;
    }

    private static void checkWritable(List<HostRecord> after) {
        if (after.size() > MAX_RECORDS) {
            throw DnsWriteException.refused("More than " + MAX_RECORDS + " records: too many to write safely.");
        }
    }

    /** Saved in its own transaction, committed before Namecheap is called, so it exists even if the write fails. */
    private UUID saveSnapshot(AuthPrincipal caller, Domain d, Zone zone, String reason) {
        UUID id = UUID.randomUUID();
        tx.executeWithoutResult(status -> jdbc.update("insert into dns_snapshots (public_id, domain_id, created_at, "
                        + "actor_public_id, actor_label, reason, email_type, record_count, hosts) "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)", id, d.id(), Timestamp.from(clock.instant()),
                caller.userPublicId(), caller.email(), reason, zone.emailType(), zone.records().size(),
                JSON.writeValueAsString(zone.records())));
        return id;
    }

    private void record(AuthPrincipal caller, Domain d, ActivityAction action, Plan plan, UUID snapshot,
            List<HostRecord> missing) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("added", plan.changes().stream().filter(c -> c.change() == Change.ADD).count());
        details.put("removed", plan.changes().stream().filter(c -> c.change() == Change.REMOVE).count());
        details.put("kept", plan.changes().stream().filter(c -> c.change() == Change.KEEP).count());
        details.put("snapshot", snapshot.toString());
        details.put("verified", missing.isEmpty());
        tx.executeWithoutResult(status -> activity.record(action, Party.of(caller), DomainService.party(d), details));
        log.info("dns {} for {}: {} records, verified={}, snapshot {} by {}", action, d.item().name(),
                plan.after().size(), missing.isEmpty(), snapshot, caller.userPublicId());
    }

    /** What the preview was based on: the records read, and what was going to be written. */
    private static String token(Zone zone, String target) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update((zone.emailType() + "\n" + target + "\n").getBytes(StandardCharsets.UTF_8));
            for (HostRecord r : zone.records()) {
                sha.update(String.join("\t", r.name(), r.type(), r.address(), r.mxPref(), r.ttl(), r.flag(), r.tag(),
                        "\n").getBytes(StandardCharsets.UTF_8));
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String desiredKey(List<HostRecord> desired) {
        StringBuilder b = new StringBuilder();
        desired.forEach(r -> b.append(r.name()).append(' ').append(r.type()).append(' ').append(r.address()).append('|'));
        return b.toString();
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
