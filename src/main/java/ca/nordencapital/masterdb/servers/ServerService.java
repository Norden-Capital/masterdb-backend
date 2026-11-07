package ca.nordencapital.masterdb.servers;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.permission.ForbiddenException;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.domain.DomainService;
import ca.nordencapital.masterdb.servers.ssh.SshFailure;
import ca.nordencapital.masterdb.servers.ssh.SshKeys;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.PresentedKey;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Result;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.FieldViolation;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Server management, job 1: the VPS servers. Add, edit, list, delete, and
 * "Connect": trust-on-first-use host-key pinning, then a login test with
 * MasterDB's key. A pinned key is never asked about again; a different key
 * blocks the server until the Owner accepts it.
 */
@Service
public class ServerService {

    static final Pattern USER = Pattern.compile("[a-z_][a-z0-9_.-]{0,31}");
    static final Map<String, String> SORT_COLUMNS = Map.of(
            "name", "lower(s.name)",
            "ip", "s.ip",
            "expiresOn", "s.expires_on",
            "createdAt", "s.created_at",
            "connectionStatus", "s.connection_status",
            "healthStatus", "case s.health_status when 'PROBLEM' then 0 when 'ERROR' then 1 when 'WARNING' then 2 "
                    + "when 'OK' then 3 end");
    private static final Duration LOGIN_TEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Logger log = LoggerFactory.getLogger(ServerService.class);

    private final JdbcTemplate jdbc;
    private final DomainService domains;
    private final ServerSsh ssh;
    private final ca.nordencapital.masterdb.servers.ssh.SshIdentityService identity;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final boolean allowPrivateIps;

    public ServerService(JdbcTemplate jdbc, DomainService domains, ServerSsh ssh,
            ca.nordencapital.masterdb.servers.ssh.SshIdentityService identity, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions,
            @Value("${app.servers.allow-private-ips:false}") boolean allowPrivateIps) {
        this.jdbc = jdbc;
        this.domains = domains;
        this.ssh = ssh;
        this.identity = identity;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
        this.allowPrivateIps = allowPrivateIps;
    }

    public enum ConnectionStatus {
        /** Never connected (or the address changed). */
        NEW,
        /** Connected once; its host key waits to be trusted. */
        KEY_PENDING,
        /** Host key trusted and MasterDB's key logs in. */
        CONNECTED,
        /** Host key trusted, but MasterDB's key is not accepted. */
        AUTH_FAILED,
        /** No SSH answer at the last try. */
        UNREACHABLE,
        /** The server presented another host key: blocked until the Owner accepts it. */
        KEY_CHANGED
    }

    public enum Expiry {
        EXPIRED,
        /** Expires within 14 days (the warning threshold). */
        DAYS_14,
        DAYS_30
    }

    public enum HealthFilter { OK, WARNING, PROBLEM, ERROR, UNCHECKED }

    public record Filter(String q, ConnectionStatus connection, Expiry expiry, HealthFilter health) {
        public Filter(String q, ConnectionStatus connection, Expiry expiry) {
            this(q, connection, expiry, null);
        }
    }

    public record LinkedDomain(UUID publicId, String name) {
    }

    public record KeyView(String type, String fingerprint, Instant at) {
    }

    public record ServerItem(UUID publicId, String name, String ip, int sshPort, String sshUser, LocalDate expiresOn,
            long daysLeft, String notes, LinkedDomain domain, ConnectionStatus connectionStatus,
            String connectionMessage, Instant connectionCheckedAt, KeyView hostKey, KeyView presentedKey,
            String os, Boolean privileged, String healthStatus, Instant healthCheckedAt, String heloHost,
            String mailFrom, Instant createdAt, Instant updatedAt) {
    }

    /** Internal: with database ids and the stored keys. */
    public record Server(long id, Long domainId, String pinnedKey, String seenKey, String osId, String osVersion,
            ServerItem item) {
    }

    public record Input(String name, String ip, Integer sshPort, String sshUser, LocalDate expiresOn, String notes,
            UUID domainId) {
    }

    /** What the Connect button answers: the server as it is now, and what happened. */
    public record ConnectResult(String outcome, String message, ServerItem server) {
    }

    static final String SELECT = "select s.*, d.public_id as domain_public_id, d.name as domain_name from servers s "
            + "left join domains d on d.id = s.domain_id";

    private RowMapper<Server> row() {
        LocalDate today = today();
        return (rs, n) -> {
            LocalDate expires = rs.getDate("expires_on").toLocalDate();
            UUID domainId = rs.getObject("domain_public_id", UUID.class);
            KeyView pinned = rs.getString("host_key") == null ? null : new KeyView(rs.getString("host_key_type"),
                    rs.getString("host_key_fingerprint"), instant(rs.getTimestamp("host_key_pinned_at")));
            KeyView seen = rs.getString("seen_key") == null ? null : new KeyView(rs.getString("seen_key_type"),
                    rs.getString("seen_key_fingerprint"), instant(rs.getTimestamp("seen_key_at")));
            ServerItem item = new ServerItem(rs.getObject("public_id", UUID.class), rs.getString("name"),
                    rs.getString("ip"), rs.getInt("ssh_port"), rs.getString("ssh_user"), expires,
                    ChronoUnit.DAYS.between(today, expires), rs.getString("notes"),
                    domainId == null ? null : new LinkedDomain(domainId, rs.getString("domain_name")),
                    ConnectionStatus.valueOf(rs.getString("connection_status")), rs.getString("connection_message"),
                    instant(rs.getTimestamp("connection_checked_at")), pinned, seen, rs.getString("os_name"),
                    (Boolean) rs.getObject("privileged"), rs.getString("health_status"),
                    instant(rs.getTimestamp("health_checked_at")),
                    domainId == null ? null : rs.getString("helo_host"),
                    domainId == null ? null : rs.getString("mail_from"), instant(rs.getTimestamp("created_at")),
                    instant(rs.getTimestamp("updated_at")));
            return new Server(rs.getLong("id"), (Long) rs.getObject("domain_id"), rs.getString("host_key"),
                    rs.getString("seen_key"), rs.getString("os_id"), rs.getString("os_version"), item);
        };
    }

    // ---- read --------------------------------------------------------------------

    @Transactional(readOnly = true)
    public PageResponse<ServerItem> list(Filter filter, Pageable pageable) {
        List<Object> args = new ArrayList<>();
        String where = where(filter, args);
        Long total = jdbc.queryForObject("select count(*) from servers s" + where, Long.class, args.toArray());
        StringBuilder order = new StringBuilder(" order by ");
        for (Sort.Order o : pageable.getSort()) {
            order.append(SORT_COLUMNS.get(o.getProperty())).append(o.isAscending() ? " asc" : " desc")
                    .append(" nulls last, ");
        }
        order.append("lower(s.name) asc, s.id asc");
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<ServerItem> items = jdbc.query(SELECT + where + order + " limit ? offset ?", row(), args.toArray())
                .stream().map(Server::item).toList();
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    private String where(Filter f, List<Object> args) {
        List<String> parts = new ArrayList<>();
        if (f.q() != null && !f.q().isBlank()) {
            parts.add("(lower(s.name) like ? escape '\\' or s.ip like ? escape '\\')");
            String like = "%" + f.q().trim().toLowerCase().replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%";
            args.add(like);
            args.add(like);
        }
        if (f.connection() != null) {
            parts.add("s.connection_status = ?");
            args.add(f.connection().name());
        }
        if (f.expiry() != null) {
            LocalDate today = today();
            switch (f.expiry()) {
                case EXPIRED -> {
                    parts.add("s.expires_on < ?");
                    args.add(Date.valueOf(today));
                }
                case DAYS_14, DAYS_30 -> {
                    parts.add("s.expires_on >= ? and s.expires_on <= ?");
                    args.add(Date.valueOf(today));
                    args.add(Date.valueOf(today.plusDays(f.expiry() == Expiry.DAYS_14 ? 14 : 30)));
                }
            }
        }
        if (f.health() != null) {
            if (f.health() == HealthFilter.UNCHECKED) {
                parts.add("s.health_status is null");
            } else {
                parts.add("s.health_status = ?");
                args.add(f.health().name());
            }
        }
        return parts.isEmpty() ? "" : " where " + String.join(" and ", parts);
    }

    @Transactional(readOnly = true)
    public Server find(UUID publicId) {
        List<Server> found = jdbc.query(SELECT + " where s.public_id = ?", row(), publicId);
        if (found.isEmpty()) {
            throw new NotFoundException("This server is not in MasterDB.");
        }
        return found.getFirst();
    }

    @Transactional(readOnly = true)
    public List<Server> all() {
        return jdbc.query(SELECT + " order by lower(s.name), s.id", row());
    }

    // ---- write -------------------------------------------------------------------

    @Transactional
    public ServerItem create(AuthPrincipal caller, Input input) {
        Valid v = validate(input);
        Timestamp now = Timestamp.from(clock.instant());
        UUID id = UUID.randomUUID();
        try {
            jdbc.update("insert into servers (public_id, name, ip, ssh_port, ssh_user, expires_on, notes, domain_id, "
                            + "helo_host, mail_from, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    id, v.name, v.ip, v.port, v.user, Date.valueOf(v.expiresOn), v.notes, v.domainId,
                    defaultHelo(v.domainName), defaultMailFrom(v.domainName), now, now);
        } catch (DuplicateKeyException e) {
            throw duplicate(e, v);
        }
        Server s = find(id);
        activity.record(ActivityAction.SERVER_ADDED, Party.of(caller), party(s), details(s));
        log.info("server added: {} {}:{} by {}", id, v.ip, v.port, caller.userPublicId());
        return s.item();
    }

    @Transactional
    public ServerItem update(AuthPrincipal caller, UUID publicId, Input input) {
        Server before = find(publicId);
        Valid v = validate(input);
        boolean addressChanged = !before.item().ip().equals(v.ip) || before.item().sshPort() != v.port;
        boolean userChanged = !before.item().sshUser().equals(v.user);
        Timestamp now = Timestamp.from(clock.instant());
        try {
            // A new domain: the identity starts again from its defaults (same statement: the check constraint).
            boolean newDomain = v.domainId != null && !java.util.Objects.equals(before.domainId(), v.domainId);
            jdbc.update("update servers set name = ?, ip = ?, ssh_port = ?, ssh_user = ?, expires_on = ?, notes = ?, "
                            + "domain_id = ?, helo_host = case when ? then ? else helo_host end, mail_from = case "
                            + "when ? then ? else mail_from end, updated_at = ? where id = ?", v.name, v.ip, v.port,
                    v.user, Date.valueOf(v.expiresOn), v.notes, v.domainId, newDomain, defaultHelo(v.domainName),
                    newDomain, defaultMailFrom(v.domainName), now, before.id());
        } catch (DuplicateKeyException e) {
            throw duplicate(e, v);
        }
        if (addressChanged) {
            // Another address may be another machine: its key must be checked from scratch.
            jdbc.update("update servers set host_key_type = null, host_key_fingerprint = null, host_key = null, "
                    + "host_key_pinned_at = null, seen_key_type = null, seen_key_fingerprint = null, seen_key = null, "
                    + "seen_key_at = null, connection_status = 'NEW', connection_message = ?, os_id = null, "
                    + "os_version = null, os_name = null, privileged = null where id = ?",
                    "The address changed: connect again to check the new host key.", before.id());
        } else if (userChanged && before.item().connectionStatus() != ConnectionStatus.KEY_CHANGED) {
            jdbc.update("update servers set connection_status = case when host_key is null then 'NEW' "
                    + "else 'CONNECTED' end, connection_message = ?, privileged = null where id = ?",
                    "The login user changed: connect again to test it.", before.id());
        }
        Server s = find(publicId);
        Map<String, Object> details = details(s);
        details.put("addressChanged", addressChanged);
        activity.record(ActivityAction.SERVER_UPDATED, Party.of(caller), party(s), details);
        return s.item();
    }

    @Transactional
    public void delete(AuthPrincipal caller, UUID publicId) {
        Server s = find(publicId);
        Integer running = jdbc.queryForObject("select count(*) from mta_installs where server_id = ? and status in "
                + "('QUEUED', 'RUNNING')", Integer.class, s.id());
        if (running != null && running > 0) {
            throw new ConflictException("An MTA install is running on this server. Wait for it to finish.");
        }
        jdbc.update("delete from servers where id = ?", s.id());
        activity.record(ActivityAction.SERVER_DELETED, Party.of(caller), party(s),
                Map.of("ip", s.item().ip()));
        log.info("server deleted: {} by {}", s.item().publicId(), caller.userPublicId());
    }

    // ---- probe identity (job 3) ----------------------------------------------------

    static final Pattern HOST = Pattern.compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9-]{2,63}");
    static final Pattern LOCAL = Pattern.compile("[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?");

    /**
     * HELO host and MAIL FROM that Validation will use from this server. Both
     * must be on the linked domain (the domain itself or a subdomain), so the
     * PTR, the greeting and the sender all match.
     */
    @Transactional
    public ServerItem identity(AuthPrincipal caller, UUID publicId, String heloHost, String mailFrom) {
        Server s = find(publicId);
        if (s.item().domain() == null) {
            throw new ServerNotReadyException("Link a domain to this server first: the HELO host and sender must "
                    + "be on it.");
        }
        String domain = s.item().domain().name();
        String helo = heloHost == null ? "" : heloHost.trim().toLowerCase(java.util.Locale.ROOT);
        String from = mailFrom == null ? "" : mailFrom.trim().toLowerCase(java.util.Locale.ROOT);
        List<FieldViolation> errors = new ArrayList<>();
        if (helo.length() > 253 || !HOST.matcher(helo).matches() || !onDomain(helo, domain)) {
            errors.add(new FieldViolation("heloHost", "must be " + domain + " or a host under it, like mail."
                    + domain));
        }
        int at = from.lastIndexOf('@');
        if (at < 1 || from.length() > 254 || !LOCAL.matcher(from.substring(0, at)).matches()
                || !HOST.matcher(from.substring(at + 1)).matches() || !onDomain(from.substring(at + 1), domain)) {
            errors.add(new FieldViolation("mailFrom", "must be an address at " + domain + " (or a subdomain), like "
                    + "postmaster@" + domain));
        }
        if (!errors.isEmpty()) {
            throw BadRequestException.validation(errors);
        }
        jdbc.update("update servers set helo_host = ?, mail_from = ?, updated_at = ? where id = ?", helo, from,
                Timestamp.from(clock.instant()), s.id());
        activity.record(ActivityAction.SERVER_IDENTITY_CHANGED, Party.of(caller), party(s),
                Map.of("heloHost", helo, "mailFrom", from, "domain", domain));
        return find(publicId).item();
    }

    static boolean onDomain(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    static String defaultHelo(String domain) {
        return domain == null ? null : "mail." + domain;
    }

    static String defaultMailFrom(String domain) {
        return domain == null ? null : "postmaster@" + domain;
    }

    // ---- connect and host keys -----------------------------------------------------

    /**
     * Looks at the host key. No key trusted yet: it is kept for the user to
     * check (KEY_PENDING). The trusted one: logs in to test MasterDB's key.
     * Another one: the server is blocked (KEY_CHANGED). SSH calls run outside
     * any transaction.
     */
    public ConnectResult connect(AuthPrincipal caller, UUID publicId) {
        Server s = find(publicId);
        PresentedKey key;
        try {
            key = ssh.probe(s);
        } catch (SshFailure f) {
            return saveOutcome(caller, s, ConnectionStatus.UNREACHABLE, f.getMessage(), null);
        }
        if (s.pinnedKey() == null) {
            Timestamp now = Timestamp.from(clock.instant());
            tx.executeWithoutResult(t -> jdbc.update("update servers set seen_key_type = ?, seen_key_fingerprint = ?, "
                            + "seen_key = ?, seen_key_at = ?, connection_status = 'KEY_PENDING', connection_message = ?, "
                            + "connection_checked_at = ?, updated_at = ? where id = ?", key.type(), key.fingerprint(),
                    key.publicKey(), now, "Check the host key fingerprint and trust it to continue.", now, now,
                    s.id()));
            return new ConnectResult("KEY_PENDING", "The server answered. Check its host key fingerprint, then "
                    + "trust it.", find(publicId).item());
        }
        if (!SshKeys.same(SshKeys.parse(key.publicKey()), s.pinnedKey())) {
            ssh.markChanged(s, key);
            return new ConnectResult("KEY_CHANGED", ServerSsh.KEY_CHANGED_MESSAGE, find(publicId).item());
        }
        return login(caller, find(publicId));
    }

    /**
     * First use: trusts the key the server showed, then tests the login. The
     * fingerprint must be the one shown. With {@code password}, MasterDB first
     * logs in once with it to add its own key (see {@link #installKey}).
     */
    public ConnectResult trust(AuthPrincipal caller, UUID publicId, String fingerprint, String password) {
        Server s = find(publicId);
        if (s.pinnedKey() != null) {
            throw new ConflictException("This server already has a trusted host key. A changed key can only be "
                    + "accepted by the Owner.");
        }
        pin(caller, s, fingerprint, ActivityAction.SERVER_HOST_KEY_TRUSTED);
        if (password != null && !password.isEmpty()) {
            return installKey(caller, publicId, password);
        }
        return login(caller, find(publicId));
    }

    public ConnectResult trust(AuthPrincipal caller, UUID publicId, String fingerprint) {
        return trust(caller, publicId, fingerprint, null);
    }

    /**
     * Puts MasterDB's public key on the server using the login user's
     * password, once, like the old app's password login: only after the host
     * key is trusted, so the password can only reach that exact server. The
     * password is used for this one login and is never stored or logged.
     * Then the normal key login is tested.
     */
    public ConnectResult installKey(AuthPrincipal caller, UUID publicId, String password) {
        if (password == null || password.isEmpty() || password.length() > 1024) {
            throw BadRequestException.validation("password", "is required");
        }
        Server s = find(publicId);
        if (s.pinnedKey() == null) {
            throw new ServerNotReadyException("Press Connect and trust the host key first, so the password can only "
                    + "go to this server.");
        }
        String command = identity.installCommand() + " && (command -v restorecon >/dev/null 2>&1 && restorecon -R "
                + "~/.ssh || true) && echo MASTERDB_KEY_ADDED";
        try {
            Result r = ssh.runWithPassword(s, password, command, Duration.ofSeconds(30));
            if (r.exitCode() != 0 || !r.output().contains("MASTERDB_KEY_ADDED")) {
                return saveOutcome(caller, s, ConnectionStatus.AUTH_FAILED, "Logged in with the password, but "
                        + "adding the key failed (exit " + r.exitCode() + "). Add it with the command instead.", null);
            }
        } catch (SshFailure f) {
            if (f.kind() == SshFailure.Kind.HOST_KEY_CHANGED) {
                return new ConnectResult("KEY_CHANGED", f.getMessage(), find(publicId).item());
            }
            ConnectionStatus status = f.kind() == SshFailure.Kind.AUTH_REFUSED ? ConnectionStatus.AUTH_FAILED
                    : ConnectionStatus.UNREACHABLE;
            return saveOutcome(caller, s, status, f.getMessage(), null);
        }
        tx.executeWithoutResult(t -> activity.record(ActivityAction.SERVER_KEY_INSTALLED, Party.of(caller), party(s),
                Map.of("user", s.item().sshUser(), "method", "password, used once")));
        log.info("ssh key added to server {} with a one-time password login by {}", s.item().publicId(),
                caller.userPublicId());
        return login(caller, find(publicId));
    }

    /** Owner only: the server's key changed on purpose (reinstall); trust the new one. */
    public ConnectResult replaceKey(AuthPrincipal caller, UUID publicId, String fingerprint) {
        if (!caller.owner()) {
            throw new ForbiddenException("Only the Owner can accept a changed host key.");
        }
        Server s = find(publicId);
        if (s.item().connectionStatus() != ConnectionStatus.KEY_CHANGED) {
            throw new ConflictException("This server's host key has not changed.");
        }
        pin(caller, s, fingerprint, ActivityAction.SERVER_HOST_KEY_REPLACED);
        return login(caller, find(publicId));
    }

    private void pin(AuthPrincipal caller, Server s, String fingerprint, ActivityAction action) {
        KeyView seen = s.item().presentedKey();
        if (seen == null || s.seenKey() == null) {
            throw new ConflictException("No host key to trust yet: press Connect first.");
        }
        if (fingerprint == null || !fingerprint.equals(seen.fingerprint())) {
            throw new ConflictException("The fingerprint doesn't match the key the server showed. Press Connect "
                    + "again and check it.");
        }
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> {
            int rows = jdbc.update("update servers set host_key_type = seen_key_type, host_key_fingerprint = "
                    + "seen_key_fingerprint, host_key = seen_key, host_key_pinned_at = ?, seen_key_type = null, "
                    + "seen_key_fingerprint = null, seen_key = null, seen_key_at = null, connection_status = "
                    + "'CONNECTED', connection_message = null, updated_at = ? where id = ? and seen_key_fingerprint = ?",
                    now, now, s.id(), fingerprint);
            if (rows != 1) {
                throw new ConflictException("The server's key changed meanwhile. Press Connect again.");
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("fingerprint", fingerprint);
            details.put("type", seen.type());
            if (s.item().hostKey() != null) {
                details.put("previous", s.item().hostKey().fingerprint());
            }
            activity.record(action, Party.of(caller), party(s), details);
        });
        log.info("server {} host key {} {} by {}", s.item().publicId(), fingerprint,
                action == ActivityAction.SERVER_HOST_KEY_REPLACED ? "replaced" : "trusted", caller.userPublicId());
    }

    /** Logs in with MasterDB's key and reads the OS; root or passwordless sudo is noted. */
    private ConnectResult login(AuthPrincipal caller, Server s) {
        Result r;
        try {
            r = ssh.run(s, LOGIN_TEST, null, LOGIN_TEST_TIMEOUT, null);
        } catch (SshFailure f) {
            if (f.kind() == SshFailure.Kind.HOST_KEY_CHANGED) {
                return new ConnectResult("KEY_CHANGED", f.getMessage(), find(s.item().publicId()).item());
            }
            ConnectionStatus status = f.kind() == SshFailure.Kind.AUTH_REFUSED ? ConnectionStatus.AUTH_FAILED
                    : ConnectionStatus.UNREACHABLE;
            return saveOutcome(caller, s, status, f.getMessage(), null);
        }
        Os os = Os.parse(r.output());
        String message = os.privileged() ? null : "Logged in, but user " + s.item().sshUser()
                + " is not root and has no passwordless sudo: the MTA can't be installed or controlled.";
        return saveOutcome(caller, s, ConnectionStatus.CONNECTED, message, os);
    }

    static final String LOGIN_TEST = "echo MASTERDB_LOGIN_TEST; grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' "
            + "/etc/os-release 2>/dev/null; echo \"MASTERDB_UID=$(id -u)\"; if [ \"$(id -u)\" != 0 ]; then "
            + "if sudo -n true 2>/dev/null; then echo MASTERDB_SUDO=yes; else echo MASTERDB_SUDO=no; fi; fi";

    /** What /etc/os-release and id said. */
    record Os(String id, String version, String name, boolean privileged) {
        static Os parse(String output) {
            String id = null;
            String version = null;
            String name = null;
            boolean root = false;
            boolean sudo = false;
            for (String line : output.split("\\R")) {
                String l = line.trim();
                if (l.startsWith("ID=")) {
                    id = unquote(l.substring(3));
                } else if (l.startsWith("VERSION_ID=")) {
                    version = unquote(l.substring(11));
                } else if (l.startsWith("PRETTY_NAME=")) {
                    name = unquote(l.substring(12));
                } else if (l.equals("MASTERDB_UID=0")) {
                    root = true;
                } else if (l.equals("MASTERDB_SUDO=yes")) {
                    sudo = true;
                }
            }
            return new Os(cut(id, 40), cut(version, 40), cut(name, 100), root || sudo);
        }

        private static String unquote(String v) {
            String s = v.trim();
            return s.length() >= 2 && (s.startsWith("\"") || s.startsWith("'")) ? s.substring(1, s.length() - 1) : s;
        }
    }

    private ConnectResult saveOutcome(AuthPrincipal caller, Server s, ConnectionStatus status, String message, Os os) {
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> {
            if (os != null) {
                jdbc.update("update servers set connection_status = ?, connection_message = ?, connection_checked_at "
                                + "= ?, os_id = ?, os_version = ?, os_name = ?, privileged = ?, updated_at = ? where id = ?",
                        status.name(), cut(message, 500), now, os.id(), os.version(), os.name(), os.privileged(), now,
                        s.id());
            } else {
                // Keep a block: an unreachable server with a changed key stays blocked.
                jdbc.update("update servers set connection_status = case when connection_status = 'KEY_CHANGED' "
                                + "then 'KEY_CHANGED' else ? end, connection_message = ?, connection_checked_at = ?, "
                                + "updated_at = ? where id = ?", status.name(), cut(message, 500), now, now, s.id());
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("status", status.name());
            if (os != null && os.name() != null) {
                details.put("os", os.name());
            }
            activity.record(ActivityAction.SERVER_CONNECTED, Party.of(caller), party(s), details);
        });
        String text = status == ConnectionStatus.CONNECTED
                ? (message == null ? "Connected: MasterDB's key logs in." : message)
                : message;
        return new ConnectResult(status.name(), text, find(s.item().publicId()).item());
    }

    // ---- helpers -------------------------------------------------------------------

    private record Valid(String name, String ip, int port, String user, LocalDate expiresOn, String notes,
            Long domainId, String domainName) {
    }

    private Valid validate(Input in) {
        List<FieldViolation> errors = new ArrayList<>();
        String name = blankToNull(in.name());
        if (name == null || name.length() > 100) {
            errors.add(new FieldViolation("name", "must be 1 to 100 characters"));
        }
        String ip = blankToNull(in.ip());
        if (!Ipv4.valid(ip)) {
            errors.add(new FieldViolation("ip", "must be an IPv4 address like 203.0.113.10"));
        } else if (!allowPrivateIps && !Ipv4.isPublic(ip)) {
            errors.add(new FieldViolation("ip", "must be the server's public IPv4 address (this one is private or "
                    + "reserved)"));
        }
        int port = in.sshPort() == null ? 22 : in.sshPort();
        if (port < 1 || port > 65535) {
            errors.add(new FieldViolation("sshPort", "must be 1 to 65535"));
        }
        String user = blankToNull(in.sshUser());
        user = user == null ? "root" : user;
        if (!USER.matcher(user).matches()) {
            errors.add(new FieldViolation("sshUser", "must be a Linux user name like root or deploy"));
        }
        if (in.expiresOn() == null) {
            errors.add(new FieldViolation("expiresOn", "is required (the date the VPS plan ends)"));
        }
        String notes = blankToNull(in.notes());
        if (notes != null && notes.length() > 2000) {
            errors.add(new FieldViolation("notes", "must be at most 2000 characters"));
        }
        Long domainId = null;
        String domainName = null;
        if (in.domainId() != null) {
            List<Map<String, Object>> found = jdbc.queryForList("select id, name from domains where public_id = ?",
                    in.domainId());
            if (found.isEmpty()) {
                errors.add(new FieldViolation("domainId", "is not a domain in MasterDB"));
            } else {
                domainId = ((Number) found.getFirst().get("id")).longValue();
                domainName = (String) found.getFirst().get("name");
            }
        }
        if (!errors.isEmpty()) {
            throw BadRequestException.validation(errors);
        }
        return new Valid(name, ip, port, user, in.expiresOn(), notes, domainId, domainName);
    }

    private static ConflictException duplicate(DuplicateKeyException e, Valid v) {
        String text = String.valueOf(e.getMostSpecificCause().getMessage());
        if (text.contains("uq_servers_domain")) {
            return new ConflictException(v.domainName + " is already linked to another server. A domain gives its "
                    + "mail IP to one server only.");
        }
        return new ConflictException("A server with IP " + v.ip + " and SSH port " + v.port
                + " is already in MasterDB.");
    }

    private static Map<String, Object> details(Server s) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("ip", s.item().ip());
        d.put("sshPort", s.item().sshPort());
        d.put("sshUser", s.item().sshUser());
        d.put("expiresOn", s.item().expiresOn().toString());
        d.put("domain", s.item().domain() == null ? "" : s.item().domain().name());
        if (s.item().heloHost() != null) {
            d.put("heloHost", s.item().heloHost());
            d.put("mailFrom", s.item().mailFrom());
        }
        return d;
    }

    public static Party party(Server s) {
        return new Party(s.item().publicId(), s.item().name());
    }

    LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    private static String cut(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
