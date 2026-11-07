package ca.nordencapital.masterdb.dns.namecheap;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.FieldViolation;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The one Namecheap account (DNS job 1). The API key is encrypted with
 * {@link SecretCipher} and is <b>write-only</b>: it can be set, replaced or
 * removed, never read back through the API. It is decrypted only by
 * {@link #credentials()} for a Namecheap call.
 */
@Service
public class NamecheapAccountService {

    static final String KEY_CONTEXT = "namecheap:api-key";
    static final Pattern USER = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    static final Pattern KEY = Pattern.compile("[A-Za-z0-9]{16,128}");
    private static final Party TARGET = Party.label("Namecheap account");
    private static final Logger log = LoggerFactory.getLogger(NamecheapAccountService.class);

    private final JdbcTemplate jdbc;
    private final SecretCipher cipher;
    private final NamecheapClient client;
    private final ActivityLog activity;
    private final Clock clock;

    public NamecheapAccountService(JdbcTemplate jdbc, SecretCipher cipher, NamecheapClient client,
            ActivityLog activity, Clock clock) {
        this.jdbc = jdbc;
        this.cipher = cipher;
        this.client = client;
        this.activity = activity;
        this.clock = clock;
    }

    /** What the page shows. Never the key, not even part of it: only that one is set. */
    public record AccountView(boolean configured, String apiUser, String username, boolean apiKeySet,
            String clientIp, Instant createdAt, Instant updatedAt, LastTest lastTest) {
    }

    public record LastTest(Instant at, boolean ok, String message) {
    }

    /** Result of "Test connection": a result, not an error, so the page can show either. */
    public record TestResult(boolean ok, String code, String message, Integer domainCount) {
    }

    private record Row(String apiUser, String username, String keyEnc, Instant createdAt, Instant updatedAt,
            Instant lastTestAt, Boolean lastTestOk, String lastTestMessage) {
    }

    @Transactional(readOnly = true)
    public AccountView view() {
        Row row = row();
        if (row == null) {
            return new AccountView(false, null, null, false, client.clientIp(), null, null, null);
        }
        LastTest last = row.lastTestAt() == null ? null
                : new LastTest(row.lastTestAt(), Boolean.TRUE.equals(row.lastTestOk()), row.lastTestMessage());
        return new AccountView(true, row.apiUser(), row.username(), true, client.clientIp(), row.createdAt(),
                row.updatedAt(), last);
    }

    /**
     * Adds the account, or changes it. {@code apiKey} is required the first
     * time; later a blank key keeps the saved one. A blank username means the
     * API user (Namecheap's usual case, as in the old app).
     */
    @Transactional
    public AccountView save(AuthPrincipal caller, String apiUser, String username, String apiKey) {
        String user = apiUser == null ? "" : apiUser.trim();
        String name = username == null || username.isBlank() ? user : username.trim();
        String key = apiKey == null ? "" : apiKey.trim();
        Row existing = row();
        List<FieldViolation> errors = new ArrayList<>();
        if (!USER.matcher(user).matches()) {
            errors.add(new FieldViolation("apiUser", "must be 1 to 64 letters, digits, dots, dashes or underscores"));
        }
        if (!USER.matcher(name).matches()) {
            errors.add(new FieldViolation("username", "must be 1 to 64 letters, digits, dots, dashes or underscores"));
        }
        if (key.isEmpty() && existing == null) {
            errors.add(new FieldViolation("apiKey", "is required"));
        } else if (!key.isEmpty() && !KEY.matcher(key).matches()) {
            // Never echo the value.
            errors.add(new FieldViolation("apiKey", "must be 16 to 128 letters and digits (copy it from Namecheap)"));
        }
        if (!errors.isEmpty()) {
            throw BadRequestException.validation(errors);
        }
        Timestamp now = Timestamp.from(clock.instant());
        boolean keyReplaced = !key.isEmpty();
        if (existing == null) {
            jdbc.update("insert into namecheap_account (id, api_user, username, api_key_enc, created_at, updated_at) "
                    + "values (1, ?, ?, ?, ?, ?)", user, name, encrypt(key), now, now);
        } else if (keyReplaced) {
            // A new key makes the last test meaningless.
            jdbc.update("update namecheap_account set api_user = ?, username = ?, api_key_enc = ?, updated_at = ?, "
                    + "last_test_at = null, last_test_ok = null, last_test_message = null where id = 1",
                    user, name, encrypt(key), now);
        } else {
            jdbc.update("update namecheap_account set api_user = ?, username = ?, updated_at = ? where id = 1",
                    user, name, now);
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("apiUser", user);
        details.put("username", name);
        details.put("added", existing == null);
        details.put("keyReplaced", keyReplaced);
        activity.record(ActivityAction.NAMECHEAP_ACCOUNT_SAVED, Party.of(caller), TARGET, details);
        log.info("namecheap account {} (key {}) by {}", existing == null ? "added" : "changed",
                keyReplaced ? "set" : "kept", caller.userPublicId());
        return view();
    }

    @Transactional
    public void remove(AuthPrincipal caller) {
        if (jdbc.update("delete from namecheap_account where id = 1") == 0) {
            throw new NotFoundException("No Namecheap account is saved.");
        }
        activity.record(ActivityAction.NAMECHEAP_ACCOUNT_REMOVED, Party.of(caller), TARGET);
        log.info("namecheap account removed by {}", caller.userPublicId());
    }

    /** Calls namecheap.domains.getList (first page) and remembers the outcome. */
    public TestResult test(AuthPrincipal caller) {
        NamecheapCredentials credentials = credentials();
        TestResult result;
        try {
            NamecheapClient.DomainList list = client.firstPage(credentials);
            result = new TestResult(true, null, "Connected. Namecheap lists " + list.totalItems() + " domain"
                    + (list.totalItems() == 1 ? "" : "s") + " on this account.", list.totalItems());
        } catch (NamecheapException e) {
            result = new TestResult(false, e.getCode().name(), e.getMessage(), null);
        }
        recordTest(caller, result);
        return result;
    }

    private void recordTest(AuthPrincipal caller, TestResult result) {
        String message = result.message().length() > 300 ? result.message().substring(0, 300) : result.message();
        jdbc.update("update namecheap_account set last_test_at = ?, last_test_ok = ?, last_test_message = ? "
                + "where id = 1", Timestamp.from(clock.instant()), result.ok(), message);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("ok", result.ok());
        if (result.code() != null) {
            details.put("code", result.code());
        }
        activity.record(ActivityAction.NAMECHEAP_CONNECTION_TESTED, Party.of(caller), TARGET, details);
    }

    /** For a Namecheap call. 409 NAMECHEAP_NOT_CONFIGURED when no account is saved. */
    @Transactional(readOnly = true)
    public NamecheapCredentials credentials() {
        Row row = row();
        if (row == null) {
            throw NamecheapException.notConfigured();
        }
        String key = new String(cipher.decrypt(row.keyEnc(), KEY_CONTEXT), StandardCharsets.UTF_8);
        return new NamecheapCredentials(row.apiUser(), row.username(), key);
    }

    private String encrypt(String key) {
        return cipher.encrypt(key.getBytes(StandardCharsets.UTF_8), KEY_CONTEXT);
    }

    private Row row() {
        List<Row> rows = jdbc.query("select * from namecheap_account where id = 1", (rs, i) -> new Row(
                rs.getString("api_user"), rs.getString("username"), rs.getString("api_key_enc"),
                rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("updated_at").toInstant(),
                rs.getTimestamp("last_test_at") == null ? null : rs.getTimestamp("last_test_at").toInstant(),
                (Boolean) rs.getObject("last_test_ok"), rs.getString("last_test_message")));
        return rows.isEmpty() ? null : rows.getFirst();
    }
}
