package ca.nordencapital.masterdb.activity;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import ca.nordencapital.masterdb.web.security.ClientIp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Writes activity-log entries, in the caller's transaction (an action that
 * rolls back leaves no entry). Client address, user agent and request id are
 * taken from the current request. {@code details} must never hold a secret.
 */
@Component
public class ActivityLog {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final JdbcTemplate jdbc;
    private final ClientIp clientIp;
    private final Clock clock;

    public ActivityLog(JdbcTemplate jdbc, ClientIp clientIp, Clock clock) {
        this.jdbc = jdbc;
        this.clientIp = clientIp;
        this.clock = clock;
    }

    /** Someone, identified by public id and label (an email, or a masked one). */
    public record Party(UUID publicId, String label) {
        public static Party of(User user) {
            return user == null ? null : new Party(user.getPublicId(), user.getEmail());
        }

        public static Party of(AuthPrincipal principal) {
            return principal == null ? null : new Party(principal.userPublicId(), principal.email());
        }

        public static Party label(String label) {
            return new Party(null, label);
        }
    }

    public void record(ActivityAction action, Party actor, Party target) {
        record(action, actor, target, Map.of());
    }

    public void record(ActivityAction action, Party actor, Party target, Map<String, ?> details) {
        HttpServletRequest request = currentRequest();
        String ip = request == null ? null : cut(clientIp.resolve(request), 45);
        String agent = request == null ? null : cut(request.getHeader(HttpHeaders.USER_AGENT), 255);
        String requestId = request == null ? null : cut(RequestIdFilter.get(request), 64);
        String json = JSON.writeValueAsString(new TreeMap<>(details == null ? Map.of() : details));
        jdbc.update("insert into activity_log (occurred_at, action, actor_public_id, actor_label, target_public_id, "
                        + "target_label, ip, user_agent, request_id, details) values (?,?,?,?,?,?,?,?,?,?::jsonb)",
                Timestamp.from(clock.instant()), action.name(),
                actor == null ? null : actor.publicId(), actor == null ? null : cut(actor.label(), 254),
                target == null ? null : target.publicId(), target == null ? null : cut(target.label(), 254),
                ip, agent, requestId, json);
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest() : null;
    }

    private static String cut(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String v = value.strip();
        return v.length() <= max ? v : v.substring(0, max);
    }
}
