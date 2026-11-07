package ca.nordencapital.masterdb.servers;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.servers.ServerService.ConnectionStatus;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ssh.SshFailure;
import ca.nordencapital.masterdb.servers.ssh.SshRunner;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.LineSink;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.PresentedKey;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;

/**
 * Every SSH command to a saved server goes through here: only with a pinned
 * host key, never to a server that is blocked by a changed key, and a key
 * change seen on the way blocks the server at once (no prompt, no retry).
 */
@Component
public class ServerSsh {

    static final String KEY_CHANGED_MESSAGE = "The server presented a different SSH host key than the trusted one. "
            + "It is blocked: nothing is sent to it until the Owner accepts the new key.";
    private static final Logger log = LoggerFactory.getLogger(ServerSsh.class);

    private final SshRunner runner;
    private final JdbcTemplate jdbc;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate own;

    public ServerSsh(SshRunner runner, JdbcTemplate jdbc, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions) {
        this.runner = runner;
        this.jdbc = jdbc;
        this.activity = activity;
        this.clock = clock;
        this.own = new TransactionTemplate(transactions);
        own.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /** Runs a command as the login user. */
    public Result run(Server s, String command, byte[] stdin, Duration timeout, LineSink sink) {
        ready(s);
        try {
            return runner.exec(target(s), command, stdin, timeout, sink);
        } catch (SshFailure f) {
            if (f.kind() == SshFailure.Kind.HOST_KEY_CHANGED) {
                markChanged(s, f.presented());
            }
            throw f;
        }
    }

    /** Runs a root script: {@code bash -s}, through {@code sudo -n} when the login user isn't root. */
    public Result runScript(Server s, String script, Duration timeout, LineSink sink) {
        return run(s, rootShell(s), script.getBytes(StandardCharsets.UTF_8), timeout, sink);
    }

    static String rootShell(Server s) {
        return "root".equals(s.item().sshUser()) ? "bash -s" : "sudo -n bash -s";
    }

    PresentedKey probe(Server s) {
        return runner.probe(s.item().ip(), s.item().sshPort(), Duration.ofSeconds(10));
    }

    /** Only with a pinned key, and never while blocked. */
    static void ready(Server s) {
        if (s.pinnedKey() == null) {
            throw new ServerNotReadyException("Connect to " + s.item().name()
                    + " and trust its host key first (Server list → the server → Connect).");
        }
        if (s.item().connectionStatus() == ConnectionStatus.KEY_CHANGED) {
            throw new SshFailure(SshFailure.Kind.HOST_KEY_CHANGED, KEY_CHANGED_MESSAGE);
        }
    }

    private static SshRunner.Target target(Server s) {
        return new SshRunner.Target(s.item().ip(), s.item().sshPort(), s.item().sshUser(), s.pinnedKey());
    }

    /** In its own transaction: the block must stick even if the caller's work rolls back. */
    void markChanged(Server s, PresentedKey presented) {
        Timestamp now = Timestamp.from(clock.instant());
        own.executeWithoutResult(t -> {
            jdbc.update("update servers set connection_status = 'KEY_CHANGED', connection_message = ?, "
                            + "connection_checked_at = ?, seen_key_type = ?, seen_key_fingerprint = ?, seen_key = ?, "
                            + "seen_key_at = ?, updated_at = ? where id = ?", KEY_CHANGED_MESSAGE, now,
                    presented == null ? null : presented.type(), presented == null ? null : presented.fingerprint(),
                    presented == null ? null : presented.publicKey(), now, now, s.id());
            activity.record(ActivityAction.SERVER_HOST_KEY_CHANGED, Party.label("MasterDB"), ServerService.party(s),
                    Map.of("pinned", s.item().hostKey() == null ? "" : s.item().hostKey().fingerprint(),
                            "presented", presented == null ? "" : presented.fingerprint()));
        });
        log.warn("server {} ({}:{}) presented a different host key {}: blocked", s.item().publicId(),
                s.item().ip(), s.item().sshPort(), presented == null ? "?" : presented.fingerprint());
    }
}
