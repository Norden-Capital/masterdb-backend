package ca.nordencapital.masterdb.validation;

import ca.nordencapital.masterdb.servers.ServerNotReadyException;
import ca.nordencapital.masterdb.servers.ServerService;
import ca.nordencapital.masterdb.servers.ServerService.ConnectionStatus;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.validation.engine.SmtpProber.Identity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Which servers can validate: connected over SSH with a trusted key, and
 * linked to a domain (that gives the greeting name and sender address).
 */
@Component
public class ValidationServers {

    private final ServerService servers;

    public ValidationServers(ServerService servers) {
        this.servers = servers;
    }

    /** A server as the validation pages see it. */
    public record Option(UUID publicId, String name, String ip, String domain, String heloHost, String mailFrom,
            String healthStatus, boolean ready, String reason) {
    }

    public List<Option> options() {
        return servers.all().stream().map(ValidationServers::option).toList();
    }

    /** The server, ready to validate; 409 SERVER_NOT_READY with the reason otherwise. */
    public Server ready(UUID publicId) {
        Server s = servers.find(publicId);
        String why = notReady(s);
        if (why != null) {
            throw new ServerNotReadyException(why);
        }
        return s;
    }

    public static Identity identity(Server s) {
        return new Identity(s.item().heloHost(), s.item().mailFrom());
    }

    static Option option(Server s) {
        String why = notReady(s);
        var i = s.item();
        return new Option(i.publicId(), i.name(), i.ip(), i.domain() == null ? null : i.domain().name(),
                i.heloHost(), i.mailFrom(), i.healthStatus(), why == null, why);
    }

    static String notReady(Server s) {
        var i = s.item();
        if (i.connectionStatus() == ConnectionStatus.KEY_CHANGED) {
            return i.name() + " is blocked: it presented a different SSH host key.";
        }
        if (i.connectionStatus() != ConnectionStatus.CONNECTED) {
            return i.name() + " is not connected yet (Server list → the server → Connect).";
        }
        if (i.domain() == null || i.heloHost() == null || i.mailFrom() == null) {
            return i.name() + " has no linked domain, so it has no greeting name and sender address.";
        }
        return null;
    }
}
