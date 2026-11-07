package ca.nordencapital.masterdb.dns.health;

import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * <b>Hook for PTR (reverse DNS).</b> When servers are linked to domains
 * (Server management), each validation server's IP must resolve back to its
 * domain's mail host (HELO / MAIL FROM, spec addition 3). That module
 * replaces this bean (or adds the lookup here) to return, for a domain, the
 * linked server's IP and the host name its PTR must show. Until then nothing
 * is linked, so the PTR row says "not checked". The check itself is already
 * in {@link HealthChecks#ptr}.
 */
@Component
public class PtrExpectations {

    /** IP whose PTR must equal {@code host}. */
    public record Expected(String ip, String host) {
    }

    public Optional<Expected> forDomain(long domainId, String domainName) {
        return Optional.empty();
    }
}
