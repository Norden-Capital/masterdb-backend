package ca.nordencapital.masterdb.dns.health;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * PTR (reverse DNS) expectation of a domain: the server linked to it
 * (Server management) must resolve back to its HELO host (spec addition 3).
 * No linked server: the PTR row says "not checked".
 */
@Component
public class PtrExpectations {

    private final JdbcTemplate jdbc;

    @Autowired
    public PtrExpectations(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Without a database: nothing is ever linked (unit tests of the checks). */
    public PtrExpectations() {
        this(null);
    }

    /** IP whose PTR must equal {@code host}. */
    public record Expected(String ip, String host) {
    }

    public Optional<Expected> forDomain(long domainId, String domainName) {
        if (jdbc == null) {
            return Optional.empty();
        }
        List<Expected> found = jdbc.query("select ip, coalesce(helo_host, 'mail.' || ?) from servers "
                + "where domain_id = ?", (rs, n) -> new Expected(rs.getString(1), rs.getString(2)), domainName, domainId);
        return found.stream().findFirst();
    }
}
