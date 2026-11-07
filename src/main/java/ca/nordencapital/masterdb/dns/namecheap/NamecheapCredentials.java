package ca.nordencapital.masterdb.dns.namecheap;

/**
 * What every Namecheap call needs. Lives only in memory, for one call; the
 * key is decrypted just before and never logged ({@link #toString()} hides it).
 */
public record NamecheapCredentials(String apiUser, String username, String apiKey) {

    @Override
    public String toString() {
        return "NamecheapCredentials[apiUser=" + apiUser + ", username=" + username + ", apiKey=(hidden)]";
    }
}
