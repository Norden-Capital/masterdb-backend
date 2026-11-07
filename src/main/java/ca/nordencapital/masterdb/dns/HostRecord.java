package ca.nordencapital.masterdb.dns;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Locale;

/**
 * One host record as Namecheap's getHosts returns it and setHosts takes it.
 * {@code flag}/{@code tag} are only used by CAA records.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record HostRecord(String name, String type, String address, String mxPref, String ttl, String flag,
        String tag) {

    public static final String DEFAULT_TTL = "1800";

    public HostRecord {
        name = name == null ? "" : name.trim();
        type = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
        address = address == null ? "" : address;
        mxPref = mxPref == null ? "" : mxPref.trim();
        ttl = ttl == null || !ttl.trim().matches("[0-9]{1,6}") ? DEFAULT_TTL : ttl.trim();
        flag = flag == null ? "" : flag.trim();
        tag = tag == null ? "" : tag.trim();
    }

    public static HostRecord of(String name, String type, String address) {
        return new HostRecord(name, type, address, "", DEFAULT_TTL, "", "");
    }

    public static HostRecord mx(String name, String address, String pref) {
        return new HostRecord(name, "MX", address, pref, DEFAULT_TTL, "", "");
    }

    /**
     * Same record for DNS purposes (old app's {@code equivalent}): host and
     * type ignoring case, address ignoring case and a trailing dot (TXT
     * exact), MX preference too. TTL is not compared.
     */
    public boolean sameAs(HostRecord o) {
        if (!name.equalsIgnoreCase(o.name) || !type.equals(o.type)) {
            return false;
        }
        boolean addressSame = type.equals("TXT") ? address.trim().equals(o.address.trim())
                : stripDot(address).equalsIgnoreCase(stripDot(o.address));
        return addressSame && (!type.equals("MX") || prefOrDefault(mxPref).equals(prefOrDefault(o.mxPref)));
    }

    private static String stripDot(String v) {
        String t = v.trim();
        return t.endsWith(".") ? t.substring(0, t.length() - 1) : t;
    }

    private static String prefOrDefault(String p) {
        return p == null || p.isBlank() ? "10" : p;
    }
}
