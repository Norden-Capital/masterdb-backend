package ca.nordencapital.masterdb.servers;

import java.util.regex.Pattern;

/** IPv4 addresses for servers: format, and whether one can be a VPS on the internet. */
public final class Ipv4 {

    private static final Pattern FORMAT = Pattern.compile(
            "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");

    private Ipv4() {
    }

    public static boolean valid(String ip) {
        return ip != null && FORMAT.matcher(ip).matches();
    }

    /** Not private, loopback, link-local, CGNAT, multicast, documentation or reserved space. */
    public static boolean isPublic(String ip) {
        if (!valid(ip)) {
            return false;
        }
        int[] o = octets(ip);
        return !(o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224
                || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113));
    }

    /** "1.2.3.4" → "4.3.2.1", for reverse and DNSBL lookups. */
    public static String reversed(String ip) {
        int[] o = octets(ip);
        return o[3] + "." + o[2] + "." + o[1] + "." + o[0];
    }

    private static int[] octets(String ip) {
        String[] p = ip.split("\\.");
        return new int[] {Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]),
                Integer.parseInt(p[3])};
    }
}
