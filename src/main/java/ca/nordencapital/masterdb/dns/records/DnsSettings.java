package ca.nordencapital.masterdb.dns.records;

import java.time.Instant;
import java.util.UUID;

/**
 * What the managed records of a domain should say (V10 columns on domains).
 * Null = not set. Used to write records (job 3) and to check them (job 4).
 *
 * @param mailIp          IPv4 of the mail server: A @/mail/webmail and SPF; the linked server's IP when
 *                        a server is linked to the domain (Server management), else the one typed
 * @param dkimSelector    DKIM selector, "mail" by default (old app)
 * @param dkimPublicKey   bare base64 public key (pasted); no DKIM record written without one
 * @param dmarcPolicy     none, quarantine (default) or reject
 */
public record DnsSettings(String mailIp, String dkimSelector, String dkimPublicKey, String dmarcPolicy,
        String bimiLogoUrl, String bimiCertificateUrl, Instant updatedAt, MailServer mailServer) {

    /** Without a linked server. */
    public DnsSettings(String mailIp, String dkimSelector, String dkimPublicKey, String dmarcPolicy,
            String bimiLogoUrl, String bimiCertificateUrl, Instant updatedAt) {
        this(mailIp, dkimSelector, dkimPublicKey, dmarcPolicy, bimiLogoUrl, bimiCertificateUrl, updatedAt, null);
    }

    /** The server linked to the domain: {@code mailIp} is its IP and can't be typed. */
    public record MailServer(UUID publicId, String name, String ip) {
    }
}
