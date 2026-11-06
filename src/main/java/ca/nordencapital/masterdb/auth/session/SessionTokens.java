package ca.nordencapital.masterdb.auth.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Random tokens (session cookie, login challenge, invite and reset links): 32 random bytes (256 bits) from {@link SecureRandom},
 * base64url without padding (43 characters).
 *
 * <p>Only {@link #hash} of it is stored. A plain SHA-256 is enough here, unlike
 * for passwords: the token is random and 256 bits long, so there is nothing to
 * guess or look up, and the hash must be fast because it runs on every request.
 */
public final class SessionTokens {

    static final int BYTES = 32;
    /** Exactly what {@link #generate} produces; anything else is rejected before the database. */
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private SessionTokens() {
    }

    public static String generate() {
        byte[] bytes = new byte[BYTES];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    public static boolean isWellFormed(String token) {
        return token != null && FORMAT.matcher(token).matches();
    }

    /** Lowercase hex SHA-256, the form stored in {@code user_sessions.token_hash}. */
    public static String hash(String token) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(sha256.digest(token.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
