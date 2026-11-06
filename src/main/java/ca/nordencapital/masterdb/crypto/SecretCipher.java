package ca.nordencapital.masterdb.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Encrypts small secrets at rest (2FA secrets) with AES-256-GCM, and derives
 * a keyed hash ("pepper") for one-time codes.
 *
 * <p><b>Key:</b> {@code ENCRYPTION_KEY}, 64 hex characters (32 bytes), a
 * GitHub secret written to the server's .env. Hex rather than base64 so the
 * value never contains {@code + / =} that a .env file could mangle.
 * <b>Fail closed</b> like PROXY_SECRET: without a valid key the application
 * refuses to start, unless {@code app.encryption.required=false} (only the
 * {@code local} profile and the tests); there, a missing key is replaced by a
 * random one for this run, so 2FA enrolments do not survive a restart.
 *
 * <p><b>Format:</b> {@code v1:} + base64(12-byte random IV + ciphertext + tag).
 * Each value is bound to its purpose and owner by the GCM associated data
 * (e.g. {@code totp:<user id>}), so a ciphertext copied to another row does
 * not decrypt. Never change the key once set: stored values become unreadable.
 * The key is never logged.
 */
@Component
public class SecretCipher {

    static final String PREFIX = "v1:";
    private static final Pattern HEX_KEY = Pattern.compile("[0-9a-fA-F]{64}");
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final Logger log = LoggerFactory.getLogger(SecretCipher.class);

    private final SecureRandom random = new SecureRandom();
    private final SecretKey key;
    private final byte[] pepper;

    public SecretCipher(@Value("${app.encryption.key:}") String hexKey,
            @Value("${app.encryption.required:true}") boolean required) {
        String value = hexKey == null ? "" : hexKey.trim();
        byte[] raw;
        if (value.isEmpty() && !required) {
            log.warn("ENCRYPTION_KEY is not set: using a random key for this run only (allowed only in local/test).");
            raw = new byte[32];
            random.nextBytes(raw);
        } else if (!HEX_KEY.matcher(value).matches()) {
            // Never echo the value: only say what is wrong.
            throw new IllegalStateException(value.isEmpty()
                    ? "ENCRYPTION_KEY is not set. The API refuses to start without it (see SecretCipher)."
                    : "ENCRYPTION_KEY must be exactly 64 hex characters (see SecretCipher).");
        } else {
            raw = HexFormat.of().parseHex(value);
        }
        this.key = new SecretKeySpec(raw, "AES");
        this.pepper = hmac(raw, "masterdb one-time code pepper v1".getBytes(StandardCharsets.UTF_8));
    }

    public String encrypt(byte[] plaintext, String context) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] sealed = cipher.doFinal(plaintext);
            return PREFIX + Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(iv.length + sealed.length).put(iv).put(sealed).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    /** Throws if the value was not made by {@link #encrypt} with this key and context. */
    public byte[] decrypt(String stored, String context) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not an encrypted value");
        }
        try {
            byte[] all = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, all, 0, IV_BYTES));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(all, IV_BYTES, all.length - IV_BYTES);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("decryption failed (wrong key or tampered value)", e);
        }
    }

    /**
     * Keyed SHA-256 (hex) for short one-time codes (recovery codes): a copy of
     * the database alone is not enough to brute-force them offline.
     */
    public String keyedHash(String value) {
        return HexFormat.of().formatHex(hmac(pepper, value.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }
}
