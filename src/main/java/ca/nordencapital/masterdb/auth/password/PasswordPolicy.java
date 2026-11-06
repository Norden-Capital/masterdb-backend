package ca.nordencapital.masterdb.auth.password;

import ca.nordencapital.masterdb.web.error.BadRequestException;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * What a new password must be (invite acceptance, change, reset): at least
 * {@value #MIN_LENGTH} characters, at most {@value PasswordConfig#MAX_BYTES}
 * bytes (BCrypt's limit), and not the email address. Length over complexity
 * rules: a password manager's or a passphrase's length is what makes it strong.
 * Breaks are answered 400 {@code VALIDATION_FAILED} on the field; the password
 * is never echoed.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;

    private PasswordPolicy() {
    }

    public static void check(String field, String password, String email) {
        if (password == null || password.codePointCount(0, password.length()) < MIN_LENGTH) {
            throw BadRequestException.validation(field, "must be at least " + MIN_LENGTH + " characters");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > PasswordConfig.MAX_BYTES) {
            throw BadRequestException.validation(field, "must be at most " + PasswordConfig.MAX_BYTES + " bytes");
        }
        if (password.isBlank()) {
            throw BadRequestException.validation(field, "must not be only spaces");
        }
        if (email != null && password.trim().toLowerCase(Locale.ROOT).equals(email.trim().toLowerCase(Locale.ROOT))) {
            throw BadRequestException.validation(field, "must not be your email address");
        }
    }
}
