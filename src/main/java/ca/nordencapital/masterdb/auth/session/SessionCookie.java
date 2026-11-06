package ca.nordencapital.masterdb.auth.session;

import ca.nordencapital.masterdb.auth.AuthProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * The session cookie {@value #NAME}: HttpOnly (scripts cannot read it),
 * Secure (HTTPS only; off only in the {@code local} profile), SameSite=Lax
 * (not sent on cross-site POSTs), Path=/, and <b>no Domain</b>, so the browser
 * keeps it for the exact host that set it: db.nordencapital.ca, through the
 * website's proxy. Max-Age is the session's absolute limit; the idle limit is
 * enforced by the server.
 */
@Component
public class SessionCookie {

    public static final String NAME = "md_session";
    /**
     * The 2FA step's cookie: the login challenge between password and code.
     * Only for the auth endpoints (Path=/api/v1/auth), SameSite=Strict, 10 min.
     */
    public static final String PREAUTH_NAME = "md_preauth";
    static final String PREAUTH_PATH = "/api/v1/auth";

    private final boolean secure;

    public SessionCookie(AuthProperties properties) {
        this.secure = properties.cookie().secure();
    }

    public ResponseCookie create(String token, Duration maxAge) {
        return base(token).maxAge(maxAge).build();
    }

    /** Tells the browser to delete the cookie. */
    public ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    public ResponseCookie createPreAuth(String token, Duration maxAge) {
        return preAuth(token).maxAge(maxAge).build();
    }

    public ResponseCookie clearPreAuth() {
        return preAuth("").maxAge(Duration.ZERO).build();
    }

    /** The session cookie's value from the request, or null. */
    public static String read(HttpServletRequest request) {
        return read(request, NAME);
    }

    /** The 2FA-step cookie's value, or null. */
    public static String readPreAuth(HttpServletRequest request) {
        return read(request, PREAUTH_NAME);
    }

    private static String read(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isEmpty()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private ResponseCookie.ResponseCookieBuilder preAuth(String value) {
        return ResponseCookie.from(PREAUTH_NAME, value).httpOnly(true).secure(secure).sameSite("Strict")
                .path(PREAUTH_PATH);
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(NAME, value).httpOnly(true).secure(secure).sameSite("Lax").path("/");
    }
}
