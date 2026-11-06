package ca.nordencapital.masterdb.auth.login;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Plain HTTP calls against the running test server, with the cookie handled by hand (it is Secure). */
final class AuthTestClient {

    static final String USER_AGENT = "AuthFlowTest/1.0";

    private static final Pattern SESSION = Pattern.compile("^md_session=([^;]*)");

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final int port;

    AuthTestClient(int port) {
        this.port = port;
    }

    HttpResponse<String> login(String email, String password, String... headers) throws Exception {
        String body = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        return send("POST", "/api/v1/auth/login", null, body, headers);
    }

    HttpResponse<String> me(String token) throws Exception {
        return send("GET", "/api/v1/auth/me", token, null);
    }

    HttpResponse<String> logout(String token) throws Exception {
        return send("POST", "/api/v1/auth/logout", token, null);
    }

    HttpResponse<String> send(String method, String path, String token, String body, String... headers)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("User-Agent", USER_AGENT)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (token != null) {
            request.header("Cookie", "md_session=" + token);
        }
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Every md_session Set-Cookie header of a response. */
    static List<String> sessionCookies(HttpResponse<?> response) {
        return response.headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("md_session=")).toList();
    }

    /** The token a response set, or null. */
    static String token(HttpResponse<?> response) {
        for (String cookie : sessionCookies(response)) {
            Matcher m = SESSION.matcher(cookie);
            if (m.find() && !m.group(1).isEmpty()) {
                return m.group(1);
            }
        }
        return null;
    }

    /** A body without the parts that differ on every call. */
    static String stable(String body) {
        return body.replaceAll("\"(timestamp|requestId)\":\"[^\"]*\"", "");
    }
}
