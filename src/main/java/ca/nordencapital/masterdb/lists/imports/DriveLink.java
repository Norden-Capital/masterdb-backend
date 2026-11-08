package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.web.error.BadRequestException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A Google Drive link as the user pastes it, reduced to what the server will
 * fetch: only links on drive.google.com or docs.google.com, turned into the
 * file's direct download address (a Google Sheet as CSV, a Google Doc as
 * text). Nothing else is ever requested (SSRF guard, with {@link #allowedHop}
 * for every redirect).
 */
public record DriveLink(Kind kind, String id) {

    public enum Kind { FILE, SHEET, DOC }

    static final Set<String> LINK_HOSTS = Set.of("drive.google.com", "docs.google.com");
    /** Where Google sends downloads: the link hosts, the download host, and its file servers. */
    static final Set<String> DOWNLOAD_HOSTS = Set.of("drive.google.com", "docs.google.com",
            "drive.usercontent.google.com");
    private static final Pattern FILE_SERVER = Pattern.compile("[a-z0-9-]+\\.googleusercontent\\.com");
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_-]{10,200}");
    private static final Pattern PATH_ID = Pattern.compile("/(file|spreadsheets|document|presentation)/(?:u/\\d+/)?d/"
            + "([A-Za-z0-9_-]{10,200})");
    private static final Pattern QUERY_ID = Pattern.compile("(?:^|&)id=([A-Za-z0-9_-]{10,200})(?:&|$)");

    /** The link, or a 400 on the {@code driveUrl} field saying what is wrong with it. */
    public static DriveLink parse(String raw) {
        String text = raw == null ? "" : raw.trim();
        if (text.isEmpty()) {
            throw BadRequestException.validation("driveUrl", "paste the Google Drive link");
        }
        if (text.length() > 2000) {
            throw BadRequestException.validation("driveUrl", "is too long");
        }
        URI uri;
        try {
            uri = new URI(text);
        } catch (URISyntaxException e) {
            throw BadRequestException.validation("driveUrl", "is not a link");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw BadRequestException.validation("driveUrl", "must start with https://");
        }
        if (!LINK_HOSTS.contains(host) || uri.getPort() != -1 || uri.getUserInfo() != null) {
            throw BadRequestException.validation("driveUrl", "must be a Google Drive link (drive.google.com or "
                    + "docs.google.com)");
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        Matcher m = PATH_ID.matcher(path);
        if (m.find()) {
            return switch (m.group(1)) {
                case "spreadsheets" -> new DriveLink(Kind.SHEET, m.group(2));
                case "document" -> new DriveLink(Kind.DOC, m.group(2));
                case "presentation" -> throw BadRequestException.validation("driveUrl", "is a presentation: share the "
                        + "list as a .txt, .csv or Google Sheet");
                default -> new DriveLink(Kind.FILE, m.group(2));
            };
        }
        String query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
        Matcher q = QUERY_ID.matcher(query);
        if (host.equals("drive.google.com") && q.find()) {
            return new DriveLink(Kind.FILE, q.group(1));
        }
        if (path.startsWith("/drive/folders") || path.contains("/folders/")) {
            throw BadRequestException.validation("driveUrl", "is a folder: share the file itself");
        }
        throw BadRequestException.validation("driveUrl", "doesn't name a file; copy it from Share → Copy link");
    }

    /** The first address fetched. */
    public URI download() {
        if (!ID.matcher(id).matches()) {
            throw new IllegalStateException("bad id");
        }
        return URI.create(switch (kind) {
            case FILE -> "https://drive.google.com/uc?export=download&id=" + id;
            case SHEET -> "https://docs.google.com/spreadsheets/d/" + id + "/export?format=csv";
            case DOC -> "https://docs.google.com/document/d/" + id + "/export?format=txt";
        });
    }

    /** May the server go to this address (a redirect, or the "download anyway" form)? HTTPS to a Google host only. */
    public static boolean allowedHop(URI uri) {
        if (uri == null || uri.getHost() == null || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getUserInfo() != null || (uri.getPort() != -1 && uri.getPort() != 443)) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        return DOWNLOAD_HOSTS.contains(host) || FILE_SERVER.matcher(host).matches();
    }

    /** Google's sign-in: the file is not shared with "Anyone with the link". */
    static boolean isSignIn(URI uri) {
        return uri != null && uri.getHost() != null && (uri.getHost().equalsIgnoreCase("accounts.google.com")
                || (uri.getPath() != null && uri.getPath().contains("ServiceLogin")));
    }
}
