package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.lists.ListRow;
import ca.nordencapital.masterdb.lists.imports.DriveTransport.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Downloads a list file from a Google Drive link shared as "Anyone with the
 * link", in the background, to the same place an upload goes. Every address
 * is checked before it is requested ({@link DriveLink#allowedHop}: HTTPS to a
 * Google download host only), redirects are followed by hand (at most 8),
 * Google's "can't scan this file for viruses" page is answered like the
 * "Download anyway" button, and the size is capped. Private links, missing
 * files and quota errors end in FAILED with a sentence for the user.
 */
@Component
public class DriveDownloader implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(DriveDownloader.class);
    static final int MAX_HOPS = 8;
    static final int MAX_PAGE = 2 * 1024 * 1024;
    static final long STALL_MS = 120_000;
    static final String PRIVATE = "This file isn't shared as \"Anyone with the link\". In Google Drive: Share → "
            + "General access → Anyone with the link, then add the list again.";

    private static final Pattern FORM = Pattern.compile("<form[^>]*id=\"download-form\"[^>]*>(.*?)</form>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern ACTION = Pattern.compile("action=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern INPUT = Pattern.compile("<input[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern NAME = Pattern.compile("name=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern VALUE = Pattern.compile("value=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONFIRM_LINK = Pattern.compile("href=\"(/uc\\?export=download[^\"]*confirm=[^\"]*)\"",
            Pattern.CASE_INSENSITIVE);

    private final JdbcTemplate jdbc;
    private final DriveTransport transport;
    private final ListFiles files;
    private final UploadFinish finish;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final ExecutorService pool = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "drive-download");
        t.setDaemon(true);
        return t;
    });
    private final Set<Long> cancelled = ConcurrentHashMap.newKeySet();
    private volatile boolean shuttingDown;

    public DriveDownloader(JdbcTemplate jdbc, DriveTransport transport, ListFiles files, UploadFinish finish,
            ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.transport = transport;
        this.files = files;
        this.finish = finish;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    /** A download that ends in FAILED with this sentence. */
    static final class DriveFailure extends Exception {
        DriveFailure(String message) {
            super(message, null, false, false);
        }
    }

    public void start(long listId, DriveLink link) {
        cancelled.remove(listId);
        pool.submit(() -> run(listId, link));
    }

    public void cancel(long listId) {
        cancelled.add(listId);
    }

    /** After a restart: downloads that were running start again from the beginning. */
    @EventListener(ApplicationReadyEvent.class)
    public void resumeAfterRestart() {
        List<ListRow> running = jdbc.query("select * from lists where status = 'DOWNLOADING' order by id",
                ListRow.MAPPER);
        for (ListRow l : running) {
            log.info("list {}: Drive download interrupted by a restart, starting it again", l.id());
            try {
                start(l.id(), DriveLink.parse(l.sourceName()));
            } catch (RuntimeException e) {
                fail(l.id(), "The Drive link can't be read any more. Add the list again.");
            }
        }
    }

    @Override
    public void destroy() {
        shuttingDown = true;
        pool.shutdownNow();
        try {
            pool.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean stopped(long id) {
        return shuttingDown || cancelled.contains(id) || Thread.currentThread().isInterrupted();
    }

    private void run(long id, DriveLink link) {
        try {
            download(id, link);
        } catch (DriveFailure e) {
            if (!stopped(id)) {
                fail(id, e.getMessage());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            if (!stopped(id)) {
                log.warn("list {}: Drive download failed: {}", id, e.toString());
                fail(id, "Google Drive could not be reached or stopped sending the file. Try again later.");
            }
        } finally {
            cancelled.remove(id);
        }
    }

    void download(long id, DriveLink link) throws Exception {
        List<ListRow> found = jdbc.query("select * from lists where id = ?", ListRow.MAPPER, id);
        if (found.isEmpty()) {
            return;
        }
        ListRow l = found.getFirst();
        jdbc.update("update lists set received = 0, file_size = null where id = ?", id);
        Path path = files.path(l.publicId());
        URI uri = link.download();
        for (int hop = 0; ; hop++) {
            if (stopped(id)) {
                return;
            }
            if (hop >= MAX_HOPS) {
                throw new DriveFailure("Google Drive sent too many redirects for this link.");
            }
            if (!DriveLink.allowedHop(uri)) {
                throw new DriveFailure("Google Drive tried to send the download to " + host(uri)
                        + ", which MasterDB doesn't download from.");
            }
            try (Response r = transport.get(uri)) {
                int status = r.status();
                if (status >= 300 && status < 400 && status != 304) {
                    String location = r.header("Location");
                    if (location == null) {
                        throw new DriveFailure("Google Drive answered with a redirect to nowhere.");
                    }
                    URI next;
                    try {
                        next = uri.resolve(new URI(location.trim()));
                    } catch (URISyntaxException e) {
                        throw new DriveFailure("Google Drive answered with a redirect MasterDB can't read.");
                    }
                    if (DriveLink.isSignIn(next)) {
                        throw new DriveFailure(PRIVATE);
                    }
                    uri = next;
                    continue;
                }
                if (status == 401 || status == 403) {
                    throw new DriveFailure(PRIVATE);
                }
                if (status == 404) {
                    throw new DriveFailure("Google Drive says this file doesn't exist. Check the link.");
                }
                if (status == 429) {
                    throw new DriveFailure("Google Drive refuses more downloads of this file for now (its download "
                            + "quota). Try again later, or upload the file from the PC.");
                }
                if (status != 200) {
                    throw new DriveFailure("Google Drive answered " + status + " for this file.");
                }
                String type = r.header("Content-Type");
                if (type != null && type.toLowerCase(Locale.ROOT).startsWith("text/html")) {
                    String html = new String(r.body().readNBytes(MAX_PAGE), StandardCharsets.UTF_8);
                    URI confirm = confirmForm(uri, html);
                    if (confirm != null) {
                        uri = confirm;
                        continue;
                    }
                    if (html.contains("accounts.google.com") || html.contains("ServiceLogin")) {
                        throw new DriveFailure(PRIVATE);
                    }
                    if (html.contains("Too many users have viewed or downloaded")) {
                        throw new DriveFailure("Google Drive refuses more downloads of this file for now (its "
                                + "download quota). Try again later, or upload the file from the PC.");
                    }
                    throw new DriveFailure("Google Drive sent a web page instead of the file. Check that the link is "
                            + "shared as \"Anyone with the link\" and points to a .txt or .csv file or a Google "
                            + "Sheet.");
                }
                save(l, path, r);
                return;
            }
        }
    }

    private void save(ListRow l, Path path, Response r) throws Exception {
        long max = files.maxFileSize();
        Long length = parseLength(r.header("Content-Length"));
        if (length != null && length > max) {
            throw new DriveFailure("This file is " + size(length) + "; MasterDB takes at most " + size(max)
                    + " in one list.");
        }
        jdbc.update("update lists set file_size = ? where id = ?", length, l.id());
        long count = 0;
        long lastSaved = System.nanoTime();
        long[] lastByte = {System.currentTimeMillis()};
        InputStream body = r.body();
        Thread watchdog = Thread.ofVirtual().unstarted(() -> {
            // A connection that stops sending is closed, so the read below ends.
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    return;
                }
                if (System.currentTimeMillis() - lastByte[0] > STALL_MS || stopped(l.id())) {
                    try {
                        body.close();
                    } catch (IOException ignored) {
                        // closing is all we want
                    }
                    return;
                }
            }
        });
        watchdog.start();
        try (OutputStream out = Files.newOutputStream(path, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = body.read(buf)) > 0) {
                lastByte[0] = System.currentTimeMillis();
                count += n;
                if (count > max) {
                    throw new DriveFailure("This file is over " + size(max) + ", the most MasterDB takes in one "
                            + "list.");
                }
                out.write(buf, 0, n);
                if (System.nanoTime() - lastSaved > 500_000_000L) {
                    lastSaved = System.nanoTime();
                    if (stopped(l.id())) {
                        return;
                    }
                    jdbc.update("update lists set received = ? where id = ?", count, l.id());
                }
            }
        } finally {
            watchdog.interrupt();
        }
        if (stopped(l.id())) {
            return;
        }
        if (length != null && count != length) {
            throw new DriveFailure("The download from Google Drive stopped before the end. Try again.");
        }
        if (count == 0) {
            throw new DriveFailure("The file on Google Drive is empty.");
        }
        finish.uploaded(null, l, count);
    }

    /** Google's "Download anyway" form (or the older confirm link) as the address to fetch next. */
    static URI confirmForm(URI base, String html) {
        Matcher form = FORM.matcher(html);
        if (form.find()) {
            Matcher action = ACTION.matcher(html.substring(form.start(), form.end()));
            if (!action.find()) {
                return null;
            }
            List<String> params = new ArrayList<>();
            Matcher input = INPUT.matcher(form.group(1));
            while (input.find()) {
                String tag = input.group();
                Matcher name = NAME.matcher(tag);
                Matcher value = VALUE.matcher(tag);
                if (name.find() && !tag.toLowerCase(Locale.ROOT).contains("type=\"submit\"")) {
                    params.add(enc(unescape(name.group(1))) + "=" + enc(value.find() ? unescape(value.group(1)) : ""));
                }
            }
            try {
                URI target = base.resolve(new URI(unescape(action.group(1))));
                String query = String.join("&", params);
                return new URI(target.getScheme() + "://" + target.getRawAuthority()
                        + (target.getRawPath() == null ? "" : target.getRawPath()) + (query.isEmpty() ? "" : "?" + query));
            } catch (URISyntaxException e) {
                return null;
            }
        }
        Matcher link = CONFIRM_LINK.matcher(html);
        if (link.find()) {
            try {
                return base.resolve(new URI(unescape(link.group(1))));
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return null;
    }

    private void fail(long id, String message) {
        List<ListRow> found = jdbc.query("select * from lists where id = ?", ListRow.MAPPER, id);
        if (found.isEmpty()) {
            return;
        }
        ListRow l = found.getFirst();
        tx.executeWithoutResult(s -> {
            int n = jdbc.update("update lists set status = 'FAILED', message = ?, updated_at = ? where id = ? and "
                    + "status = 'DOWNLOADING'", message, Timestamp.from(clock.instant()), id);
            if (n == 1) {
                activity.record(ActivityAction.LIST_IMPORT_FAILED, Party.label("MasterDB"), Party.label(l.name()),
                        Map.of("list", l.publicId().toString(), "reason", message.length() > 300
                                ? message.substring(0, 300) : message));
            }
        });
        files.delete(l.publicId());
    }

    private static Long parseLength(String v) {
        try {
            return v == null ? null : Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String host(URI uri) {
        return uri == null || uri.getHost() == null ? "another address" : uri.getHost();
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String unescape(String v) {
        return v.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<")
                .replace("&gt;", ">");
    }

    /** "2 GB", "350 MB", "12 KB". */
    public static String size(long bytes) {
        if (bytes >= 1L << 30) {
            return (bytes % (1L << 30) == 0 ? String.valueOf(bytes >> 30) : String.format(Locale.ROOT, "%.1f",
                    bytes / (double) (1L << 30))) + " GB";
        }
        if (bytes >= 1L << 20) {
            return (bytes >> 20) + " MB";
        }
        return Math.max(1, bytes >> 10) + " KB";
    }
}
