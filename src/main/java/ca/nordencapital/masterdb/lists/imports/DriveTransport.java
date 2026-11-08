package ca.nordencapital.masterdb.lists.imports;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * One HTTPS GET for the Drive download, without following redirects (the
 * downloader checks every hop itself). Tests replace it with one that talks to
 * a fake server on 127.0.0.1.
 */
public interface DriveTransport {

    record Response(int status, Map<String, List<String>> headers, InputStream body) implements Closeable {

        public String header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))
                        && !e.getValue().isEmpty()) {
                    return e.getValue().getFirst();
                }
            }
            return null;
        }

        @Override
        public void close() throws IOException {
            body.close();
        }
    }

    Response get(URI uri) throws IOException, InterruptedException;
}
