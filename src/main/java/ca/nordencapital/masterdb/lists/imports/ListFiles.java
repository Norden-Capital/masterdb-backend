package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Where uploaded list files wait for their import: one file per list in
 * {@code app.lists.upload-dir} (on the server a Docker volume, so a restart
 * keeps them). A file is deleted once its list is imported, fails, or is
 * deleted.
 */
@Component
public class ListFiles {

    private static final Logger log = LoggerFactory.getLogger(ListFiles.class);

    private final Path dir;
    private final long maxFileSize;
    private final long minFreeDisk;

    public ListFiles(@Value("${app.lists.upload-dir}") String dir,
            @Value("${app.lists.max-file-size:2GB}") DataSize maxFileSize,
            @Value("${app.lists.min-free-disk:2GB}") DataSize minFreeDisk) {
        this.dir = Path.of(dir).toAbsolutePath();
        this.maxFileSize = maxFileSize.toBytes();
        this.minFreeDisk = minFreeDisk.toBytes();
    }

    public long maxFileSize() {
        return maxFileSize;
    }

    /** The file of a list (named by its public id, never by anything the user typed). */
    public Path path(UUID list) {
        return dir.resolve(list + ".upload");
    }

    /** Creates the folder and an empty file; refuses when the disk would get too full. */
    public void create(UUID list, long expectedSize) {
        try {
            Files.createDirectories(dir);
            long free = Files.getFileStore(dir).getUsableSpace();
            if (free - Math.max(0, expectedSize) < minFreeDisk) {
                throw new ListException(HttpStatus.CONFLICT, ErrorCode.STORAGE_FULL,
                        "The server doesn't have enough free disk space for this file right now.");
            }
            Files.deleteIfExists(path(list));
            Files.createFile(path(list));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void delete(UUID list) {
        try {
            Files.deleteIfExists(path(list));
        } catch (IOException e) {
            log.warn("list file {} could not be deleted: {}", list, e.getMessage());
        }
    }
}
