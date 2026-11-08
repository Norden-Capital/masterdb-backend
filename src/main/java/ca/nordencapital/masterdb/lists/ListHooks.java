package ca.nordencapital.masterdb.lists;

import java.util.UUID;

/**
 * What other modules add to a list: the validation job running on it, a
 * reason it can't be deleted now, and clean-up once it is deleted. Every
 * method has a no-op default.
 */
public interface ListHooks {

    /** A validation job working on a list (or one part) right now. */
    record RunningJob(UUID publicId, String status, int total, int checked) {
    }

    /** {@code part} null = any job on the list, else only a job on that part. */
    default RunningJob runningJob(long listId, Integer part) {
        return null;
    }

    /** A sentence for the user when the list can't be deleted now; null = fine. */
    default String blocksDelete(ListRow list) {
        return null;
    }

    /** After the list was deleted (outside its transaction). */
    default void deleted(ListRow list) {
    }
}
