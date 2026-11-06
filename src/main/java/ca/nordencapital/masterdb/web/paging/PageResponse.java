package ca.nordencapital.masterdb.web.paging;

import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;

/**
 * One page of a list endpoint. Spring's {@code Page} is never returned as-is:
 * its JSON is a framework detail that has changed between versions.
 *
 * @param items      the rows of this page
 * @param page       zero-based page number
 * @param size       page size actually used (after clamping), not the row count of this page
 * @param totalItems all rows matching the filters
 * @param totalPages {@code ceil(totalItems / size)}
 */
public record PageResponse<T>(List<T> items, int page, int size, long totalItems, int totalPages) {

    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }

    /** Converts each row (entity to DTO) on the way out. */
    public static <E, T> PageResponse<T> from(Page<E> page, Function<? super E, ? extends T> mapper) {
        return from(page.map(mapper));
    }
}
