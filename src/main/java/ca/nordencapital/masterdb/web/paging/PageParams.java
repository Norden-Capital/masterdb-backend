package ca.nordencapital.masterdb.web.paging;

import ca.nordencapital.masterdb.web.error.BadRequestException;
import io.swagger.v3.oas.annotations.Parameter;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The {@code page}, {@code size} and {@code sort} query parameters of every
 * list endpoint. Bind it with {@code @ParameterObject PageParams params} (so
 * Swagger lists the three parameters) and turn it into a {@link Pageable} with
 * the endpoint's own sort whitelist:
 *
 * <pre>{@code
 * private static final Set<String> SORTABLE = Set.of("createdAt", "email");
 *
 * @GetMapping
 * PageResponse<ContactDto> list(@ParameterObject PageParams params) {
 *     Pageable pageable = params.toPageable(SORTABLE, Sort.by("createdAt").descending());
 *     return PageResponse.from(repository.findAll(pageable), ContactDto::from);
 * }
 * }</pre>
 *
 * Rules: {@code page} is zero-based, default 0, negative is a 400.
 * {@code size} defaults to 25 and is clamped to 1..100 (never an error).
 * {@code sort} is {@code field} or {@code field,asc|desc}, repeatable; a field
 * outside the whitelist or any other direction is a 400 {@code VALIDATION_FAILED}.
 */
public record PageParams(
        @Parameter(description = "Zero-based page number.", example = "0")
        Integer page,
        @Parameter(description = "Page size, default " + PageParams.DEFAULT_SIZE + ", clamped to 1.."
                + PageParams.MAX_SIZE + ".", example = "25")
        Integer size,
        @Parameter(description = "`field` or `field,asc|desc`; repeat for several. Only the fields the endpoint "
                + "documents are allowed.")
        List<String> sort) {

    public static final int DEFAULT_SIZE = 25;
    public static final int MAX_SIZE = 100;

    public Pageable toPageable(Set<String> sortable) {
        return toPageable(sortable, Sort.unsorted());
    }

    /**
     * @param sortable    field names callers may sort on (API names; they must also be entity properties)
     * @param defaultSort used when no {@code sort} is given
     */
    public Pageable toPageable(Set<String> sortable, Sort defaultSort) {
        int pageNumber = page == null ? 0 : page;
        if (pageNumber < 0) {
            throw BadRequestException.validation("page", "must be 0 or greater");
        }
        int pageSize = size == null ? DEFAULT_SIZE : Math.clamp(size, 1, MAX_SIZE);
        return PageRequest.of(pageNumber, pageSize, parseSort(sortable, defaultSort));
    }

    /*
     * Spring's binder splits a single "name,desc" into ["name", "desc"] but leaves
     * repeated parameters whole, so the values are flattened into tokens: a field
     * name, optionally followed by a direction. Field names are never "asc" or
     * "desc", so the reading is unambiguous either way.
     */
    private Sort parseSort(Set<String> sortable, Sort defaultSort) {
        if (sort == null || sort.isEmpty()) {
            return defaultSort;
        }
        List<String> tokens = new ArrayList<>();
        for (String value : sort) {
            for (String token : (value == null ? "" : value).split(",", -1)) {
                tokens.add(token.trim());
            }
        }
        List<Sort.Order> orders = new ArrayList<>();
        for (int i = 0; i < tokens.size(); i++) {
            String field = tokens.get(i);
            if (!sortable.contains(field)) {
                throw BadRequestException.validation("sort", "must be field or field,asc|desc with field one of: "
                        + allowed(sortable));
            }
            String next = i + 1 < tokens.size() ? tokens.get(i + 1).toLowerCase(Locale.ROOT) : "";
            if (next.equals("desc")) {
                orders.add(Sort.Order.desc(field));
                i++;
            } else {
                orders.add(Sort.Order.asc(field));
                if (next.equals("asc")) {
                    i++;
                }
            }
        }
        return Sort.by(orders);
    }

    private static String allowed(Set<String> sortable) {
        return sortable.isEmpty() ? "(none: this list cannot be sorted)" : String.join(", ", sortable.stream().sorted().toList());
    }
}
