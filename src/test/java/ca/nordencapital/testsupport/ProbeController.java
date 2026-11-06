package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

/**
 * Test-only endpoints that trigger each kind of error. Lives outside
 * ca.nordencapital.masterdb so the application's component scan never sees
 * it; tests pull it in with @Import.
 */
@RestController
@RequestMapping("/probe")
public class ProbeController {

    public static final String SECRET = "jane.doe@example.com password=hunter2";

    public record Body(@NotBlank @Email String email, @NotNull @Min(1) Integer count) {
    }

    public record Dated(String name, String nothing, Instant at) {
    }

    @PostMapping(value = "/body", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Body body(@Valid @RequestBody Body body) {
        return body;
    }

    @GetMapping("/param")
    public int param(@RequestParam @Min(1) @Max(10) int count) {
        return count;
    }

    @GetMapping("/not-found")
    public void notFound() {
        throw new NotFoundException("Contact 42 was not found.");
    }

    @GetMapping("/conflict")
    public void conflict() {
        throw new ConflictException("An import is already running.");
    }

    @GetMapping("/bad-request")
    public void badRequest() {
        throw new BadRequestException("The file is empty.");
    }

    @GetMapping("/boom")
    public void boom() {
        throw new IllegalStateException(SECRET);
    }

    @GetMapping("/json")
    public Dated json() {
        return new Dated("x", null, Instant.parse("2026-11-06T12:00:00Z"));
    }

    /** Returns the applied sort orders as the items, so tests can see what was parsed. */
    @GetMapping("/page")
    public PageResponse<String> page(@ParameterObject PageParams params) {
        Pageable pageable = params.toPageable(Set.of("name", "createdAt"), Sort.by("createdAt").descending());
        List<String> sorts = pageable.getSort().stream()
                .map(o -> o.getProperty() + "," + o.getDirection().name().toLowerCase())
                .toList();
        long total = 1234;
        return PageResponse.from(new PageImpl<>(sorts, pageable, total));
    }

    @GetMapping("/rows")
    public PageResponse<Integer> rows(@ParameterObject PageParams params) {
        Pageable pageable = params.toPageable(Set.of());
        List<Integer> all = IntStream.range(0, 30).boxed().toList();
        int from = (int) Math.min(pageable.getOffset(), all.size());
        int to = Math.min(from + pageable.getPageSize(), all.size());
        return PageResponse.from(new PageImpl<>(all.subList(from, to), pageable, all.size()), i -> i * 10);
    }
}
