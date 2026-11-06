package ca.nordencapital.masterdb.status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;

/**
 * Public reachability/version check for the frontend. Does not touch the
 * database, so it means "the API answers", not "everything is healthy"
 * (that is /actuator/health).
 */
@Tag(name = "Status")
@RestController
@RequestMapping("/api/v1/status")
public class StatusController {

    static final String SERVICE = "masterdb-backend";

    private final String version;
    private final Clock clock;

    public StatusController(ObjectProvider<BuildProperties> buildProperties, ObjectProvider<Clock> clock) {
        BuildProperties build = buildProperties.getIfAvailable();
        this.version = build != null ? build.getVersion() : "dev";
        this.clock = clock.getIfAvailable(Clock::systemUTC);
    }

    @Operation(summary = "Service status", description = "Service name, version and current server time.")
    @GetMapping
    public StatusResponse status() {
        return new StatusResponse(SERVICE, "ok", version, Instant.now(clock));
    }

    public record StatusResponse(String service, String status, String version, Instant time) {
    }
}
