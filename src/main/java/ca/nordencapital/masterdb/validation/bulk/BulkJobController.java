package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.validation.bulk.BulkJobService.CreateRequest;
import ca.nordencapital.masterdb.validation.bulk.BulkJobService.JobView;
import ca.nordencapital.masterdb.validation.bulk.BulkJobService.Status;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Bulk validation jobs: start, watch, stop, resume, retry unknown, delete. */
@Tag(name = "Validation")
@RestController
@RequestMapping("/api/v1/validation/jobs")
public class BulkJobController {

    private final BulkJobService service;

    public BulkJobController(BulkJobService service) {
        this.service = service;
    }

    public record StartRequest(@Size(max = 120) String name, @Size(max = 3_000_000) String emails,
            @Size(max = 50) List<UUID> serverIds) {
    }

    public record ServersRequest(@Size(max = 50) List<UUID> serverIds) {
    }

    @Operation(summary = "Start a bulk job", description = "`emails`: one address per line (a CSV row's first "
            + "field with an @ is taken), at most 50,000 after dropping duplicates and malformed lines (both "
            + "counted). 1 to 10 ready servers; the work rotates between them. Runs in the background: 201 with the "
            + "job, then poll it.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.RUN)
    @PostMapping
    public ResponseEntity<JobView> start(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody StartRequest body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(caller,
                new CreateRequest(body.name(), body.emails(), body.serverIds())));
    }

    @Operation(summary = "Jobs", description = "Newest first; `status` RUNNING, STOPPED or COMPLETED.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping
    public PageResponse<JobView> list(@RequestParam(required = false) Status status,
            @ParameterObject PageParams params) {
        return service.list(status, params.toPageable(Set.of()));
    }

    @Operation(summary = "One job, live", description = "Counters (pending + the six categories = total), what "
            + "each server is doing, checks per minute over the last 5 minutes, and why it waits or stopped.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/{id}")
    public JobView get(@PathVariable UUID id) {
        return service.get(id);
    }

    @Operation(summary = "Stop", description = "Results so far are kept; Resume goes on with the rest.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.RUN)
    @PostMapping("/{id}/stop")
    public JobView stop(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.stop(caller, id);
    }

    @Operation(summary = "Resume", description = "Optional `serverIds` replaces the job's servers.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.RUN)
    @PostMapping("/{id}/resume")
    public JobView resume(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody(required = false) ServersRequest body) {
        return service.resume(caller, id, body == null ? null : body.serverIds());
    }

    @Operation(summary = "Retry unknown", description = "The unknown addresses go back to \"to check\" in the same "
            + "job (never counted twice). Not while running. Optional `serverIds` replaces the job's servers.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.RUN)
    @PostMapping("/{id}/retry-unknown")
    public JobView retry(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody(required = false) ServersRequest body) {
        return service.retryUnknown(caller, id, body == null ? null : body.serverIds());
    }

    @Operation(summary = "Delete a job", description = "With its results. Not while it runs.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.DELETE)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        service.delete(caller, id);
        return ResponseEntity.noContent().build();
    }
}
