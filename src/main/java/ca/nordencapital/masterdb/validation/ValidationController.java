package ca.nordencapital.masterdb.validation;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.validation.SingleCheckService.CheckView;
import ca.nordencapital.masterdb.validation.SingleCheckService.Filter;
import ca.nordencapital.masterdb.validation.ValidationServers.Option;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Validation: servers to choose from, and the single email check with its history. */
@Tag(name = "Validation")
@RestController
@RequestMapping("/api/v1/validation")
public class ValidationController {

    private final ValidationServers servers;
    private final SingleCheckService checks;

    public ValidationController(ValidationServers servers, SingleCheckService checks) {
        this.servers = servers;
        this.checks = checks;
    }

    public record CheckRequest(@Size(max = 300) String email, UUID serverId) {
    }

    @Operation(summary = "Servers for validation", description = "Every server with `ready` and, if not, why: "
            + "connected over SSH with a trusted key, and linked to a domain (greeting name and sender address).")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/servers")
    public List<Option> servers() {
        return servers.options();
    }

    @Operation(summary = "Check one email now", description = "SMTP check through the chosen server (it leaves "
            + "from the server's IP, greeting with its HELO host and sender address; no message is sent). Up to "
            + "about a minute when mail servers are slow. 409 SERVER_NOT_READY with the reason, 424 SSH_FAILED if "
            + "the server can't be reached. Saved in the history.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.RUN)
    @PostMapping("/checks")
    public CheckView check(@AuthenticationPrincipal AuthPrincipal caller, @Validated @RequestBody CheckRequest body) {
        return checks.check(caller, body.email(), body.serverId());
    }

    @Operation(summary = "History of single checks", description = "Newest first; `q` searches the email, "
            + "`category` filters. Kept 90 days.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/checks")
    public PageResponse<CheckView> history(@RequestParam(required = false) String q,
            @RequestParam(required = false) Category category, @ParameterObject PageParams params) {
        return checks.history(new Filter(q, category), params.toPageable(SingleCheckService.SORT_COLUMNS.keySet(),
                Sort.by("createdAt").descending()));
    }

    @Operation(summary = "One check", description = "With the SMTP conversation.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/checks/{id}")
    public CheckView get(@PathVariable UUID id) {
        return checks.get(id);
    }
}
