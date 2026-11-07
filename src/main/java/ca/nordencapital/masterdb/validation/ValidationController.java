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
import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.PutMapping;
import java.util.Map;
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
    private final Pacing pacing;
    private final ActivityLog activity;

    public ValidationController(ValidationServers servers, SingleCheckService checks, Pacing pacing,
            ActivityLog activity) {
        this.servers = servers;
        this.checks = checks;
        this.pacing = pacing;
        this.activity = activity;
    }

    public record PacingView(List<Pacing.Provider> providers, List<Pacing.CooldownView> paused) {
    }

    public record ProviderRequest(@NotNull @Min(0) @Max(600_000) Integer gapMs,
            @NotNull @Min(0) @Max(600_000) Integer globalGapMs, @NotNull @Min(0) @Max(86_400) Integer rateCooldownS,
            @NotNull @Min(0) @Max(86_400) Integer blockCooldownS, @NotNull @Min(0) @Max(86_400) Integer maxCooldownS) {
    }

    @Operation(summary = "Pacing per provider", description = "The waits and pauses per email provider (saved in "
            + "the database), and every pause running now (server, provider, until when, the answer that caused it).")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/pacing")
    public PacingView pacing() {
        return new PacingView(pacing.providers(), pacing.active());
    }

    @Operation(summary = "Change a provider's pacing", description = "GOOGLE, MICROSOFT, YAHOO or OTHER. Waits in "
            + "milliseconds, pauses in seconds. Used from the next check on.")
    @RequiresPermission(module = Module.SETTINGS, action = Action.EDIT)
    @PutMapping("/pacing/{key}")
    public Pacing.Provider updatePacing(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable String key,
            @Validated @RequestBody ProviderRequest body) {
        Pacing.Provider p = pacing.update(key, body.gapMs(), body.globalGapMs(), body.rateCooldownS(),
                body.blockCooldownS(), body.maxCooldownS());
        activity.record(ActivityAction.VALIDATION_PACING_CHANGED, Party.of(caller), Party.label(p.label()),
                Map.of("gapMs", p.gapMs(), "globalGapMs", p.globalGapMs(), "rateCooldownS", p.rateCooldownS(),
                        "blockCooldownS", p.blockCooldownS(), "maxCooldownS", p.maxCooldownS()));
        return p;
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
