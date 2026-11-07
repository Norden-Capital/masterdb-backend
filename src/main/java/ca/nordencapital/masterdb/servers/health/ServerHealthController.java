package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.servers.health.ServerHealthService.Report;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** Server health (Server management job 2). */
@Tag(name = "Servers")
@RestController
@RequestMapping("/api/v1/servers/{id}/health")
public class ServerHealthController {

    private final ServerHealthService service;

    public ServerHealthController(ServerHealthService service) {
        this.service = service;
    }

    @Operation(summary = "Last health result", description = "Per check (SSH, PORT25, PTR, DNSBL, EXPIRY): "
            + "OK, WARNING, PROBLEM, ERROR (couldn't tell) or NOT_CHECKED, with the reason. `checks` empty = never "
            + "checked.")
    @RequiresPermission(module = Module.SERVERS, action = Action.VIEW)
    @GetMapping
    public Report report(@PathVariable UUID id) {
        return service.report(id);
    }

    @Operation(summary = "Re-check now", description = "SSH and port 25 out run on the server over SSH (up to "
            + "about 40 s when port 25 is blocked); PTR and blocklists are looked up from the backend.")
    @RequiresPermission(module = Module.SERVERS, action = Action.RUN)
    @PostMapping("/check")
    public Report check(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.check(caller, id);
    }
}
