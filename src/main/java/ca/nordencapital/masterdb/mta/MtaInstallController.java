package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.mta.MtaInstallService.Candidate;
import ca.nordencapital.masterdb.mta.MtaInstallService.InstallView;
import ca.nordencapital.masterdb.mta.MtaInstallService.StartRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

/** Install MTA (Server management job 4). */
@Tag(name = "MTA")
@RestController
@RequestMapping("/api/v1/mta")
public class MtaInstallController {

    private final MtaInstallService service;

    public MtaInstallController(MtaInstallService service) {
        this.service = service;
    }

    public record InstallRequest(UUID serverId, Boolean webmail, @Size(max = 64) String webmailLogin,
            @Size(max = 400) String webmailPassword) {
    }

    @Operation(summary = "Servers for Install MTA", description = "Every server with whether it can get an MTA now "
            + "(`ready`) and, if not, why (`reason`): connected with a trusted key, root or passwordless sudo, a "
            + "linked domain, Ubuntu 22.04/24.04 or AlmaLinux 8/9/10. Plus its last install.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/candidates")
    public List<Candidate> candidates() {
        return service.candidates();
    }

    @Operation(summary = "Start an MTA install", description = "202 with the job; it runs in the background "
            + "(poll it). Postfix, Dovecot, OpenDKIM (key made on the server, selector mail), optional Roundcube "
            + "webmail with one mailbox (the password is used once and never stored). A server that already has an "
            + "MTA needs MTA:EDIT to run it again. 409 MTA_INSTALL_RUNNING if one is running, 409 SERVER_NOT_READY "
            + "with the reason.")
    @RequiresPermission(module = Module.MTA, action = Action.CREATE)
    @PostMapping("/installs")
    public ResponseEntity<InstallView> start(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody InstallRequest body) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(service.start(caller, new StartRequest(body.serverId(),
                Boolean.TRUE.equals(body.webmail()), body.webmailLogin(), body.webmailPassword())));
    }

    @Operation(summary = "One install, live", description = "Status, steps done of total, each step's state and "
            + "the scrubbed output. `logFrom` (characters already shown) returns only the newer part; `logLength` "
            + "is the next `logFrom`.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/installs/{id}")
    public InstallView get(@PathVariable UUID id, @RequestParam(defaultValue = "0") int logFrom) {
        return service.get(id, logFrom);
    }

    @Operation(summary = "Installs of a server", description = "Newest first, at most 20 (logs left out).")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/installs")
    public List<InstallView> history(@RequestParam UUID serverId) {
        return service.history(serverId);
    }
}
