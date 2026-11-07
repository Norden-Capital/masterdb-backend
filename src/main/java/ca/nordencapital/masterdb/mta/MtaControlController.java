package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.mta.MtaControlService.LogView;
import ca.nordencapital.masterdb.mta.MtaControlService.MtaItem;
import ca.nordencapital.masterdb.mta.MtaControlService.QueueView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** MTA list and MTA manager (Server management job 5). */
@Tag(name = "MTA")
@RestController
@RequestMapping("/api/v1/mta/servers")
public class MtaControlController {

    private final MtaControlService mta;

    public MtaControlController(MtaControlService service) {
        this.mta = service;
    }

    @Operation(summary = "MTA list", description = "Every server with an MTA installed by MasterDB, with the last "
            + "status read (service states, versions, queue size) and when.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping
    public List<MtaItem> list() {
        return mta.list();
    }

    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/{id}")
    public MtaItem get(@PathVariable UUID id) {
        return mta.item(id);
    }

    @Operation(summary = "Read the status now", description = "Over SSH: systemctl is-active for postfix, dovecot "
            + "and opendkim, their versions, and the queue size. 424 SSH_FAILED if the server can't be reached.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @PostMapping("/{id}/status")
    public MtaItem refresh(@PathVariable UUID id) {
        return mta.refresh(id);
    }

    @Operation(summary = "Start, stop, restart or reset a service", description = "`service`: postfix, dovecot, "
            + "opendkim or all; `action`: start, stop, restart, reset (systemctl reset-failed). Returns the new status.")
    @RequiresPermission(module = Module.MTA, action = Action.RUN)
    @PostMapping("/{id}/services/{service}/{action}")
    public MtaItem serviceAction(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @PathVariable String service, @PathVariable String action) {
        return mta.serviceAction(caller, id, service, action);
    }

    @Operation(summary = "Recent logs", description = "journalctl, newest last: `source` postfix, dovecot, opendkim "
            + "or mail (every mail log line); `lines` 10 to 500 (100). Scrubbed like the install log.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/{id}/logs")
    public LogView logs(@PathVariable UUID id, @RequestParam(defaultValue = "mail") String source,
            @RequestParam(defaultValue = "100") int lines) {
        return mta.logs(id, source, lines);
    }

    @Operation(summary = "Mail queue", description = "postqueue -j: the number of queued messages and the first 100.")
    @RequiresPermission(module = Module.MTA, action = Action.VIEW)
    @GetMapping("/{id}/queue")
    public QueueView queue(@PathVariable UUID id) {
        return mta.queue(id);
    }

    @Operation(summary = "Flush the queue", description = "postqueue -f: try delivering every queued message now.")
    @RequiresPermission(module = Module.MTA, action = Action.RUN)
    @PostMapping("/{id}/queue/flush")
    public QueueView flush(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return mta.flush(caller, id);
    }

    @Operation(summary = "Remove from the MTA list", description = "Forgets the MTA in MasterDB; nothing changes on "
            + "the server. Install MTA brings it back.")
    @RequiresPermission(module = Module.MTA, action = Action.DELETE)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> forget(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        mta.forget(caller, id);
        return ResponseEntity.noContent().build();
    }
}
