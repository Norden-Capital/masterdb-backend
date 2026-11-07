package ca.nordencapital.masterdb.dns.health;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.health.DnsHealthService.Report;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** DNS health of a domain (DNS job 4). */
@Tag(name = "DNS")
@RestController
@RequestMapping("/api/v1/dns/domains/{id}/health")
public class DnsHealthController {

    private final DnsHealthService service;

    public DnsHealthController(DnsHealthService service) {
        this.service = service;
    }

    @Operation(summary = "Last health check", description = "Per record (A, MX, SPF, DKIM, DMARC, BIMI, PTR): OK, "
            + "PROBLEM, ERROR (lookup failed) or NOT_CHECKED, with the reason. Empty `records` = never checked.")
    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping
    public Report get(@PathVariable UUID id) {
        return service.report(id);
    }

    @Operation(summary = "Re-check now", description = "Asks public DNS (app.dns.resolvers) and stores the result. "
            + "Every domain is also re-checked daily.")
    @RequiresPermission(module = Module.DNS, action = Action.RUN)
    @PostMapping("/check")
    public Report check(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.check(caller, id);
    }
}
