package ca.nordencapital.masterdb.dns.records;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.records.DnsRecordService.Plan;
import ca.nordencapital.masterdb.dns.records.DnsRecordService.SnapshotView;
import ca.nordencapital.masterdb.dns.records.DnsRecordService.WriteResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Managed DNS records of a domain (DNS job 3). */
@Tag(name = "DNS")
@RestController
@RequestMapping("/api/v1/dns/domains/{id}")
public class DnsRecordController {

    private final DnsRecordService service;

    public DnsRecordController(DnsRecordService service) {
        this.service = service;
    }

    public record SettingsRequest(@Size(max = 100) String mailIp, @Size(max = 100) String dkimSelector,
            @Size(max = 6000) String dkimPublicKey, @Size(max = 20) String dmarcPolicy,
            @Size(max = 600) String bimiLogoUrl, @Size(max = 600) String bimiCertificateUrl) {
    }

    public record TokenRequest(@NotBlank @Size(max = 100) String token) {
    }

    @Operation(summary = "What the managed records should say", description = "Mail IP, DKIM selector and public "
            + "key, DMARC policy, BIMI URLs. Any domain; health checks use them too.")
    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping("/dns-settings")
    public DnsSettings settings(@PathVariable UUID id) {
        return service.settings(id);
    }

    @Operation(summary = "Change the managed-record settings", description = "Writes nothing at Namecheap.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @PutMapping("/dns-settings")
    public DnsSettings saveSettings(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody SettingsRequest body) {
        return service.saveSettings(caller, id, new DnsSettings(body.mailIp(), body.dkimSelector(),
                body.dkimPublicKey(), body.dmarcPolicy(), body.bimiLogoUrl(), body.bimiCertificateUrl(), null));
    }

    @Operation(summary = "Preview writing the managed records", description = "Reads the records at Namecheap "
            + "and returns the before/after (every record MasterDB does not manage is kept) and a `token`. "
            + "Writes nothing. 409 DNS_WRITE_REFUSED when it can't be done safely.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @GetMapping("/records/preview")
    public Plan preview(@PathVariable UUID id) {
        return service.preview(id);
    }

    @Operation(summary = "Write the managed records", description = "Needs the preview's `token`; 409 "
            + "DNS_CHANGED_SINCE_PREVIEW if the records changed since. Saves a snapshot of the current records, "
            + "calls setHosts with the merged set, then reads back to verify.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @PostMapping("/records/apply")
    public WriteResult apply(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody TokenRequest body) {
        return service.apply(caller, id, body.token());
    }

    @Operation(summary = "Snapshots", description = "The record sets saved before each write, newest first (50).")
    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping("/snapshots")
    public List<SnapshotView> snapshots(@PathVariable UUID id) {
        return service.snapshots(id);
    }

    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping("/snapshots/{snapshotId}")
    public SnapshotView snapshot(@PathVariable UUID id, @PathVariable UUID snapshotId) {
        return service.snapshot(id, snapshotId);
    }

    @Operation(summary = "Preview restoring a snapshot", description = "Before/after and a `token`; writes nothing.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @GetMapping("/snapshots/{snapshotId}/restore-preview")
    public Plan restorePreview(@PathVariable UUID id, @PathVariable UUID snapshotId) {
        return service.restorePreview(id, snapshotId);
    }

    @Operation(summary = "Restore a snapshot", description = "Same safety as a write: token check, snapshot of "
            + "the current records first, verify after.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @PostMapping("/snapshots/{snapshotId}/restore")
    public WriteResult restore(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @PathVariable UUID snapshotId, @Validated @RequestBody TokenRequest body) {
        return service.restore(caller, id, snapshotId, body.token());
    }
}
