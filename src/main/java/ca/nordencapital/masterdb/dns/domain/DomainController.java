package ca.nordencapital.masterdb.dns.domain;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.domain.DomainService.AccountDomainView;
import ca.nordencapital.masterdb.dns.domain.DomainService.DomainItem;
import ca.nordencapital.masterdb.dns.domain.DomainService.Expiry;
import ca.nordencapital.masterdb.dns.domain.DomainService.Filter;
import ca.nordencapital.masterdb.dns.domain.DomainService.HealthFilter;
import ca.nordencapital.masterdb.dns.domain.DomainService.ImportResult;
import ca.nordencapital.masterdb.dns.domain.DomainService.Source;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Sort;
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
import java.util.UUID;

/** Domains (DNS job 2). */
@Tag(name = "DNS")
@RestController
@RequestMapping("/api/v1/dns")
public class DomainController {

    private final DomainService service;

    public DomainController(DomainService service) {
        this.service = service;
    }

    public record AddRequest(@NotNull @Size(max = 300) String name) {
    }

    public record ImportRequest(@NotNull List<@Size(max = 300) String> names) {
    }

    @Operation(summary = "List domains", description = "Search `q` in the name; filter `source` (MANUAL, "
            + "NAMECHEAP), `expiry` (EXPIRED, DAYS_30, DAYS_90, UNKNOWN), `health` (OK, PROBLEM, ERROR, UNCHECKED). "
            + "Sort: name, source, expiresAt, createdAt, healthStatus.")
    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping("/domains")
    public PageResponse<DomainItem> list(@ParameterObject PageParams params,
            @RequestParam(required = false) String q, @RequestParam(required = false) Source source,
            @RequestParam(required = false) Expiry expiry, @RequestParam(required = false) HealthFilter health) {
        return service.list(new Filter(q, source, expiry, health),
                params.toPageable(DomainService.SORT_COLUMNS.keySet(), Sort.by("name")));
    }

    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping("/domains/{id}")
    public DomainItem get(@PathVariable UUID id) {
        return service.find(id).item();
    }

    @Operation(summary = "Add a domain by hand", description = "Stored lowercase, punycode for IDN, no trailing "
            + "dot. 400 VALIDATION_FAILED for a bad name, 409 if it is already there.")
    @RequiresPermission(module = Module.DNS, action = Action.CREATE)
    @PostMapping("/domains")
    public ResponseEntity<DomainItem> add(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody AddRequest body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.addManual(caller, body.name()));
    }

    @RequiresPermission(module = Module.DNS, action = Action.DELETE)
    @DeleteMapping("/domains/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        service.delete(caller, id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Domains on the Namecheap account", description = "Calls namecheap.domains.getList "
            + "(all pages). `alreadyAdded` marks names that are in MasterDB already. Nothing is saved.")
    @RequiresPermission(module = Module.DNS, action = Action.CREATE)
    @GetMapping("/namecheap/domains")
    public List<AccountDomainView> namecheapDomains() {
        return service.namecheapDomains();
    }

    @Operation(summary = "Import selected Namecheap domains", description = "Only the names sent are imported, "
            + "and only if they are on the account (checked again). Names already present get fresh metadata.")
    @RequiresPermission(module = Module.DNS, action = Action.CREATE)
    @PostMapping("/domains/import")
    public ImportResult importSelected(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody ImportRequest body) {
        return service.importSelected(caller, body.names());
    }
}
