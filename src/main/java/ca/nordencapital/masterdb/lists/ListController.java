package ca.nordencapital.masterdb.lists;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.lists.ListRow.Source;
import ca.nordencapital.masterdb.lists.ListRow.Status;
import ca.nordencapital.masterdb.lists.ListService.Detail;
import ca.nordencapital.masterdb.lists.ListService.Facets;
import ca.nordencapital.masterdb.lists.ListService.Filter;
import ca.nordencapital.masterdb.lists.ListService.ListView;
import ca.nordencapital.masterdb.lists.ListService.Member;
import ca.nordencapital.masterdb.lists.ListService.UpdateRequest;
import ca.nordencapital.masterdb.validation.bulk.ResultsController;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** List management: the lists, one list with its parts and members, edit, delete, export. */
@Tag(name = "Lists")
@RestController
@RequestMapping("/api/v1/lists")
public class ListController {

    private final ListService lists;

    public ListController(ListService lists) {
        this.lists = lists;
    }

    public record EditBody(@Size(max = 300) String name, @Size(max = 300) String esp, @Size(max = 300) String country,
            @Size(max = 300) String vertical) {
    }

    @Operation(summary = "Lists", description = "Newest first. `q` searches the name; `esp`, `country`, `vertical` "
            + "(exact), `source` FILE|DRIVE, `status`. Sort: name, records, esp, country, vertical, parts, createdAt, "
            + "status, source.")
    @RequiresPermission(module = Module.LISTS, action = Action.VIEW)
    @GetMapping
    public PageResponse<ListView> list(@RequestParam(required = false) String q,
            @RequestParam(required = false) String esp, @RequestParam(required = false) String country,
            @RequestParam(required = false) String vertical, @RequestParam(required = false) Source source,
            @RequestParam(required = false) Status status, @ParameterObject PageParams params) {
        return lists.page(new Filter(q, esp, country, vertical, source, status),
                params.toPageable(ListService.SORT_COLUMNS.keySet(), Sort.unsorted()));
    }

    @Operation(summary = "Filter values", description = "The ESPs, countries and verticals used by the lists.")
    @RequiresPermission(module = Module.LISTS, action = Action.VIEW)
    @GetMapping("/facets")
    public Facets facets() {
        return lists.facets();
    }

    @Operation(summary = "One list", description = "With its import report or live progress, its parts, and the "
            + "latest validation counts.")
    @RequiresPermission(module = Module.LISTS, action = Action.VIEW)
    @GetMapping("/{id}")
    public Detail get(@PathVariable UUID id) {
        return lists.detail(id);
    }

    @Operation(summary = "A list's addresses", description = "File order, with the file's own columns. `part` "
            + "limits to one part; `q` searches the address.")
    @RequiresPermission(module = Module.LISTS, action = Action.VIEW)
    @GetMapping("/{id}/emails")
    public PageResponse<Member> emails(@PathVariable UUID id, @RequestParam(required = false) Integer part,
            @RequestParam(required = false) String q, @ParameterObject PageParams params) {
        return lists.members(id, part, q, params.toPageable(Set.of()));
    }

    @Operation(summary = "Edit the details", description = "Name (required), ESP, country, vertical, as in the old "
            + "app. Remove duplicates and split size are fixed at import.")
    @RequiresPermission(module = Module.LISTS, action = Action.EDIT)
    @PutMapping("/{id}")
    public ListView update(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody EditBody body) {
        return lists.update(caller, id, new UpdateRequest(body.name(), body.esp(), body.country(), body.vertical()));
    }

    @Operation(summary = "Delete a list", description = "With its parts and members (the contacts stay). Not while "
            + "a validation job runs on it.")
    @RequiresPermission(module = Module.LISTS, action = Action.DELETE)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        lists.delete(caller, id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Export a list", description = "CSV of the list (or one `part`) in file order, with the "
            + "file's own columns (UTF-8 BOM; cells starting with = + - @ defused). Logged.")
    @RequiresPermission(module = Module.LISTS, action = Action.EXPORT)
    @GetMapping("/{id}/export")
    @Transactional
    public void export(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @RequestParam(required = false) Integer part, HttpServletResponse response) throws IOException {
        ListRow l = lists.find(id);
        String file = ResultsController.slug(l.name()) + (part == null ? "" : "-part-" + part) + ".csv";
        PrintWriter[] out = {null};
        int[] width = {1};
        lists.export(caller, id, part, header -> {
            // Headers only once the checks passed (a refusal stays a normal error answer).
            response.setContentType("text/csv; charset=UTF-8");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file + "\"");
            response.setHeader("Cache-Control", "no-store");
            try {
                out[0] = response.getWriter();
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
            width[0] = header.size();
            out[0].print('﻿');
            out[0].print(row(header) + "\r\n");
        }, m -> out[0].print(row(cells(m, width[0])) + "\r\n"));
        out[0].flush();
    }

    /** The member's own cells (or just the address for a one-column file), padded to the header's width. */
    static List<String> cells(Member m, int width) {
        if (m.fields() == null) {
            return List.of(m.email());
        }
        List<String> out = new ArrayList<>(m.fields());
        while (out.size() < width) {
            out.add("");
        }
        return out;
    }

    static String row(List<String> cells) {
        return String.join(",", cells.stream().map(ResultsController::csv).toList());
    }
}
