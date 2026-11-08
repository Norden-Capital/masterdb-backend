package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.validation.Category;
import ca.nordencapital.masterdb.validation.bulk.ResultsService.EmailResult;
import ca.nordencapital.masterdb.validation.bulk.ResultsService.Status;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Results of the bulk jobs: addresses per job, exports, and List status across every job. */
@Tag(name = "Validation")
@RestController
@RequestMapping("/api/v1/validation")
public class ResultsController {

    private final ResultsService results;
    private final ActivityLog activity;

    public ResultsController(ResultsService results, ActivityLog activity) {
        this.results = results;
        this.activity = activity;
    }

    @Operation(summary = "Addresses of a job", description = "In list order; `category` one of the six or PENDING "
            + "(still to check); `q` searches the address.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/jobs/{id}/emails")
    public PageResponse<EmailResult> emails(@PathVariable UUID id, @RequestParam(required = false) String category,
            @RequestParam(required = false) String q, @ParameterObject PageParams params) {
        boolean pending = "PENDING".equalsIgnoreCase(category);
        return results.emails(id, pending ? null : category(category), pending, q, params.toPageable(Set.of()));
    }

    @Operation(summary = "Export a job", description = "`category` one of the six: a text file, one address per "
            + "line. `category=DETAILS`: a CSV of every checked address with its result, SMTP code, mail server, "
            + "server, reason and the provider's reply. The export is logged.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.EXPORT)
    @GetMapping("/jobs/{id}/export")
    @Transactional
    public void export(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @RequestParam String category, HttpServletResponse response) throws IOException {
        boolean details = "DETAILS".equalsIgnoreCase(category);
        Category c = details ? null : category(category);
        if (c == null && !details) {
            throw BadRequestException.validation("category", "must be one of the six categories or DETAILS");
        }
        String jobName = results.jobName(id);
        String file = slug(jobName) + "-" + (details ? "details.csv" : c.name().toLowerCase(Locale.ROOT)
                .replace('_', '-') + ".txt");
        response.setContentType((details ? "text/csv" : "text/plain") + "; charset=UTF-8");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Content-Disposition", "attachment; filename=\"" + file + "\"");
        response.setHeader("Cache-Control", "no-store");
        PrintWriter out = response.getWriter();
        int rows;
        if (details) {
            out.print('﻿'); // so Excel reads UTF-8
            out.print("email,category,smtp_code,mail_server,server,checked_at,reason,provider_reply\r\n");
            rows = results.export(id, null, e -> out.print(String.join(",", csv(e.email()),
                    csv(e.category().name()), csv(e.smtpCode() == null ? "" : e.smtpCode().toString()),
                    csv(e.mxHost()), csv(e.serverName()), csv(e.checkedAt() == null ? "" : e.checkedAt().toString()),
                    csv(e.reason()), csv(e.reply())) + "\r\n"));
        } else {
            rows = results.export(id, c, e -> out.print(e.email() + "\r\n"));
        }
        activity.record(ActivityAction.VALIDATION_EXPORTED, Party.of(caller), Party.label(jobName),
                Map.of("job", id.toString(), "category", details ? "DETAILS" : c.name(), "rows", rows));
        out.flush();
    }

    @Operation(summary = "List status", description = "Every address validated in any job, by its latest result: "
            + "how many in each of the six categories.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/status")
    public Status status() {
        return results.status();
    }

    @Operation(summary = "List status: addresses", description = "Latest result per address, newest first; "
            + "`category` filters, `q` searches the address.")
    @RequiresPermission(module = Module.VALIDATION, action = Action.VIEW)
    @GetMapping("/status/emails")
    public PageResponse<EmailResult> latest(@RequestParam(required = false) String category,
            @RequestParam(required = false) String q, @ParameterObject PageParams params) {
        return results.latest(category(category), q, params.toPageable(Set.of()));
    }

    private static Category category(String v) {
        if (v == null || v.isBlank()) {
            return null;
        }
        try {
            return Category.valueOf(v.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw BadRequestException.validation("category", "must be one of VALID, BOUNCE, SOFT_BOUNCE, REJECT, "
                    + "CATCH_ALL, UNKNOWN");
        }
    }

    /** A file name from the job name: letters, digits and dashes. */
    public static String slug(String name) {
        String s = name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-+|-+$)", "");
        s = s.length() > 60 ? s.substring(0, 60) : s;
        return s.isEmpty() ? "validation" : s;
    }

    /** One CSV cell, quoted; a leading = + - @ (or tab / CR) defused so a spreadsheet never runs it. */
    public static String csv(String value) {
        if (value == null) {
            return "";
        }
        String v = value;
        if (!v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0) {
            v = "'" + v;
        }
        return "\"" + v.replace("\"", "\"\"") + "\"";
    }
}
