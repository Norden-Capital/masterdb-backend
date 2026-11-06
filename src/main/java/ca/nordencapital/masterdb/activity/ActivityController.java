package ca.nordencapital.masterdb.activity;

import ca.nordencapital.masterdb.activity.ActivityQuery.Entry;
import ca.nordencapital.masterdb.activity.ActivityQuery.Filter;
import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** The activity log page: list with filters, CSV export. */
@Tag(name = "Activity log")
@RestController
@RequestMapping("/api/v1/activity")
public class ActivityController {

    private final ActivityQuery query;
    private final ActivityLog activity;
    private final Clock clock;

    public ActivityController(ActivityQuery query, ActivityLog activity, Clock clock) {
        this.query = query;
        this.activity = activity;
        this.clock = clock;
    }

    @Operation(summary = "Activity log", description = "Filters: action (repeatable), user (public id, actor or "
            + "target), q (text in emails), from / to (ISO instants, to exclusive). Sort: occurredAt (default desc).")
    @RequiresPermission(module = Module.ACTIVITY_LOG, action = Action.VIEW)
    @GetMapping
    public PageResponse<Entry> list(@ParameterObject PageParams params,
            @RequestParam(required = false) List<String> action, @RequestParam(required = false) UUID user,
            @RequestParam(required = false) String q, @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        Pageable pageable = params.toPageable(Set.of("occurredAt"), Sort.by("occurredAt").descending());
        boolean ascending = pageable.getSort().stream().anyMatch(Sort.Order::isAscending);
        ActivityQuery.Page page = query.list(filter(action, user, q, from, to), pageable.getPageNumber(),
                pageable.getPageSize(), ascending);
        return PageResponse.from(new PageImpl<>(page.items(), pageable, page.total()));
    }

    @Operation(summary = "Export as CSV", description = "Same filters, newest first, at most 100,000 rows. "
            + "The export itself is logged.")
    @RequiresPermission(module = Module.ACTIVITY_LOG, action = Action.EXPORT)
    @GetMapping(value = "/export", produces = "text/csv")
    @Transactional
    public void export(@AuthenticationPrincipal AuthPrincipal me,
            @RequestParam(required = false) List<String> action, @RequestParam(required = false) UUID user,
            @RequestParam(required = false) String q, @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to, HttpServletResponse response) throws IOException {
        Filter filter = filter(action, user, q, from, to);
        String name = "activity-log-" + DateTimeFormatter.ISO_LOCAL_DATE.format(clock.instant().atZone(
                java.time.ZoneOffset.UTC)) + ".csv";
        response.setContentType("text/csv; charset=UTF-8");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
        response.setHeader("Cache-Control", "no-store");
        PrintWriter out = response.getWriter();
        out.print('﻿'); // so Excel reads UTF-8
        out.print("occurred_at,action,actor,actor_id,target,target_id,ip,user_agent,request_id,details\r\n");
        int rows = query.export(filter, e -> out.print(String.join(",", csv(e.occurredAt().toString()),
                csv(e.action()), csv(e.actorLabel()), csv(str(e.actorPublicId())), csv(e.targetLabel()),
                csv(str(e.targetPublicId())), csv(e.ip()), csv(e.userAgent()), csv(e.requestId()),
                csv(e.details().toString())) + "\r\n"));
        activity.record(ActivityAction.ACTIVITY_EXPORTED, ActivityLog.Party.of(me), null,
                Map.of("rows", rows, "filtered", action != null || user != null || q != null || from != null
                        || to != null));
        out.flush();
    }

    private static Filter filter(List<String> action, UUID user, String q, Instant from, Instant to) {
        List<ActivityAction> actions = new ArrayList<>();
        if (action != null) {
            for (String a : action) {
                for (String one : a.split(",")) {
                    if (one.isBlank()) {
                        continue;
                    }
                    try {
                        actions.add(ActivityAction.valueOf(one.trim()));
                    } catch (IllegalArgumentException e) {
                        throw BadRequestException.validation("action", "unknown action");
                    }
                }
            }
        }
        if (q != null && q.length() > 254) {
            throw BadRequestException.validation("q", "must be at most 254 characters");
        }
        return new Filter(actions, user, q, from, to);
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }

    /**
     * One CSV cell: quoted, quotes doubled, and a leading = + - @ (or tab / CR)
     * defused with an apostrophe so a spreadsheet never runs it as a formula.
     */
    static String csv(String value) {
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
