package ca.nordencapital.masterdb.auth.permission;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces {@link RequiresPermission} before a controller method runs: 403
 * {@code FORBIDDEN} (problem+json via the global handler) when the signed-in
 * user lacks it. The Owner holds every permission.
 */
public class PermissionInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        RequiresPermission required = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(),
                RequiresPermission.class);
        if (required == null) {
            required = AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), RequiresPermission.class);
        }
        if (required == null) {
            return true;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthPrincipal principal
                && principal.can(required.module(), required.action())) {
            return true;
        }
        throw new ForbiddenException();
    }
}
