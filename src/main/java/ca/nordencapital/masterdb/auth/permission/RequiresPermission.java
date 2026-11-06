package ca.nordencapital.masterdb.auth.permission;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * On a controller method (or class): the signed-in user needs this permission,
 * otherwise 403 {@code FORBIDDEN}. The Owner always passes. Checked by
 * {@link PermissionInterceptor} before the method runs.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequiresPermission {
    Module module();

    Action action();
}
