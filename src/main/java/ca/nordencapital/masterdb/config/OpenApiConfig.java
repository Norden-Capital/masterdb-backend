package ca.nordencapital.masterdb.config;

import ca.nordencapital.masterdb.web.error.ErrorCode;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

/**
 * API documentation metadata shown at the top of /api/docs, plus the shared
 * error schema: every operation gets a {@code default} response of type
 * {@code ProblemDetail} (application/problem+json).
 */
@Configuration
public class OpenApiConfig {

    static final String PROBLEM_SCHEMA = "ProblemDetail";
    static final String FIELD_VIOLATION_SCHEMA = "FieldViolation";

    @Bean
    public OpenAPI masterDbOpenApi(ObjectProvider<BuildProperties> buildProperties) {
        BuildProperties build = buildProperties.getIfAvailable();
        return new OpenAPI()
                .info(new Info()
                        .title("MasterDB API")
                        .version(build != null ? build.getVersion() : "dev")
                        .description("Backend for MasterDB, handling email validation, bounce management, "
                                + "deduplication, suppression lists, and contact segmentation.\n\n"
                                + "Every error is `application/problem+json` (RFC 9457) with `code`, "
                                + "`timestamp`, `requestId` and, for `VALIDATION_FAILED`, `errors`."));
    }

    @Bean
    public OpenApiCustomizer problemDetailResponses() {
        return openApi -> {
            if (openApi.getComponents() == null) {
                openApi.setComponents(new Components());
            }
            openApi.getComponents()
                    .addSchemas(FIELD_VIOLATION_SCHEMA, fieldViolationSchema())
                    .addSchemas(PROBLEM_SCHEMA, problemSchema());

            ApiResponse error = new ApiResponse()
                    .description("Error. Always application/problem+json; switch on `code`.")
                    .content(new Content().addMediaType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON_VALUE,
                            new MediaType().schema(ref(PROBLEM_SCHEMA))));
            if (openApi.getPaths() == null) {
                return;
            }
            openApi.getPaths().values().forEach(path -> path.readOperations().forEach(operation -> {
                if (operation.getResponses() == null) {
                    operation.setResponses(new ApiResponses());
                }
                operation.getResponses().addApiResponse("default", error);
            }));
        };
    }

    private static Schema<?> fieldViolationSchema() {
        return new ObjectSchema()
                .description("One invalid field or query parameter. The rejected value is never echoed.")
                .addProperty("field", new StringSchema().example("email"))
                .addProperty("message", new StringSchema().example("must be a well-formed email address"));
    }

    private static Schema<?> problemSchema() {
        StringSchema code = new StringSchema();
        code.setEnum(Arrays.stream(ErrorCode.values()).map(Enum::name).toList());
        return new ObjectSchema()
                .description("RFC 9457 problem details, used for every error response.")
                .addProperty("type", new StringSchema().example("about:blank"))
                .addProperty("title", new StringSchema().example("Bad Request"))
                .addProperty("status", new IntegerSchema().example(400))
                .addProperty("detail", new StringSchema().example("The request has invalid fields."))
                .addProperty("instance", new StringSchema().description("Request path, without query string.")
                        .example("/api/v1/contacts"))
                .addProperty("code", code.description("Stable machine-readable code.").example("VALIDATION_FAILED"))
                .addProperty("timestamp", new StringSchema().format("date-time").example("2026-11-06T12:00:00Z"))
                .addProperty("requestId", new StringSchema().description("Same as the X-Request-Id response header.")
                        .example("3f2b9c1e-8a8d-4c7e-9a43-0f4b8d1c2e55"))
                .addProperty("errors", new ArraySchema().items(ref(FIELD_VIOLATION_SCHEMA))
                        .description("Only on VALIDATION_FAILED."));
    }

    private static Schema<?> ref(String name) {
        return new Schema<>().$ref("#/components/schemas/" + name);
    }
}
