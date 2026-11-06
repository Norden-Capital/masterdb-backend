package ca.nordencapital.masterdb.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * API documentation metadata shown at the top of /api/docs.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI masterDbOpenApi(ObjectProvider<BuildProperties> buildProperties) {
        BuildProperties build = buildProperties.getIfAvailable();
        return new OpenAPI()
                .info(new Info()
                        .title("MasterDB API")
                        .version(build != null ? build.getVersion() : "dev")
                        .description("Backend for MasterDB, handling email validation, bounce management, "
                                + "deduplication, suppression lists, and contact segmentation."));
    }
}
