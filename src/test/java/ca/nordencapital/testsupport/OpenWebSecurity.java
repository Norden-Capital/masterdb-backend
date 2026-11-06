package ca.nordencapital.testsupport;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * For @WebMvcTest slices that test web conventions, not access rules: the
 * slice does not load SecurityConfig (it needs the database), and Boot's
 * fallback would demand a login everywhere. Access rules are tested against
 * the real configuration in AuthFlowTest.
 */
@TestConfiguration(proxyBeanMethods = false)
public class OpenWebSecurity {

    @Bean
    SecurityFilterChain openChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }
}
