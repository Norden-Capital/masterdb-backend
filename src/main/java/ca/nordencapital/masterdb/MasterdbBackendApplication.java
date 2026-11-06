package ca.nordencapital.masterdb;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

/**
 * UserDetailsServiceAutoConfiguration is excluded: logins go through
 * auth/login/LoginService, and Boot's fallback would create an in-memory user
 * and print its generated password to the log.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class MasterdbBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(MasterdbBackendApplication.class, args);
	}

}
