package bo.edu.ucb.microservices.core.msreview;

import java.time.Duration;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.containers.PostgreSQLContainer;

public abstract class PostgreSqlTestBase {


	  private static PostgreSQLContainer<?> database = new PostgreSQLContainer<>("postgres:16-alpine").withStartupTimeout(Duration.ofSeconds(300));

	  static {
	    database.start();
	  }

	  @DynamicPropertySource
	  static void databaseProperties(DynamicPropertyRegistry registry) {
	    registry.add("spring.datasource.url", database::getJdbcUrl);
	    registry.add("spring.datasource.username", database::getUsername);
	    registry.add("spring.datasource.password", database::getPassword);
	  }
}
