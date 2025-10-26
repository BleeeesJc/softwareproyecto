package bo.edu.ucb.microservices.core.ms_product_composite;

import static java.util.Collections.singletonList;
import static org.mockito.Mockito.when;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.MediaType.APPLICATION_JSON;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import bo.edu.ucb.microservices.core.ms_product_composite.external.MsProductIntegration;
import bo.edu.ucb.microservices.core.ms_product_composite.external.MsRecommendationIntegration;
import bo.edu.ucb.microservices.core.ms_product_composite.external.MsReviewIntegration;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.exceptions.NotFoundException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@SpringBootTest(webEnvironment = RANDOM_PORT, 
properties = {"eureka.client.enabled=false","spring.main.allow-bean-definition-overriding=true"}, 
classes = {TestSecurityConfig.class})
@AutoConfigureWebTestClient
class MsProductCompositeApplicationTests {

	private static final int PRODUCT_ID_OK = 1;
	private static final int PRODUCT_ID_NOT_FOUND = 2;
	private static final int PRODUCT_ID_INVALID = 3;

	@Autowired
	private WebTestClient client;

	@MockitoBean
	private MsProductIntegration productIntegration;
	@MockitoBean
	private MsReviewIntegration reviewIntegration;
	@MockitoBean
	private MsRecommendationIntegration recommendationIntegration;

	@BeforeEach
	void setUp() {

		when(productIntegration.getProduct(PRODUCT_ID_OK))
				.thenReturn(Mono.just(new ProductDto(PRODUCT_ID_OK, "name", 1, "mock-address")));

		when(recommendationIntegration.getRecommendations(PRODUCT_ID_OK)).thenReturn(Flux.fromIterable(
				singletonList(new RecommendationDto(PRODUCT_ID_OK, 1, "author", 1, "content", "mock address"))));

		when(reviewIntegration.getReviews(PRODUCT_ID_OK)).thenReturn(Flux.fromIterable(
				singletonList(new ReviewDto(PRODUCT_ID_OK, 1, "author", "subject", "content", "mock address"))));

		when(productIntegration.getProduct(PRODUCT_ID_NOT_FOUND))
				.thenThrow(new NotFoundException("NOT FOUND: " + PRODUCT_ID_NOT_FOUND));

		when(productIntegration.getProduct(PRODUCT_ID_INVALID))
				.thenThrow(new InvalidInputException("INVALID: " + PRODUCT_ID_INVALID));
	}

	@Test
	void contextLoads() {
	}

	@Test
	void getProductById() {

		getAndVerifyProduct(PRODUCT_ID_OK, HttpStatus.OK).jsonPath("$.productId").isEqualTo(PRODUCT_ID_OK)
				.jsonPath("$.recommendations.length()").isEqualTo(1)
				.jsonPath("$.reviews.length()").isEqualTo(1);
	}

	@Test
	void getProductNotFound() {

		getAndVerifyProduct(PRODUCT_ID_NOT_FOUND, HttpStatus.NOT_FOUND)
				.jsonPath("$.path").isEqualTo("/v1/product-composite/" + PRODUCT_ID_NOT_FOUND)
				.jsonPath("$.message").isEqualTo("NOT FOUND: " + PRODUCT_ID_NOT_FOUND);
	}

	@Test
	void getProductInvalidInput() {
		getAndVerifyProduct(PRODUCT_ID_INVALID, HttpStatus.UNPROCESSABLE_ENTITY)
				.jsonPath("$.path").isEqualTo("/v1/product-composite/" + PRODUCT_ID_INVALID)
				.jsonPath("$.message").isEqualTo("INVALID: " + PRODUCT_ID_INVALID);
	}

	private WebTestClient.BodyContentSpec getAndVerifyProduct(int productId, HttpStatus expectedStatus) {
		return client
				.mutateWith(SecurityMockServerConfigurers.mockUser("user").roles("PRODUCT_COMPOSITE_READ"))
				.get()
				.uri("/v1/product-composite/" + productId)
				.accept(APPLICATION_JSON).exchange()
				.expectStatus().isEqualTo(expectedStatus)
				.expectHeader().contentType(APPLICATION_JSON)
				.expectBody();
	}
}
