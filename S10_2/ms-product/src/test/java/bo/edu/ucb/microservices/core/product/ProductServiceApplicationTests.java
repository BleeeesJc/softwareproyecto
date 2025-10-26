package bo.edu.ucb.microservices.core.product;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.http.MediaType.APPLICATION_JSON;

import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.reactive.server.WebTestClient;

import bo.edu.ucb.microservices.core.product.model.Product;
import bo.edu.ucb.microservices.core.product.repository.ProductRepository;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.util.events.Event;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;

@SpringBootTest(webEnvironment = RANDOM_PORT, properties = {"eureka.client.enabled=false"})
class ProductServiceApplicationTests extends MongoDbTestBase {

	@Autowired
	private WebTestClient client;

	@Autowired
	private ProductRepository repository;

	@Autowired
	@Qualifier("messageProcessor")
	private Consumer<Event<Integer, ProductDto>> messageProcessor;

	@BeforeEach
	void setupDb() {
		repository.deleteAll().block();
	}

	@Test
	void getProductById() {

		int productId = 1;
		assertNull(repository.findByProductId(productId).block());
		assertEquals(0, (long) repository.count().block());

		sendCreateProductEvent(productId);

		assertNotNull(repository.findByProductId(productId).block());
		assertEquals(1, (long) repository.count().block());

		getAndVerifyProduct(productId, HttpStatus.OK).jsonPath("$.productId").isEqualTo(productId);
	}

	@Test
	void duplicateError() {

		int productId = 1;

		assertNull(repository.findByProductId(productId).block());

		sendCreateProductEvent(productId);

		assertNotNull(repository.findByProductId(productId).block());

		InvalidInputException thrown = assertThrows(InvalidInputException.class,
				() -> sendCreateProductEvent(productId), "Expected a InvalidInputException here!");
	}

	@Test
	void deleteProduct() {

		int productId = 1;

		sendCreateProductEvent(productId);
		assertNotNull(repository.findByProductId(productId).block());

		sendDeleteProductEvent(productId);
		assertNull(repository.findByProductId(productId).block());

		sendDeleteProductEvent(productId);
	}

	@Test
	void getProductInvalidParameterString() {
		getAndVerifyProduct("/no-integer", BAD_REQUEST)
				.jsonPath("$.path").isEqualTo("/v1/product/no-integer")
				.jsonPath("$.message").isEqualTo("Type mismatch.");
	}

	@Test
	void getProductNotFound() {

		int productIdNotFound = 13;
		getAndVerifyProduct(productIdNotFound, HttpStatus.NOT_FOUND)
				.jsonPath("$.path").isEqualTo("/v1/product/" + productIdNotFound);
	}

	@Test
	void getProductInvalidParameterNegativeValue() {

		int productIdInvalid = -1;

		getAndVerifyProduct(productIdInvalid, UNPROCESSABLE_ENTITY)
				.jsonPath("$.path").isEqualTo("/v1/product/" + productIdInvalid);
	}

	private WebTestClient.BodyContentSpec getAndVerifyProduct(int productId, HttpStatus expectedStatus) {
		return getAndVerifyProduct("/" + productId, expectedStatus);
	}

	private WebTestClient.BodyContentSpec getAndVerifyProduct(String productIdPath, HttpStatus expectedStatus) {
		return client.get()
				.uri("/v1/product" + productIdPath)
				.accept(APPLICATION_JSON)
				.exchange()
				.expectStatus().isEqualTo(expectedStatus)
				.expectHeader().contentType(APPLICATION_JSON).expectBody();
	}

	private void sendCreateProductEvent(int productId) {
		ProductDto product = new ProductDto(productId, "Name " + productId, productId, "SA");
		Event<Integer, ProductDto> event = new Event(Event.Type.CREATE, productId, product);
		messageProcessor.accept(event);
	}

	private void sendDeleteProductEvent(int productId) {
		Event<Integer, ProductDto> event = new Event(Event.Type.DELETE, productId, null);
		messageProcessor.accept(event);
	}
}
