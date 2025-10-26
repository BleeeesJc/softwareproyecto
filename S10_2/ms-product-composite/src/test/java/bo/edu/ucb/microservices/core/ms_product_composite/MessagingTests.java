package bo.edu.ucb.microservices.core.ms_product_composite;


import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.test.web.reactive.server.WebTestClient;

import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.dto.productcomposite.ProductAggregateDto;
import bo.edu.ucb.microservices.dto.productcomposite.RecommendationSummaryDto;
import bo.edu.ucb.microservices.dto.productcomposite.ReviewSummaryDto;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.events.Event;
import reactor.core.publisher.Mono;

@SpringBootTest(
		  webEnvironment = WebEnvironment.RANDOM_PORT,
		  properties = {"spring.main.allow-bean-definition-overriding=true", "eureka.client.enabled=false"},
		  classes = {TestSecurityConfig.class})
		@Import({TestChannelBinderConfiguration.class})
public class MessagingTests {
	private static final Logger LOGGER = LoggerFactory.getLogger(MessagingTests.class);

	  @Autowired
	  private WebTestClient client;

	  @Autowired
	  private OutputDestination target;

	  @BeforeEach
	  void setUp() {
	    purgeMessages("products");
	    purgeMessages("recommendations");
	    purgeMessages("reviews");
	  }

	  @Test
	  void createCompositeProduct1() {

	    ProductAggregateDto composite = new ProductAggregateDto(1, "name", 1, null, null, null);
	    postAndVerifyProduct(composite, HttpStatus.ACCEPTED);

	    final List<String> productMessages = getMessages("products");
	    final List<String> recommendationMessages = getMessages("recommendations");
	    final List<String> reviewMessages = getMessages("reviews");

	    // Assert one expected new product event queued up
	    assertEquals(1, productMessages.size());

	    Event<Integer, ProductDto> expectedEvent =
	      new Event(Event.Type.CREATE, composite.getProductId(), new ProductDto(composite.getProductId(), composite.getName(), composite.getWeight(), null));
	    assertThat(productMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedEvent)));

	    // Assert no recommendation and review events
	    assertEquals(0, recommendationMessages.size());
	    assertEquals(0, reviewMessages.size());
	  }

	  @Test
	  void createCompositeProduct2() {

	    ProductAggregateDto composite = new ProductAggregateDto(1, "name", 1,
	      Collections.singletonList(new RecommendationSummaryDto(1, "a", 1, "c")),
	      Collections.singletonList(new ReviewSummaryDto(1, "a", "s", "c")), null);
	    postAndVerifyProduct(composite, HttpStatus.ACCEPTED);

	    final List<String> productMessages = getMessages("products");
	    final List<String> recommendationMessages = getMessages("recommendations");
	    final List<String> reviewMessages = getMessages("reviews");

	    // Assert one create product event queued up
	    assertEquals(1, productMessages.size());

	    Event<Integer, ProductDto> expectedProductEvent =
	      new Event(Event.Type.CREATE, composite.getProductId(), new ProductDto(composite.getProductId(), composite.getName(), composite.getWeight(), null));
	    assertThat(productMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedProductEvent)));

	    // Assert one create recommendation event queued up
	    assertEquals(1, recommendationMessages.size());

	    RecommendationSummaryDto rec = composite.getRecommendations().get(0);
	    Event<Integer, ProductDto> expectedRecommendationEvent =
	      new Event(Event.Type.CREATE, composite.getProductId(),
	        new RecommendationDto(composite.getProductId(), rec.getRecommendationId(), rec.getAuthor(), rec.getRate(), rec.getContent(), null));
	    assertThat(recommendationMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedRecommendationEvent)));

	    // Assert one create review event queued up
	    assertEquals(1, reviewMessages.size());

	    ReviewSummaryDto rev = composite.getReviews().get(0);
	    Event<Integer, ProductDto> expectedReviewEvent =
	      new Event(Event.Type.CREATE, composite.getProductId(), new ReviewDto(composite.getProductId(), rev.getReviewId(), rev.getAuthor(), rev.getSubject(), rev.getContent(), null));
	    assertThat(reviewMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedReviewEvent)));
	  }

	  @Test
	  void deleteCompositeProduct() {
	    deleteAndVerifyProduct(1, HttpStatus.ACCEPTED);

	    final List<String> productMessages = getMessages("products");
	    final List<String> recommendationMessages = getMessages("recommendations");
	    final List<String> reviewMessages = getMessages("reviews");

	    // Assert one delete product event queued up
	    assertEquals(1, productMessages.size());

	    Event<Integer, ProductDto> expectedProductEvent = new Event(Event.Type.DELETE, 1, null);
	    assertThat(productMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedProductEvent)));

	    // Assert one delete recommendation event queued up
	    assertEquals(1, recommendationMessages.size());

	    Event<Integer, ProductDto> expectedRecommendationEvent = new Event(Event.Type.DELETE, 1, null);
	    assertThat(recommendationMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedRecommendationEvent)));

	    // Assert one delete review event queued up
	    assertEquals(1, reviewMessages.size());

	    Event<Integer, ProductDto> expectedReviewEvent = new Event(Event.Type.DELETE, 1, null);
	    assertThat(reviewMessages.get(0), is(IsSameEvent.sameEventExceptCreatedAt(expectedReviewEvent)));
	  }

	  private void purgeMessages(String bindingName) {
	    getMessages(bindingName);
	  }

	  private List<String> getMessages(String bindingName) {
	    List<String> messages = new ArrayList<>();
	    boolean anyMoreMessages = true;

	    while (anyMoreMessages) {
	      Message<byte[]> message = getMessage(bindingName);

	      if (message == null) {
	        anyMoreMessages = false;

	      } else {
	        messages.add(new String(message.getPayload()));
	      }
	    }
	    return messages;
	  }

	  private Message<byte[]> getMessage(String bindingName) {
	    try {
	      return target.receive(0, bindingName);
	    } catch (NullPointerException npe) {
	      // Si la variable messageQueues del objeto de destino no contiene colas al llamar al método de recepción, se generará una NPE.
	      // Aquí capturamos el NPE y devolvemos un valor nulo para indicar que no se encontraron mensajes.
	      LOGGER.error("getMessage() received a NPE with binding = {}", bindingName);
	      return null;
	    }
	  }

	  private void postAndVerifyProduct(ProductAggregateDto compositeProduct, HttpStatus expectedStatus) {
	    client.post()
	      .uri("/v1/product-composite")
	      .body(Mono.just(compositeProduct), ProductAggregateDto.class)
	      .exchange()
	      .expectStatus().isEqualTo(expectedStatus);
	  }

	  private void deleteAndVerifyProduct(int productId, HttpStatus expectedStatus) {
	    client.delete()
	      .uri("/v1/product-composite/" + productId)
	      .exchange()
	      .expectStatus().isEqualTo(expectedStatus);
	  }

}
