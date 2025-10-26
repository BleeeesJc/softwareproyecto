package bo.edu.ucb.microservices.core.ms_product_composite.external;

import java.io.IOException;
import java.util.logging.Level;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.fasterxml.jackson.databind.ObjectMapper;

import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.events.Event;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.exceptions.NotFoundException;
import bo.edu.ucb.microservices.util.http.HttpErrorInfo;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

@Component
public class MsReviewIntegration {
	private static final Logger LOGGER = LoggerFactory.getLogger(MsReviewIntegration.class);

	private static final String REVIEW_SERVICE_URL = "http://ms-review";
	private final WebClient webClient;
	private final ObjectMapper mapper;
	private final StreamBridge streamBridge;
	private final Scheduler publishEventScheduler;

	@Autowired
	public MsReviewIntegration(@Qualifier("publishEventScheduler") Scheduler publishEventScheduler,
			WebClient.Builder webClient, ObjectMapper mapper, StreamBridge streamBridge) {

		this.publishEventScheduler = publishEventScheduler;
		this.webClient = webClient.build();
		this.mapper = mapper;
		this.streamBridge = streamBridge;
	}

	public Mono<ReviewDto> createReview(ReviewDto body) {
		return Mono.fromCallable(() -> {
			sendMessage("reviews-out-0", new Event(Event.Type.CREATE, body.getProductId(), body));
			return body;
		}).subscribeOn(publishEventScheduler);
	}

	public Flux<ReviewDto> getReviews(int productId) {

		String url = REVIEW_SERVICE_URL + "/v1/review?productId=" + productId;

		LOGGER.debug("Llamará a getReviews API en URL: {}", url);

		// Se retorna un resultado vacío si algo sale mal para que el servicio de
		// Product-Composite pueda retornar respuestas parciales
		return webClient.get()
				.uri(url)
				.retrieve()
				.bodyToFlux(ReviewDto.class)
				.log(LOGGER.getName(), Level.FINE)
				.onErrorResume(error -> Flux.empty());
	}

	public Mono<Void> deleteReviews(int productId) {

		return Mono.fromRunnable(() -> sendMessage("reviews-out-0", new Event(Event.Type.DELETE, productId, null)))
				.subscribeOn(publishEventScheduler).then();
	}

	private void sendMessage(String bindingName, Event event) {
		LOGGER.debug("Sending a {} message to {}", event.getEventType(), bindingName);
		Message message = MessageBuilder.withPayload(event)
				.setHeader("partitionKey", event.getKey())
				.build();
		streamBridge.send(bindingName, message);
	}

	private Throwable handleException(Throwable ex) {

		if (!(ex instanceof WebClientResponseException)) {
			LOGGER.warn("Se obtuvo un error inesperado: {}", ex.toString());
			return ex;
		}

		WebClientResponseException wcre = (WebClientResponseException) ex;

		switch (HttpStatus.resolve(wcre.getStatusCode().value())) {

		case NOT_FOUND:
			return new NotFoundException(getErrorMessage(wcre));

		case UNPROCESSABLE_ENTITY:
			return new InvalidInputException(getErrorMessage(wcre));

		default:
			LOGGER.warn("Se obtuvo un error HTTP inesperado: {}", wcre.getStatusCode());
			LOGGER.warn("Cuerpo del error: {}", wcre.getResponseBodyAsString());
			return ex;
		}
	}

	private String getErrorMessage(WebClientResponseException ex) {
		try {
			return mapper.readValue(ex.getResponseBodyAsString(), HttpErrorInfo.class).getMessage();
		} catch (IOException ioex) {
			return ex.getMessage();
		}
	}
}
