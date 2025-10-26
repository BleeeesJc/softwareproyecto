package bo.edu.ucb.microservices.core.msreview.config;

import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import bo.edu.ucb.microservices.core.msreview.controller.ReviewServiceController;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.events.Event;
import bo.edu.ucb.microservices.util.exceptions.EventProcessingException;

@Configuration
public class MessageProcessorConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(MessageProcessorConfig.class);

	  private final ReviewServiceController reviewServiceController;

	  @Autowired
	  public MessageProcessorConfig(ReviewServiceController reviewServiceController) {
	    this.reviewServiceController = reviewServiceController;
	  }

	  @Bean
	  public Consumer<Event<Integer, ReviewDto>> messageProcessor() {
	    return event -> {
	    	LOGGER.info("Evento para procesar mensaje creado {}...", event.getEventCreatedAt());

	      switch (event.getEventType()) {

	        case CREATE:
	          ReviewDto reviewDto = event.getData();
	          LOGGER.info("Crea reseña con ID: {}/{}", reviewDto.getProductId(), reviewDto.getReviewId());
	          reviewServiceController.createReview(reviewDto).block();
	          break;

	        case DELETE:
	          int productId = event.getKey();
	          LOGGER.info("Elimina reseñas con ProductID: {}", productId);
	          reviewServiceController.deleteReviews(productId).block();
	          break;

	        default:
	          String errorMessage = "Tipo de evento incorrecto: " + event.getEventType() + ", se espera CREATE o DELETE";
	          LOGGER.warn(errorMessage);
	          throw new EventProcessingException(errorMessage);
	      }

	      LOGGER.info("Procesamiento de mensajes realizado!");
	    };
	  }
}
