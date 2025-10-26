package bo.edu.ucb.microservices.core.ms_recommendation.config;

import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import bo.edu.ucb.microservices.core.ms_recommendation.controller.RecommendationServiceController;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
import bo.edu.ucb.microservices.util.events.Event;
import bo.edu.ucb.microservices.util.exceptions.EventProcessingException;

@Configuration
public class MessageProcessorConfig {
	private static final Logger LOGGER = LoggerFactory.getLogger(MessageProcessorConfig.class);

	  private final RecommendationServiceController recommendationServiceController;

	  @Autowired
	  public MessageProcessorConfig(RecommendationServiceController recommendationServiceController) {
	    this.recommendationServiceController = recommendationServiceController;
	  }

	  @Bean
	  public Consumer<Event<Integer, RecommendationDto>> messageProcessor() {
	    return event -> {

	      LOGGER.info("Evento para procesar mensaje creado {}...", event.getEventCreatedAt());

	      switch (event.getEventType()) {

	        case CREATE:
	          RecommendationDto recommendationDto = event.getData();
	          LOGGER.info("Crea recomendacion con ID: {}/{}", recommendationDto.getProductId(), recommendationDto.getRecommendationId());
	          recommendationServiceController.createRecommendation(recommendationDto).block();
	          break;

	        case DELETE:
	          int productId = event.getKey();
	          LOGGER.info("Elimina recomendación con ProductID: {}", productId);
	          recommendationServiceController.deleteRecommendations(productId).block();
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
