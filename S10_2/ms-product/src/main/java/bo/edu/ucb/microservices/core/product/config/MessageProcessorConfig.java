package bo.edu.ucb.microservices.core.product.config;

import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import bo.edu.ucb.microservices.core.product.controller.ProductServiceController;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.util.events.Event;
import bo.edu.ucb.microservices.util.exceptions.EventProcessingException;

@Configuration
public class MessageProcessorConfig {

	  private static final Logger LOGGER = LoggerFactory.getLogger(MessageProcessorConfig.class);

	  private final ProductServiceController productServiceController;
	  
	  @Autowired
	  public MessageProcessorConfig(ProductServiceController productServiceController) {
	    this.productServiceController = productServiceController;
	  }

	  @Bean
	  public Consumer<Event<Integer, ProductDto>> messageProcessor() {
	    return event -> {
	    	LOGGER.info("Evento para procesar mensaje creado {}...", event.getEventCreatedAt());

	      switch (event.getEventType()) {

	        case CREATE:
	          ProductDto productDto = event.getData();
	          LOGGER.info("Crear producto con ID: {}", productDto.getProductId());
	          productServiceController.createProduct(productDto).block();
	          break;

	        case DELETE:
	          int productId = event.getKey();
	          LOGGER.info("Eliminar producto con ProductID: {}", productId);
	          productServiceController.deleteProduct(productId).block();
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
