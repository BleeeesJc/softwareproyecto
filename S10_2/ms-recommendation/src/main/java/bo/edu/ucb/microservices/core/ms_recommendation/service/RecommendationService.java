package bo.edu.ucb.microservices.core.ms_recommendation.service;

import java.util.logging.Level;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import bo.edu.ucb.microservices.core.ms_recommendation.mapper.RecommendationMapper;
import bo.edu.ucb.microservices.core.ms_recommendation.model.Recommendation;
import bo.edu.ucb.microservices.core.ms_recommendation.repository.RecommendationRepository;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.http.ServiceUtil;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class RecommendationService {

	private static Logger LOGGER = LoggerFactory.getLogger(RecommendationService.class);
	private final ServiceUtil serviceUtil;
	private final RecommendationRepository repository;
	private final RecommendationMapper mapper;
	
	public RecommendationService(ServiceUtil serviceUtil, RecommendationRepository repository,
			RecommendationMapper mapper) {
		super();
		this.serviceUtil = serviceUtil;
		this.repository = repository;
		this.mapper = mapper;
	}
	

	  public Mono<RecommendationDto> createRecommendation(RecommendationDto body) {
		  if (body.getProductId() < 1) {
		      throw new InvalidInputException("productId inválido: " + body.getProductId());
		    }

		    Recommendation entity = mapper.dtoToEntity(body);
		    Mono<RecommendationDto> newEntity = repository.save(entity)
		      .log(LOGGER.getName(), Level.FINE)
		      .onErrorMap(
		        DuplicateKeyException.class,
		        ex -> new InvalidInputException("Llave duplicada, Product Id: " + body.getProductId() + ", Recommendation Id:" + body.getRecommendationId()))
		      .map(e -> mapper.entityToDto(e));

		    return newEntity;
	  }


	  public Flux<RecommendationDto> getRecommendations(int productId) {

	    if (productId < 1) {
	      throw new InvalidInputException("productId inválido: " + productId);
	    }
	    
	    LOGGER.info("Obteniendo recomendaciones para el producto con id={}", productId);

	    return repository.findByProductId(productId)
	      .log(LOGGER.getName(), Level.FINE)
	      .map(e -> mapper.entityToDto(e))
	      .map(e -> setServiceAddress(e));
	  }


	  public Mono<Void> deleteRecommendations(int productId) {
		  
		if (productId < 1) {
		        throw new InvalidInputException("productId inválido: " + productId);
		}

	    LOGGER.debug("deleteRecommendations: eliminando recomendaciones para el producto con productId: {}", productId);
	    return repository.deleteAll(repository.findByProductId(productId));
	  }
	  
	  private RecommendationDto setServiceAddress(RecommendationDto e) {
		    e.setServiceAddress(serviceUtil.getServiceAddress());
		    return e;
		  }
}
