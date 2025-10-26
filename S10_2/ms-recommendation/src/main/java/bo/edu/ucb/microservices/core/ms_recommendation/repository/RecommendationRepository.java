package bo.edu.ucb.microservices.core.ms_recommendation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;

import bo.edu.ucb.microservices.core.ms_recommendation.model.Recommendation;
import reactor.core.publisher.Flux;

public interface RecommendationRepository extends ReactiveCrudRepository<Recommendation, String> {
	  Flux<Recommendation> findByProductId(int productId);

}
