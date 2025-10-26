package bo.edu.ucb.microservices.core.product.repository;

import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;

import bo.edu.ucb.microservices.core.product.model.Product;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface ProductRepository extends ReactiveCrudRepository<Product, String> {
	  Mono<Product> findByProductId(int productId);
	  
	  Flux<Product> findByWeightGreaterThanEqual(int weight);
	  
	  @Query("{'weight': {$gte: ?0, $lte: ?1} }")
	  Flux<Product> findProductsInWeightRange(int minWeight, int maxWeight);

}
