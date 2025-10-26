package bo.edu.ucb.microservices.core.msreview.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.transaction.annotation.Transactional;

import bo.edu.ucb.microservices.core.msreview.model.Review;


public interface ReviewRepository extends CrudRepository<Review, Integer> {

	  @Transactional(readOnly = true)
	  List<Review> findByProductId(int productId);
	
}
	