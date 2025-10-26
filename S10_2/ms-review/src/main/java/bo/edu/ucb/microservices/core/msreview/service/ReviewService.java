package bo.edu.ucb.microservices.core.msreview.service;

import java.util.List;
import java.util.logging.Level;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import bo.edu.ucb.microservices.core.msreview.mapper.ReviewMapper;
import bo.edu.ucb.microservices.core.msreview.model.Review;
import bo.edu.ucb.microservices.core.msreview.repository.ReviewRepository;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.http.ServiceUtil;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

@Service
public class ReviewService {
	private static final Logger LOGGER = LoggerFactory.getLogger(ReviewService.class);

	private final ReviewRepository repository;

	private final ReviewMapper mapper;

	private final ServiceUtil serviceUtil;

	private final Scheduler jdbcScheduler;

	@Autowired
	public ReviewService(@Qualifier("jdbcScheduler") Scheduler jdbcScheduler, ReviewRepository repository,
			ReviewMapper mapper, ServiceUtil serviceUtil) {
		super();
		this.jdbcScheduler = jdbcScheduler;
		this.repository = repository;
		this.mapper = mapper;
		this.serviceUtil = serviceUtil;
	}

	public Mono<ReviewDto> createReview(ReviewDto body) {
		if (body.getProductId() < 1) {
			throw new InvalidInputException("productId inválido: " + body.getProductId());
		}
		return Mono.fromCallable(() -> internalCreateReview(body))
				.subscribeOn(jdbcScheduler);
	}

	private ReviewDto internalCreateReview(ReviewDto body) {
		try {
			Review entity = mapper.dtoToEntity(body);
			Review newEntity = repository.save(entity);

			LOGGER.debug("createReview: se creó una reseña: {}/{}", body.getProductId(), body.getReviewId());
			return mapper.entityToDto(newEntity);

		} catch (DataIntegrityViolationException dive) {
			throw new InvalidInputException(
					"Llave duplicada, Product Id: " + body.getProductId() + ", Review Id:" + body.getReviewId());
		}
	}

	public Flux<ReviewDto> getReviews(int productId) {

		if (productId < 1) {
			throw new InvalidInputException("productId inválido: " + productId);
		}

		LOGGER.info("Se obtiene reseñas para el producto con id={}", productId);

		return Mono.fromCallable(() -> internalGetReviews(productId))
				.flatMapMany(Flux::fromIterable)
				.log(LOGGER.getName(), Level.FINE)
				.subscribeOn(jdbcScheduler);
	}

	private List<ReviewDto> internalGetReviews(int productId) {

		List<Review> entityList = repository.findByProductId(productId);
		List<ReviewDto> list = mapper.entityListToDtoList(entityList);
		list.forEach(e -> e.setServiceAddress(serviceUtil.getServiceAddress()));

		LOGGER.debug("Tamaño de la respuesta: {}", list.size());

		return list;
	}

	public Mono<Void> deleteReviews(int productId) {
		if (productId < 1) {
			throw new InvalidInputException("Invalid productId: " + productId);
		}

		return Mono.fromRunnable(() -> internalDeleteReviews(productId))
				.subscribeOn(jdbcScheduler)
				.then();
	}

	private void internalDeleteReviews(int productId) {

		LOGGER.debug("deleteReviews: eliminando reseñas para el producto con productId: {}", productId);
		repository.deleteAll(repository.findByProductId(productId));
	}

}
