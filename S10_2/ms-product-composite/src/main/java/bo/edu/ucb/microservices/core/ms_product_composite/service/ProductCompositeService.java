package bo.edu.ucb.microservices.core.ms_product_composite.service;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import bo.edu.ucb.microservices.core.ms_product_composite.external.MsProductIntegration;
import bo.edu.ucb.microservices.core.ms_product_composite.external.MsRecommendationIntegration;
import bo.edu.ucb.microservices.core.ms_product_composite.external.MsReviewIntegration;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.dto.productcomposite.ProductAggregateDto;
import bo.edu.ucb.microservices.dto.productcomposite.RecommendationSummaryDto;
import bo.edu.ucb.microservices.dto.productcomposite.ReviewSummaryDto;
import bo.edu.ucb.microservices.dto.productcomposite.ServiceAddressesDto;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import bo.edu.ucb.microservices.util.http.ServiceUtil;
import reactor.core.publisher.Mono;

@Service
public class ProductCompositeService {
	private static final Logger LOGGER = LoggerFactory.getLogger(ProductCompositeService.class);

	private final ServiceUtil serviceUtil;
	private final MsProductIntegration productIntegration;
	private final MsRecommendationIntegration recommendationIntegration;
	private final MsReviewIntegration reviewIntegration;

	@Autowired
	public ProductCompositeService(ServiceUtil serviceUtil, MsProductIntegration productIntegration,
			MsRecommendationIntegration recommendationIntegration, MsReviewIntegration reviewIntegration) {
		this.serviceUtil = serviceUtil;
		this.productIntegration = productIntegration;
		this.recommendationIntegration = recommendationIntegration;
		this.reviewIntegration = reviewIntegration;
	}

	public Mono<Void> createProduct(ProductAggregateDto body) {

		try {

			List<Mono> monoList = new ArrayList<>();

			LOGGER.info("Crearemos un producto compuesto para el id de producto: {}", body.getProductId());

			ProductDto product = new ProductDto(body.getProductId(), body.getName(), body.getWeight(), null);
			monoList.add(productIntegration.createProduct(product));

			if (body.getRecommendations() != null) {
				body.getRecommendations().forEach(r -> {
					RecommendationDto recommendation = new RecommendationDto(body.getProductId(), r.getRecommendationId(),
							r.getAuthor(), r.getRate(), r.getContent(), null);
					monoList.add(recommendationIntegration.createRecommendation(recommendation));
				});
			}

			if (body.getReviews() != null) {
				body.getReviews().forEach(r -> {
					ReviewDto review = new ReviewDto(body.getProductId(), r.getReviewId(), r.getAuthor(), r.getSubject(),
							r.getContent(), null);
					monoList.add(reviewIntegration.createReview(review));
				});
			}

			LOGGER.debug("createCompositeProduct: se crearon las reseñas, recomendaciones para el producto con productId: {}", body.getProductId());

			return Mono.zip(r -> "", monoList.toArray(new Mono[0]))
					.doOnError(ex -> LOGGER.warn("falló createCompositeProduct: {}", ex.toString())).then();

		} catch (RuntimeException re) {
			LOGGER.warn("falló createCompositeProduct: {}", re.toString());
			throw re;
		}
	}


	public Mono<ProductAggregateDto> getProduct(int productId) {
		LOGGER.info("Obteniendo información del producto, reseñas y recomendaciones para el producto con id={}", productId);
		return Mono.zip(values -> createProductAggregate((ProductDto) values[0], (List<RecommendationDto>) values[1],
				(List<ReviewDto>) values[2], serviceUtil.getServiceAddress()), 
				productIntegration.getProduct(productId),
				recommendationIntegration.getRecommendations(productId).collectList(),
				reviewIntegration.getReviews(productId).collectList())
				.doOnError(ex -> LOGGER.warn("getCompositeProduct failed: {}", ex.toString()))
				.log(LOGGER.getName(),Level.FINE);
	}


	public Mono<Void> deleteProduct(int productId) {
		try {
			LOGGER.info("Se eliminará el producto compuesto para el id: {}", productId);
			return Mono
					.zip(r -> "", productIntegration.deleteProduct(productId), recommendationIntegration.deleteRecommendations(productId),
							reviewIntegration.deleteReviews(productId))
					.doOnError(ex -> LOGGER.warn("delete failed: {}", ex.toString()))
					.log(LOGGER.getName(), Level.FINE)
					.then();

		} catch (RuntimeException re) {
			LOGGER.warn("deleteCompositeProduct failed: {}", re.toString());
			throw re;
		}
	}

	private ProductAggregateDto createProductAggregate(ProductDto product, List<RecommendationDto> recommendations,
			List<ReviewDto> reviews, String serviceAddress) {

		// 1. Configurar información del producto
		int productId = product.getProductId();
		String name = product.getName();
		int weight = product.getWeight();

		// 2. Copiar información de las recomendaciones si existen
		List<RecommendationSummaryDto> recommendationSummaries = 
				(recommendations == null) ? null: recommendations.stream()
						.map(r -> new RecommendationSummaryDto(r.getRecommendationId(), r.getAuthor(),	r.getRate(), r.getContent()))
						.collect(Collectors.toList());

		// 3. Copiar información de las reseñas si existen
		List<ReviewSummaryDto> reviewSummaries = 
				(reviews == null) ? null : reviews.stream()
						.map(r -> new ReviewSummaryDto(r.getReviewId(), r.getAuthor(), r.getSubject(), r.getContent()))
						.collect(Collectors.toList());

		// 4. Crear información de los hosts de los microservicios invocados
		String productAddress = product.getServiceAddress();
		String reviewAddress = (reviews != null && reviews.size() > 0) ? reviews.get(0).getServiceAddress() : "";
		String recommendationAddress = (recommendations != null && recommendations.size() > 0)? recommendations.get(0).getServiceAddress(): "";
		ServiceAddressesDto serviceAddresses = new ServiceAddressesDto(serviceAddress, productAddress, reviewAddress,recommendationAddress);

		return new ProductAggregateDto(productId, name, weight, recommendationSummaries, reviewSummaries, serviceAddresses);
	}
}
