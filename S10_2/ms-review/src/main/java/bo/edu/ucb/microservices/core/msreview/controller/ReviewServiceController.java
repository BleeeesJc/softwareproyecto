package bo.edu.ucb.microservices.core.msreview.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import bo.edu.ucb.microservices.core.msreview.service.ReviewService;
import bo.edu.ucb.microservices.dto.review.ReviewDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(value = "/v1/review")
@Tag(name = "Review", description = "REST API para las reseñas de productos.")
public class ReviewServiceController {

	private static final Logger LOGGER = LoggerFactory.getLogger(ReviewServiceController.class);

	private ReviewService reviewService;

	@Autowired
	public ReviewServiceController(ReviewService reviewService) {
		this.reviewService = reviewService;
	}

	@Operation(summary = "${api.review.get-review.description}", description = "${api.review.get-review.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@GetMapping(produces = "application/json")
	public Flux<ReviewDto> getReviews(
			@Parameter(description = "${api.review.get-review.parameters.productId}", required = true) 
			@RequestParam(value = "productId", required = true) int productId) {
		return reviewService.getReviews(productId);
	}

	@Operation(summary = "${api.review.create-review.description}", description = "${api.review.create-review.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@PostMapping(consumes = "application/json", produces = "application/json")
	public Mono<ReviewDto> createReview(@io.swagger.v3.oas.annotations.parameters.RequestBody(description = "${api.review.schema.review.description}",
            required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = ReviewDto.class)))
			@RequestBody ReviewDto body) {
           return reviewService.createReview(body);
	}

	@Operation(summary = "${api.review.delete-review.description}", description = "${api.review.delete-review.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@DeleteMapping()
	public Mono<Void> deleteReviews(@Parameter(description = "${api.review.delete-review.parameters.productId}", required = true)
			@RequestParam(value = "productId", required = true) int productId) {
		return reviewService.deleteReviews(productId);
	}
}
