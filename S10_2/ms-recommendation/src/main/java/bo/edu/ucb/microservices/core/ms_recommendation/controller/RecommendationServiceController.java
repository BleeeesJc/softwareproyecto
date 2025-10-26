package bo.edu.ucb.microservices.core.ms_recommendation.controller;

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

import bo.edu.ucb.microservices.core.ms_recommendation.service.RecommendationService;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;
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
@RequestMapping(value = "/v1/recommendation")
@Tag(name = "Recommendation", description = "REST API para las recomendaciones de productos.")
public class RecommendationServiceController {

	private static final Logger LOGGER = LoggerFactory.getLogger(RecommendationServiceController.class);

	private final RecommendationService recommendationService;

	@Autowired
	public RecommendationServiceController(RecommendationService recommendationService) {
		this.recommendationService = recommendationService;
	}

	@Operation(summary = "${api.recommendation.get-recommendation.description}", description = "${api.recommendation.get-recommendation.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@GetMapping(produces = "application/json")
	public Flux<RecommendationDto> getRecommendations(
			@Parameter(description = "${api.recommendation.get-recommendation.parameters.productId}", required = true) 
			@RequestParam(value = "productId", required = true) int productId) {
		return recommendationService.getRecommendations(productId);
	}

	@Operation(summary = "${api.recommendation.create-recommendation.description}", description = "${api.recommendation.create-recommendation.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@PostMapping(consumes = "application/json", produces = "application/json")
	public Mono<RecommendationDto> createRecommendation( @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "${api.recommendation.schema.recommendation.description}",
            required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = RecommendationDto.class)))
			@RequestBody RecommendationDto body) {
		return recommendationService.createRecommendation(body);
	}

	@Operation(summary = "${api.recommendation.delete-recommendation.description}", description = "${api.recommendation.delete-recommendation.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@DeleteMapping()
	public Mono<Void> deleteRecommendations(@Parameter(description = "${api.recommendation.delete-recommendation.parameters.productId}", required = true)
			@RequestParam(value = "productId", required = true) int productId) {
		return recommendationService.deleteRecommendations(productId);
	}
}
