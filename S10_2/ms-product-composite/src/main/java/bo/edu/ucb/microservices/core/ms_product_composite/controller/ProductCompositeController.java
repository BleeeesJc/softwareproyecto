package bo.edu.ucb.microservices.core.ms_product_composite.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import bo.edu.ucb.microservices.core.ms_product_composite.service.ProductCompositeService;
import bo.edu.ucb.microservices.dto.productcomposite.ProductAggregateDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(value = "/v1/product-composite")
@Tag(name = "ProductComposite", description = "REST API para la información completa de productos.")
public class ProductCompositeController {

	private static Logger LOGGER=LoggerFactory.getLogger(ProductCompositeController.class);
	private ProductCompositeService productCompositeService;

	@Autowired
	public ProductCompositeController(ProductCompositeService productCompositeService) {
		super();
		this.productCompositeService = productCompositeService;
	}

	@Operation(summary = "${api.product-composite.get-composite-product.description}", description = "${api.product-composite.get-composite-product.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
			@ApiResponse(responseCode = "404", description = "${api.responseCodes.notFound.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@GetMapping(value = "/{productId}", produces = "application/json")
	@PreAuthorize("hasRole('ROLE_PRODUCT_COMPOSITE_READ')")
	public Mono<ProductAggregateDto> getProduct(
			@Parameter(description = "${api.product-composite.get-composite-product.parameters.productId}", required = true) @PathVariable int productId
			,@AuthenticationPrincipal Jwt jwt
			) {
		LOGGER.info("Datos adicionales (Claims): {}", jwt!=null?jwt.getClaims():"");
		return productCompositeService.getProduct(productId);
	}

	@Operation(summary = "${api.product-composite.create-composite-product.description}", description = "${api.product-composite.create-composite-product.notes}")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@ResponseStatus(HttpStatus.ACCEPTED)
	@PostMapping(consumes = "application/json")
//	@PreAuthorize("hasRole('ROLE_PRODUCT_COMPOSITE_WRITE')")
	public Mono<Void> createProductAggregate(
			@io.swagger.v3.oas.annotations.parameters.RequestBody(description = "${api.product-composite.schema.product-composite.description}", required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = ProductAggregateDto.class))) @RequestBody ProductAggregateDto body) {
		return productCompositeService.createProduct(body);
	}

	@Operation(summary = "${api.product-composite.delete-composite-product.description}", description = "${api.product-composite.delete-composite-product.notes}")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
			@ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}") })
	@ResponseStatus(HttpStatus.ACCEPTED)
	@DeleteMapping(value = "/{productId}")
	public Mono<Void> deleteProduct(
			@Parameter(description = "${api.product-composite.delete-composite-product.parameters.productId}", required = true) @PathVariable int productId) {
		return productCompositeService.deleteProduct(productId);
	}
}
