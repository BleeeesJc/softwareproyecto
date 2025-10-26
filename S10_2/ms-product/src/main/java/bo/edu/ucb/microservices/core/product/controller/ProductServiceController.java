package bo.edu.ucb.microservices.core.product.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import bo.edu.ucb.microservices.core.product.services.ProductService;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.exceptions.NotFoundException;
import bo.edu.ucb.microservices.util.http.ServiceUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(value = "/v1/product")
@Tag(name = "Product", description = "REST API para productos")
public class ProductServiceController {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProductServiceController.class);
	private ProductService productService;

	@Autowired
	public ProductServiceController(ProductService productService) {
		this.productService = productService;
	}

	@Operation(summary = "${api.product.get-product.description}", description = "${api.product.get-product.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
			@ApiResponse(responseCode = "404", description = "${api.responseCodes.notFound.description}") })
	@GetMapping(value = "/{productId}", produces = "application/json")
	public Mono<ProductDto> getProduct(@Parameter(description = "${api.product.get-product.parameters.productId}", required = true) 
								@PathVariable int productId) {
		LOGGER.info("Obteniendo producto por el id: {}", productId);
		return productService.getProduct(productId);
	}

	@Operation(summary = "${api.product.create-product.description}", description = "${api.product.create-product.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}") })
	@PostMapping(consumes = "application/json", produces = "application/json")
	public Mono<ProductDto> createProduct( @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "${api.product.schema.product.description}",
            required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = ProductDto.class)))
			@Valid @RequestBody ProductDto body) {
		LOGGER.debug("createProduct: body producto: {}", body);
		return productService.createProduct(body);
	}

	@Operation(summary = "${api.product.delete-product.description}", description = "${api.product.delete-product.notes}")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
			@ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
			@ApiResponse(responseCode = "404", description = "${api.responseCodes.notFound.description}") })
	@DeleteMapping(value = "/{productId}")
	public Mono<Void> deleteProduct(@Parameter(description = "${api.product.delete-product.parameters.productId}", required = true) 
							@PathVariable int productId) {
		LOGGER.debug("deleteProduct: elimiminando producto con productId: {}", productId);
		return productService.deleteProduct(productId);
	}
}
