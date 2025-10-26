package bo.edu.ucb.microservices.core.product.services;

import java.util.logging.Level;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import bo.edu.ucb.microservices.core.product.mapper.ProductMapper;
import bo.edu.ucb.microservices.core.product.model.Product;
import bo.edu.ucb.microservices.core.product.repository.ProductRepository;
import bo.edu.ucb.microservices.dto.product.ProductDto;
import bo.edu.ucb.microservices.util.exceptions.InvalidInputException;
import bo.edu.ucb.microservices.util.exceptions.NotFoundException;
import bo.edu.ucb.microservices.util.http.ServiceUtil;
import reactor.core.publisher.Mono;

@Service
public class ProductService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProductService.class);
	private final ServiceUtil serviceUtil;
	private final ProductRepository repository;
	private final ProductMapper mapper;

	@Autowired
	public ProductService(ServiceUtil serviceUtil, ProductRepository repository, ProductMapper mapper) {
		super();
		this.serviceUtil = serviceUtil;
		this.repository = repository;
		this.mapper = mapper;
	}

	public Mono<ProductDto> createProduct(ProductDto productDto) {

		if (productDto.getProductId() < 1) {
			throw new InvalidInputException("Id de producto inválido: " + productDto.getProductId());
		}

		Product entity = mapper.dtoToEntity(productDto);
		Mono<ProductDto> newEntity = repository.save(entity)
				.log(LOGGER.getName(), Level.FINE)
				.onErrorMap(DuplicateKeyException.class,
						ex -> new InvalidInputException("Llave duplicada, Product Id: " + productDto.getProductId()))
				.map(e -> mapper.entityToDto(e));

		LOGGER.debug("createProduct: entidad creada para productId: {}", productDto.getProductId());
		return newEntity;
	}

	public Mono<ProductDto> getProduct(int productId) {
		if (productId < 1) {
			throw new InvalidInputException("productId inválido: " + productId);
		}

		return repository.findByProductId(productId)
				.switchIfEmpty(Mono.error(new NotFoundException("No se encontró producto para productId: " + productId)))
				.log(LOGGER.getName(), Level.FINE)
				.map(e -> mapper.entityToDto(e))
				.map(e -> setServiceAddress(e));
	}

	public Mono<Void> deleteProduct(int productId) {
		if (productId < 1) {
			throw new InvalidInputException("productId inválido: " + productId);
		}
		LOGGER.debug("deleteProduct: eliminando producto con productId: {}", productId);
		return repository.findByProductId(productId)
				.log(LOGGER.getName(), Level.FINE)
				.map(e -> repository.delete(e))
				.flatMap(e -> e);
	}

	private ProductDto setServiceAddress(ProductDto e) {
		e.setServiceAddress(serviceUtil.getServiceAddress());
		return e;
	}
}
