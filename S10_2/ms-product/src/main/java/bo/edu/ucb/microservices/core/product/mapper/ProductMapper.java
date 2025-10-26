package bo.edu.ucb.microservices.core.product.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;

import bo.edu.ucb.microservices.core.product.model.Product;
import bo.edu.ucb.microservices.dto.product.ProductDto;

@Mapper(componentModel = "spring")
public interface ProductMapper {
	@Mappings({
	    @Mapping(target = "serviceAddress", ignore = true)
	  })
	  ProductDto entityToDto(Product entity);

	  @Mappings({
	    @Mapping(target = "id", ignore = true), @Mapping(target = "version", ignore = true)
	  })
	  Product dtoToEntity(ProductDto dto);
}
