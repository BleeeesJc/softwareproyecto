package bo.edu.ucb.microservices.core.msreview.mapper;

import java.util.List;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;

import bo.edu.ucb.microservices.core.msreview.model.Review;
import bo.edu.ucb.microservices.dto.review.ReviewDto;

@Mapper(componentModel = "spring")
public interface ReviewMapper {

	@Mappings({ @Mapping(target = "serviceAddress", ignore = true) })
	ReviewDto entityToDto(Review entity);

	@Mappings({ @Mapping(target = "id", ignore = true), @Mapping(target = "version", ignore = true) })
	Review dtoToEntity(ReviewDto dto);

	List<ReviewDto> entityListToDtoList(List<Review> entity);

	List<Review> dtoListToEntityList(List<Review> dto);
}
