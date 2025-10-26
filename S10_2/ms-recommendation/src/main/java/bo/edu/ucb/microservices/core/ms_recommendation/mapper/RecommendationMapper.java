package bo.edu.ucb.microservices.core.ms_recommendation.mapper;

import java.util.List;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;

import bo.edu.ucb.microservices.core.ms_recommendation.model.Recommendation;
import bo.edu.ucb.microservices.dto.recommendation.RecommendationDto;

@Mapper(componentModel = "spring")
public interface RecommendationMapper {
	  @Mappings({
	    @Mapping(target = "rate", source = "entity.rating"),
	    @Mapping(target = "serviceAddress", ignore = true)
	  })
	  RecommendationDto entityToDto(Recommendation entity);

	  @Mappings({
	    @Mapping(target = "rating", source = "dto.rate"),
	    @Mapping(target = "id", ignore = true),
	    @Mapping(target = "version", ignore = true)
	  })
	  Recommendation dtoToEntity(RecommendationDto dto);

	  List<RecommendationDto> entityListToDtoList(List<Recommendation> entity);

	  List<Recommendation> dtoListToEntityList(List<RecommendationDto> dto);
}
