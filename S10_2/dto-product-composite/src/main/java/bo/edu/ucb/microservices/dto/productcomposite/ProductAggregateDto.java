package bo.edu.ucb.microservices.dto.productcomposite;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class ProductAggregateDto {
	@Schema(description = "Identificador del producto", example = "1")
	private int productId;
	
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 50, message = "El nombre debe tener entre 3 y 50 caracteres")
    @Schema(description = "Nombre del producto", example = "1")
	private String name;
    
    @NotNull(message = "El peso es ser nula")
    @Schema(description = "Peso del producto", example = "1")
	private int weight;
    
    @Schema(description="Lista de recomendaciones del producto")
	private List<RecommendationSummaryDto> recommendations;
    
    @Schema(description="Lista de reseñas del producto")
	private List<ReviewSummaryDto> reviews;
    
	private ServiceAddressesDto serviceAddresses;

	public ProductAggregateDto() {

	}

	public ProductAggregateDto(int productId, String name, int weight, List<RecommendationSummaryDto> recommendations,
			List<ReviewSummaryDto> reviews, ServiceAddressesDto serviceAddresses) {
		super();
		this.productId = productId;
		this.name = name;
		this.weight = weight;
		this.recommendations = recommendations;
		this.reviews = reviews;
		this.serviceAddresses = serviceAddresses;
	}

	public int getProductId() {
		return productId;
	}

	public void setProductId(int productId) {
		this.productId = productId;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getWeight() {
		return weight;
	}

	public void setWeight(int weight) {
		this.weight = weight;
	}

	public List<RecommendationSummaryDto> getRecommendations() {
		return recommendations;
	}

	public void setRecommendations(List<RecommendationSummaryDto> recommendations) {
		this.recommendations = recommendations;
	}

	public List<ReviewSummaryDto> getReviews() {
		return reviews;
	}

	public void setReviews(List<ReviewSummaryDto> reviews) {
		this.reviews = reviews;
	}

	public ServiceAddressesDto getServiceAddresses() {
		return serviceAddresses;
	}

	public void setServiceAddresses(ServiceAddressesDto serviceAddresses) {
		this.serviceAddresses = serviceAddresses;
	}

	@Override
	public String toString() {
		return "ProductAggregateDto [productId=" + productId + ", name=" + name + ", weight=" + weight
				+ ", recommendations=" + recommendations + ", reviews=" + reviews + ", serviceAddresses="
				+ serviceAddresses + "]";
	}
}