package bo.edu.ucb.microservices.dto.product;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class ProductDto {
	@Schema(description = "Identificador del producto", example = "1")
	private int productId;
	
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 50, message = "El nombre debe tener entre 3 y 50 caracteres")
    @Schema(description = "Nombre del producto", example = "1")
	private String name;
    
    @NotNull(message = "El peso es ser nula")
    @Schema(description = "Peso del producto", example = "1")
	private int weight;
    
    private String serviceAddress;

	public ProductDto() {
	}

	public ProductDto(int productId, String name, int weight, String serviceAddress) {
		super();
		this.productId = productId;
		this.name = name;
		this.weight = weight;
		this.serviceAddress = serviceAddress;
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

	public String getServiceAddress() {
		return serviceAddress;
	}

	public void setServiceAddress(String serviceAddress) {
		this.serviceAddress = serviceAddress;
	}

	@Override
	public String toString() {
		return "ProductDto [productId=" + productId + ", name=" + name + ", weight=" + weight + ", serviceAddress="
				+ serviceAddress + "]";
	}

}