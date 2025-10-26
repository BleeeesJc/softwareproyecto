package bo.edu.ucb.microservices.dto.recommendation;

public class RecommendationDto {
	private int productId;
	private int recommendationId;
	private String author;
	private int rate;
	private String content;
	private String serviceAddress;

	public RecommendationDto() {
	}

	public RecommendationDto(int productId, int recommendationId, String author, int rate, String content,
			String serviceAddress) {
		super();
		this.productId = productId;
		this.recommendationId = recommendationId;
		this.author = author;
		this.rate = rate;
		this.content = content;
		this.serviceAddress = serviceAddress;
	}

	public int getProductId() {
		return productId;
	}

	public void setProductId(int productId) {
		this.productId = productId;
	}

	public int getRecommendationId() {
		return recommendationId;
	}

	public void setRecommendationId(int recommendationId) {
		this.recommendationId = recommendationId;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public int getRate() {
		return rate;
	}

	public void setRate(int rate) {
		this.rate = rate;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public String getServiceAddress() {
		return serviceAddress;
	}

	public void setServiceAddress(String serviceAddress) {
		this.serviceAddress = serviceAddress;
	}

	@Override
	public String toString() {
		return "RecommendationDto [productId=" + productId + ", recommendationId=" + recommendationId + ", author="
				+ author + ", rate=" + rate + ", content=" + content + ", serviceAddress=" + serviceAddress + "]";
	}
}
