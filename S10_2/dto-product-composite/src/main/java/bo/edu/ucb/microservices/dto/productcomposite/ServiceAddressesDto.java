package bo.edu.ucb.microservices.dto.productcomposite;

public class ServiceAddressesDto {
	private String cmp;
	private String pro;
	private String rev;
	private String rec;

	public ServiceAddressesDto() {
	}

	public ServiceAddressesDto(String cmp, String pro, String rev, String rec) {
		super();
		this.cmp = cmp;
		this.pro = pro;
		this.rev = rev;
		this.rec = rec;
	}

	public String getCmp() {
		return cmp;
	}

	public void setCmp(String cmp) {
		this.cmp = cmp;
	}

	public String getPro() {
		return pro;
	}

	public void setPro(String pro) {
		this.pro = pro;
	}

	public String getRev() {
		return rev;
	}

	public void setRev(String rev) {
		this.rev = rev;
	}

	public String getRec() {
		return rec;
	}

	public void setRec(String rec) {
		this.rec = rec;
	}

	@Override
	public String toString() {
		return "ServiceAddresses [cmp=" + cmp + ", pro=" + pro + ", rev=" + rev + ", rec=" + rec + "]";
	}
}
