import java.util.Arrays;

public class SecurityOptions {
	public boolean confidentiality;
	public boolean integrity;
	public boolean authentication;

	/**
	 * 
	 */
	public SecurityOptions() {
	};

	/**
	 * @param confidentiality
	 * @param integrity
	 * @param authentication
	 */
	public SecurityOptions(boolean confidentiality, boolean integrity, boolean authentication) {
		this.confidentiality = confidentiality;
		this.integrity = integrity;
		this.authentication = authentication;
	}

	/**
	 * @param options
	 * @return
	 */
	public boolean compare(SecurityOptions options) {
		return confidentiality == options.confidentiality && integrity == options.integrity
				&& authentication == options.authentication;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		String str = "";
		for (boolean v : Arrays.asList(confidentiality, integrity, authentication)) {
			str += v ? "T" : "F";
		}
		return str;
	}
}
