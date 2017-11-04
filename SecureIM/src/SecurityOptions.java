import java.util.Arrays;

public class SecurityOptions {
	public boolean confidentiality;
	public boolean integrity;
	public boolean authentication;

	public SecurityOptions() {
	};

	public SecurityOptions(boolean confidentiality, boolean integrity, boolean authentication) {
		this.confidentiality = confidentiality;
		this.integrity = integrity;
		this.authentication = authentication;
	}

	public boolean compare(SecurityOptions options) {
		return confidentiality == options.confidentiality && integrity == options.integrity
				&& authentication == options.authentication;
	}

	public String toString() {
		String str = "";
		for (boolean v : Arrays.asList(confidentiality, integrity, authentication)) {
			str += v ? "T" : "F";
		}
		return str;
	}
}
