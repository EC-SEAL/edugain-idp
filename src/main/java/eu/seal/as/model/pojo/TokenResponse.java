package eu.seal.as.model.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenResponse {
	
	private String success;
	private String timestamp;
	@JsonProperty("OAuth")
	private OAuth oauth;
	private ErrorCodeMessage error;
	
	public TokenResponse() {
		
	}

	public String getSuccess() {
		return success;
	}

	public void setSuccess(String success) {
		this.success = success;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public OAuth getOauth() {
		return oauth;
	}

	public void setOauth(OAuth oauth) {
		this.oauth = oauth;
	}
	
	public ErrorCodeMessage getError() {
		return error;
	}

	public void setError(ErrorCodeMessage error) {
		this.error = error;
	}

	@Override
	public String toString() {
		return "TokenResponse{" +
               "success='" + success + '\'' +
               ", timestamp='" + timestamp + '\'' +
               ", OAuth=" + oauth +
               ", error=" + error +
               '}';
	}
	
}
