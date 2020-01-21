package eu.seal.as.model.pojo;

public class ErrorCodeMessage {
	
	private String code;
	private String message;
	
	public ErrorCodeMessage() {
		
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String toString() {
		return "error{" +
               "code='" + code + '\'' +
               ", message='" + message + '\'' +
               '}';
	}

}
