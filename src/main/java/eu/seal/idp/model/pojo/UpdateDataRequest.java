package eu.seal.idp.model.pojo;

/**
 *
 * @author nikos
 */
public class UpdateDataRequest {

    private String sessionId;
    private String variableName;
    private String dataObject;

    public UpdateDataRequest() {
    }

    public UpdateDataRequest(String sessionId, String variableName, String dataObject) {
        this.sessionId = sessionId;
        this.variableName = variableName;
        this.dataObject = dataObject;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getVariableName() {
        return variableName;
    }

    public void setVariableName(String variableName) {
        this.variableName = variableName;
    }

    public String getDataObject() {
        return dataObject;
    }

    public void setDataObject(String dataObject) {
        this.dataObject = dataObject;
    }

}
