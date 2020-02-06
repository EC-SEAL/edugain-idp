package eu.seal.idp.model.pojo;

import java.util.Map;

/**
 *
 * @author nikos
 */
public class MngrSessionTO {

    private String sessionId;
    private Map sessionVariables;

    public MngrSessionTO(String sessionId, Map sessionVariables) {
        this.sessionId = sessionId;
        this.sessionVariables = sessionVariables;
    }

    public MngrSessionTO() {
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Map getSessionVariables() {
        return sessionVariables;
    }

    public void setSessionVariables(Map sessionVariables) {
        this.sessionVariables = sessionVariables;
    }

}
