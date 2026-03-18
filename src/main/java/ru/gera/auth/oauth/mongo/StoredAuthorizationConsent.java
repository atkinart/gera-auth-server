package ru.gera.auth.oauth.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("oauth2_authorization_consent")
public class StoredAuthorizationConsent {

    @Id
    private String id;

    @Indexed
    private String registeredClientId;

    @Indexed
    private String principalName;

    private String payload;

    public StoredAuthorizationConsent() {
    }

    public StoredAuthorizationConsent(String id, String registeredClientId, String principalName, String payload) {
        this.id = id;
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
        this.payload = payload;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRegisteredClientId() {
        return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
