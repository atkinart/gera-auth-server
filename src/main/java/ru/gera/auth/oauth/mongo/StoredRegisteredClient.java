package ru.gera.auth.oauth.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("oauth2_registered_client")
public class StoredRegisteredClient {

    @Id
    private String id;

    @Indexed(unique = true)
    private String clientId;

    private String payload;

    public StoredRegisteredClient() {
    }

    public StoredRegisteredClient(String id, String clientId, String payload) {
        this.id = id;
        this.clientId = clientId;
        this.payload = payload;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
