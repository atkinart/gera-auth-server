package ru.gera.auth.oauth.mongo;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class MongoRegisteredClientRepository implements RegisteredClientRepository {

    private final StoredRegisteredClientRepository repository;

    public MongoRegisteredClientRepository(StoredRegisteredClientRepository repository) {
        this.repository = repository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        String payload = SerializedObjectCodec.serialize(registeredClient);
        repository.save(new StoredRegisteredClient(registeredClient.getId(), registeredClient.getClientId(), payload));
    }

    @Override
    public RegisteredClient findById(String id) {
        return repository.findById(id)
                .map(StoredRegisteredClient::getPayload)
                .map(payload -> SerializedObjectCodec.deserialize(payload, RegisteredClient.class))
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return repository.findByClientId(clientId)
                .map(StoredRegisteredClient::getPayload)
                .map(payload -> SerializedObjectCodec.deserialize(payload, RegisteredClient.class))
                .orElse(null);
    }
}
