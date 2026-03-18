package ru.gera.auth.oauth.mongo;

import org.springframework.util.SerializationUtils;

import java.io.Serializable;
import java.util.Base64;

final class SerializedObjectCodec {

    private SerializedObjectCodec() {
    }

    static String serialize(Serializable source) {
        byte[] bytes = SerializationUtils.serialize(source);
        if (bytes == null) {
            throw new IllegalStateException("Failed to serialize object");
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    static <T> T deserialize(String payload, Class<T> targetType) {
        byte[] bytes = Base64.getDecoder().decode(payload);
        Object value = SerializationUtils.deserialize(bytes);
        if (value == null) {
            throw new IllegalStateException("Failed to deserialize object");
        }
        return targetType.cast(value);
    }
}
