// com.apisecurity.analyzer.discovery/EndpointSignature.java
package com.apisecurity.analyzer.discovery;

import java.util.*;

/**
 * Сигнатура эндпоинта: что требует на входе, что возвращает на выходе.
 */
public class EndpointSignature {
    public final String path;
    public final String method;
    public final String operationId;

    // Входные параметры: имя → тип (path, query, header, body)
    public final Map<String, String> inputs = new LinkedHashMap<>();

    // Выходные поля (из 2xx-ответов)
    public final Set<String> outputs = new LinkedHashSet<>();

    public EndpointSignature(String path, String method, String operationId) {
        this.path = path;
        this.method = method;
        this.operationId = operationId;
    }

    @Override
    public String toString() {
        return String.format(
            "%s %s -> inputs: %s, outputs: %s",
            method.toUpperCase(), path, inputs.keySet(), outputs
        );
    }
}