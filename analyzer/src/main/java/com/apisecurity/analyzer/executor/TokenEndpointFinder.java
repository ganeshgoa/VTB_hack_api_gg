// com.apisecurity.analyzer.executor/TokenEndpointFinder.java
package com.apisecurity.analyzer.executor;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

/**
 * Находит эндпоинт получения токена (OAuth2 client_credentials) в OpenAPI.
 */
public class TokenEndpointFinder {

    public static class TokenEndpoint {
        public final String path;
        public final String method;
        public final Map<String, String> requiredParams; // name → in (query/form)

        public TokenEndpoint(String path, String method, Map<String, String> requiredParams) {
            this.path = path;
            this.method = method;
            this.requiredParams = requiredParams;
        }
    }

    public TokenEndpoint findTokenEndpoint(JsonNode spec) {
        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) return null;

        Iterator<Map.Entry<String, JsonNode>> pathIt = paths.fields();
        while (pathIt.hasNext()) {
            Map.Entry<String, JsonNode> entry = pathIt.next();
            String path = entry.getKey();
            JsonNode pathItem = entry.getValue();

            JsonNode postOp = pathItem.get("post");
            if (postOp == null) continue;

            // Ищем признаки токена: client_id + client_secret в query/form
            Set<String> foundParams = new HashSet<>();
            Map<String, String> paramLocations = new HashMap<>();

            JsonNode params = postOp.get("parameters");
            if (params != null && params.isArray()) {
                for (JsonNode param : params) {
                    String name = param.has("name") ? param.get("name").asText() : "";
                    String in = param.has("in") ? param.get("in").asText() : "";
                    if (("query".equals(in) || "formData".equals(in)) &&
                        ("client_id".equalsIgnoreCase(name) || "client_secret".equalsIgnoreCase(name))) {
                        foundParams.add(name.toLowerCase());
                        paramLocations.put(name.toLowerCase(), in);
                    }
                }
            }

            if (foundParams.contains("client_id") && foundParams.contains("client_secret")) {
                Map<String, String> required = new HashMap<>();
                required.put("client_id", paramLocations.get("client_id"));
                required.put("client_secret", paramLocations.get("client_secret"));
                return new TokenEndpoint(path, "post", required);
            }

            // Дополнительно: по описанию
            String summary = postOp.has("summary") ? postOp.get("summary").asText().toLowerCase() : "";
            String desc = postOp.has("description") ? postOp.get("description").asText().toLowerCase() : "";
            if ((summary.contains("token") || desc.contains("token")) &&
                (summary.contains("access") || desc.contains("access") || summary.contains("bearer"))) {
                Map<String, String> required = new HashMap<>();
                required.put("client_id", "query");
                required.put("client_secret", "query");
                return new TokenEndpoint(path, "post", required);
            }
        }
        return null;
    }
}