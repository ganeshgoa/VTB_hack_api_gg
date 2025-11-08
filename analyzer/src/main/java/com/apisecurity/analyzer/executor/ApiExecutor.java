// com.apisecurity.analyzer.executor/ApiExecutor.java
package com.apisecurity.analyzer.executor;

import com.apisecurity.analyzer.context.ExecutionContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ApiExecutor {

    private final String baseUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String accessToken = null;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    public ApiExecutor(String baseUrl) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    // === ПОЛУЧЕНИЕ ТОКЕНА ===

    public boolean obtainToken(JsonNode spec, ExecutionContext ctx) {
        TokenEndpointFinder finder = new TokenEndpointFinder();
        TokenEndpointFinder.TokenEndpoint tokenEp = finder.findTokenEndpoint(spec);

        if (tokenEp == null) {
            System.err.println("❌ No token endpoint found in spec.");
            return false;
        }

        // Собираем параметры
        Map<String, String> tokenParams = new HashMap<>();
        for (String paramName : tokenEp.requiredParams.keySet()) {
            if (ctx.has(paramName)) {
                tokenParams.put(paramName, ctx.get(paramName).toString());
            } else {
                System.err.println("⚠️ Missing param for token: " + paramName);
                return false;
            }
        }

        // Формируем URL
        String url = this.baseUrl + tokenEp.path;
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : tokenParams.entrySet()) {
            if (query.length() > 0) query.append("&");
            query.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                 .append("=")
                 .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        if (query.length() > 0) {
            url += "?" + query;
        }

        // Выполняем POST
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode tokenRes = objectMapper.readTree(response.body());
                if (tokenRes.has("access_token")) {
                    this.accessToken = tokenRes.get("access_token").asText();
                    System.out.println("✅ Token obtained successfully.");
                    return true;
                } else {
                    System.err.println("❌ No 'access_token' in response: " + response.body());
                }
            } else {
                System.err.println("❌ Token request failed: " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("❌ Error obtaining token: " + e.getMessage());
        }
        return false;
    }

    // === ВЫЗОВ ЛЮБОГО ЭНДПОИНТА ===

    public ApiCallResult callEndpoint(String method, String path, ExecutionContext ctx) {
        String url = buildUrl(path, ctx);

        try {
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .method(method.toUpperCase(), HttpRequest.BodyPublishers.noBody());

            // Добавляем токен, если есть
            if (this.accessToken != null) {
                reqBuilder.header("Authorization", "Bearer " + this.accessToken);
            }

            // Добавляем другие параметры как заголовки (x-consent-id и т.д.)
            addHeadersFromContext(reqBuilder, ctx, path);

            HttpRequest request = reqBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            return new ApiCallResult(response.statusCode(), response.body());

        } catch (Exception e) {
            return new ApiCallResult(e);
        }
    }

    // === ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ===

    private String buildUrl(String path, ExecutionContext ctx) {
        String url = this.baseUrl + path;
        // Подставляем path-параметры: /accounts/{account_id} → /accounts/acc-123
        for (String key : ctx.getKeys()) {
            String placeholder = "{" + key + "}";
            if (url.contains(placeholder)) {
                url = url.replace(placeholder, ctx.get(key).toString());
            }
        }
        return url;
    }

    private void addHeadersFromContext(HttpRequest.Builder builder, ExecutionContext ctx, String path) {
        // Пример: x-consent-id, x-requesting-bank
        for (String key : ctx.getKeys()) {
            if (key.startsWith("x-")) {
                builder.header(key, ctx.get(key).toString());
            }
        }
    }

    public String getAccessToken() {
        return this.accessToken;
    }
}