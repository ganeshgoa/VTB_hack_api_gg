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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.io.IOException;

public class ApiExecutor {

    private final String baseUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String accessToken = null;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    // В начале класса ApiExecutor:
    private static final String REQUESTS_LOG_FILE = "reports/dynamic-requests.log";
    private final List<String> requestLog = new ArrayList<>();

    // В конец класса ApiExecutor — метод для логирования
    private void logRequestResponse(String method, String url, Map<String, String> requestHeaders, 
                                    String requestBody, 
                                    int statusCode, String responseBody) {
        StringBuilder logEntry = new StringBuilder();
        logEntry.append("# ").append(new Date()).append("\n");
        
        // Запрос (curl)
        logEntry.append("### REQUEST\n");
        logEntry.append("curl -X ").append(method.toUpperCase()).append(" '").append(url).append("'");
        for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
            logEntry.append(" \\\n  -H '").append(header.getKey()).append(": ").append(header.getValue()).append("'");
        }
        if (requestBody != null && !requestBody.isEmpty()) {
            String safeBody = requestBody.replace("'", "'\"'\"'");
            logEntry.append(" \\\n  -d '").append(safeBody).append("'");
        }
        logEntry.append("\n\n");

        // Ответ
        logEntry.append("### RESPONSE (").append(statusCode).append(")\n");
        if (responseBody != null) {
            // Ограничиваем длину тела (чтобы не засорять лог)
            String trimmedBody = responseBody.length() > 1000 
                ? responseBody.substring(0, 1000) + "..." 
                : responseBody;
            logEntry.append(trimmedBody).append("\n");
        }
        logEntry.append("\n").append("=".repeat(80)).append("\n\n");

        synchronized (requestLog) {
            requestLog.add(logEntry.toString());
        }
    }

    // Метод для сохранения лога в файл (вызывать в конце анализа)
    public void saveRequestLog() {
        if (requestLog.isEmpty()) return;
        
        try {
            Files.createDirectories(Paths.get("reports"));
            Files.write(Paths.get(REQUESTS_LOG_FILE), requestLog, 
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.out.println("📝 Dynamic requests logged to: " + REQUESTS_LOG_FILE);
        } catch (IOException e) {
            System.err.println("❌ Failed to write request log: " + e.getMessage());
        }
    }

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

        if (this.accessToken != null) {
            reqBuilder.header("Authorization", "Bearer " + this.accessToken);
        }
        addHeadersFromContext(reqBuilder, ctx, path);

        HttpRequest request = reqBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // Только ПОСЛЕ получения ответа:
        int statusCode = response.statusCode();
        String responseBody = response.body();

        // Собираем заголовки запроса для лога
        Map<String, String> requestHeaders = new HashMap<>();
        if (this.accessToken != null) {
            requestHeaders.put("Authorization", "Bearer " + this.accessToken);
        }
        for (String key : ctx.getKeys()) {
            if (key.startsWith("x-")) {
                requestHeaders.put(key, ctx.get(key).toString());
            }
        }

        // Логируем ПОСЛЕ всего
        logRequestResponse(method, url, requestHeaders, null, statusCode, responseBody);

        return new ApiCallResult(statusCode, responseBody);

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