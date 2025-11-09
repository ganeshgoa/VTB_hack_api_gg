package com.apisecurity.analyzer.executor;

import com.apisecurity.analyzer.context.ExecutionContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ApiExecutor {

    private final String baseUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String accessToken = null;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private static final String REQUESTS_LOG_FILE = "reports/dynamic-requests.log";
    private final List<String> requestLog = new ArrayList<>();

    private void logRequestResponse(String method, String url, Map<String, String> requestHeaders,
                                    String requestBody,
                                    int statusCode, String responseBody) {
        StringBuilder logEntry = new StringBuilder();
        logEntry.append("# ").append(new Date()).append("\n");

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

        logEntry.append("### RESPONSE (").append(statusCode).append(")\n");
        if (responseBody != null) {
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

    public void saveRequestLog() {
        if (requestLog.isEmpty()) return;
        try {
            Files.createDirectories(Paths.get("reports"));
            Files.write(Paths.get(REQUESTS_LOG_FILE), requestLog,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.out.println("Dynamic requests logged to: " + REQUESTS_LOG_FILE);
        } catch (IOException e) {
            System.err.println("Failed to write request log: " + e.getMessage());
        }
    }

    public ApiExecutor(String baseUrl) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    // === СТАРЫЙ МЕТОД: получение токена через ExecutionContext ===
    public boolean obtainToken(JsonNode spec, ExecutionContext ctx) {
        TokenEndpointFinder finder = new TokenEndpointFinder();
        TokenEndpointFinder.TokenEndpoint tokenEp = finder.findTokenEndpoint(spec);

        if (tokenEp == null) {
            System.err.println("No token endpoint found in spec.");
            return false;
        }

        Map<String, String> tokenParams = new HashMap<>();
        for (String paramName : tokenEp.requiredParams.keySet()) {
            if (ctx.has(paramName)) {
                tokenParams.put(paramName, ctx.get(paramName).toString());
            } else {
                System.err.println("Missing param for token: " + paramName);
                return false;
            }
        }

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

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logRequestResponse("POST", url, Map.of(), "", response.statusCode(), response.body());

            if (response.statusCode() == 200) {
                JsonNode tokenRes = objectMapper.readTree(response.body());
                if (tokenRes.has("access_token")) {
                    this.accessToken = tokenRes.get("access_token").asText();
                    System.out.println("Token obtained successfully.");
                    return true;
                } else {
                    System.err.println("No 'access_token' in response: " + response.body());
                }
            } else {
                System.err.println("Token request failed: " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("Error obtaining token: " + e.getMessage());
        }
        return false;
    }

    // === НОВЫЙ МЕТОД: получение токена из params.json (для динамического тестирования) ===
public boolean obtainTokenFromParams(JsonNode spec) {
    TokenEndpointFinder finder = new TokenEndpointFinder();
    TokenEndpointFinder.TokenEndpoint tokenEp = finder.findTokenEndpoint(spec);

    if (tokenEp == null) {
        System.err.println("No token endpoint found in spec.");
        return false;
    }

    JsonNode params;
    try {
        params = objectMapper.readTree(Files.readAllBytes(Paths.get("params.json")));
    } catch (IOException e) {
        System.err.println("Failed to read params.json: " + e.getMessage());
        return false;
    }

    Map<String, String> tokenParams = new HashMap<>();
    for (String paramName : tokenEp.requiredParams.keySet()) {
        if (params.has(paramName)) {
            JsonNode values = params.get(paramName);
            if (values.isArray() && values.size() > 0) {
                tokenParams.put(paramName, values.get(0).asText());
            } else {
                System.err.println("Parameter '" + paramName + "' in params.json is not a non-empty array");
                return false;
            }
        } else {
            System.err.println("Required token param '" + paramName + "' not found in params.json");
            return false;
        }
    }

    // 🔴 ИСПРАВЛЕНО: собираем URL как baseUrl + path, НЕ используем tokenEp.url
    String tokenUrl = this.baseUrl + tokenEp.path;

    String formData = tokenParams.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" +
                   URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(tokenUrl)) 
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(formData, StandardCharsets.UTF_8))
        .build();

    try {
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        logRequestResponse("POST", tokenUrl,  
            Map.of("Content-Type", "application/x-www-form-urlencoded"),
            formData, response.statusCode(), response.body());

        if (response.statusCode() == 200) {
            JsonNode tokenResponse = objectMapper.readTree(response.body());
            if (tokenResponse.has("access_token")) {
                this.accessToken = tokenResponse.get("access_token").asText();
                System.out.println("Token from params.json obtained successfully.");
                return true;
            } else {
                System.err.println("Token response missing 'access_token'");
            }
        } else {
            System.err.println("Token request failed: " + response.statusCode());
        }
    } catch (Exception e) {
        System.err.println("Exception during token request from params.json: " + e.getMessage());
    }
    return false;
}

    // === СТАРЫЕ МЕТОДЫ ДЛЯ СОВМЕСТИМОСТИ ===

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

            int statusCode = response.statusCode();
            String responseBody = response.body();

            Map<String, String> requestHeaders = new HashMap<>();
            if (this.accessToken != null) {
                requestHeaders.put("Authorization", "Bearer " + this.accessToken);
            }
            for (String key : ctx.getKeys()) {
                if (key.startsWith("x-")) {
                    requestHeaders.put(key, ctx.get(key).toString());
                }
            }

            logRequestResponse(method, url, requestHeaders, null, statusCode, responseBody);
            return new ApiCallResult(statusCode, responseBody);

        } catch (Exception e) {
            return new ApiCallResult(e);
        }
    }

    public ApiCallResult callEndpointWithBody(String method, String path, JsonNode body, ExecutionContext ctx) {
        String url = buildUrl(path, ctx);
        try {
            String requestBody = body != null ? body.toString() : null;
            HttpRequest.BodyPublisher bodyPublisher = requestBody != null
                ? HttpRequest.BodyPublishers.ofString(requestBody)
                : HttpRequest.BodyPublishers.noBody();

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .method(method.toUpperCase(), bodyPublisher)
                .header("Content-Type", "application/json");

            if (this.accessToken != null) {
                reqBuilder.header("Authorization", "Bearer " + this.accessToken);
            }
            addHeadersFromContext(reqBuilder, ctx, path);

            HttpRequest request = reqBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            int statusCode = response.statusCode();
            String responseBody = response.body();

            Map<String, String> requestHeaders = new HashMap<>();
            requestHeaders.put("Content-Type", "application/json");
            if (this.accessToken != null) {
                requestHeaders.put("Authorization", "Bearer " + this.accessToken);
            }
            for (String key : ctx.getKeys()) {
                if (key.startsWith("x-")) {
                    requestHeaders.put(key, ctx.get(key).toString());
                }
            }

            logRequestResponse(method, url, requestHeaders, requestBody, statusCode, responseBody);
            return new ApiCallResult(statusCode, responseBody);

        } catch (Exception e) {
            return new ApiCallResult(e);
        }
    }

    private String buildUrl(String path, ExecutionContext ctx) {
        String url = this.baseUrl + path;
        for (String key : ctx.getKeys()) {
            String placeholder = "{" + key + "}";
            if (url.contains(placeholder)) {
                url = url.replace(placeholder, ctx.get(key).toString());
            }
        }
        return url;
    }

    private void addHeadersFromContext(HttpRequest.Builder builder, ExecutionContext ctx, String path) {
        for (String key : ctx.getKeys()) {
            if (key.startsWith("x-")) {
                builder.header(key, ctx.get(key).toString());
            }
        }
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    // === НОВЫЙ МЕТОД: executeRequest (для прямого вызова с pathParams и requestBody) ===
    public ApiCallResult executeRequest(String method, String path, Map<String, String> pathParams,
                                        ObjectNode requestBody) {
        String url = baseUrl + path;
        for (Map.Entry<String, String> param : pathParams.entrySet()) {
            url = url.replace("{" + param.getKey() + "}",
                URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8));
        }

        Map<String, String> headers = new HashMap<>();
        if (accessToken != null) {
            headers.put("Authorization", "Bearer " + accessToken);
        }
        headers.put("Content-Type", "application/json");

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .headers(headers.entrySet().stream()
                .flatMap(e -> Stream.of(e.getKey(), e.getValue()))
                .toArray(String[]::new));

        String bodyStr = null;
        if (requestBody != null) {
            bodyStr = requestBody.toString();
            requestBuilder = requestBuilder.method(method, HttpRequest.BodyPublishers.ofString(bodyStr));
        } else {
            if ("POST".equals(method) || "PUT".equals(method)) {
                requestBuilder = requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            } else {
                requestBuilder = requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            }
        }

        try {
            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            logRequestResponse(method, url, headers, bodyStr, response.statusCode(), response.body());
            return new ApiCallResult(response.statusCode(), response.body());
        } catch (Exception e) {
            return new ApiCallResult(e);
        }
    }
}