// com.apisecurity.analyzer.checks/ServerSideRequestForgeryCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import com.apisecurity.analyzer.context.DynamicContext;
public class ServerSideRequestForgeryCheck implements SecurityCheck {

    // Имена параметров и полей, которые могут содержать URL/URI от клиента
    private static final Set<String> URL_LIKE_FIELD_NAMES = Set.of(
        "url", "uri", "link", "href", "picture_url", "image_url", "file_url", "avatar",
        "webhook", "callback", "redirect", "target", "endpoint", "location", "source",
        "import_from", "fetch_from", "remote_path", "external_url", "feed_url"
    );

    // Контекстные ключевые слова в пути или описании
    private static final Set<String> SSRF_CONTEXT_KEYWORDS = Set.of(
        "webhook", "fetch", "import", "download", "preview", "proxy", "avatar",
        "picture", "image", "file", "callback", "redirect", "integration"
    );

    // Слова, указывающие на защиту от SSRF
    private static final Set<String> SSRF_PROTECTION_KEYWORDS = Set.of(
        "whitelist", "allowlist", "blocklist", "denylist",
        "validate", "sanitize", "filter", "restrict", "internal", "localhost",
        "metadata", "169.254.169.254", "cloud", "ssrf", "firewall"
    );

    @Override
    public String getName() {
        return "ServerSideRequestForgery";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Server-Side Request Forgery (API7:2023)...");

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            System.out.println("  ⚠️ No paths defined in spec.");
            return;
        }

        boolean foundIssues = false;

        Iterator<Map.Entry<String, JsonNode>> pathIt = paths.fields();
        while (pathIt.hasNext()) {
            Map.Entry<String, JsonNode> pathEntry = pathIt.next();
            String path = pathEntry.getKey();
            JsonNode pathItem = pathEntry.getValue();

            Iterator<String> methodIt = pathItem.fieldNames();
            while (methodIt.hasNext()) {
                String method = methodIt.next().toLowerCase();
                if (!"post".equals(method) && !"put".equals(method) && !"patch".equals(method)) {
                    continue; // SSRF обычно в изменяющих запросах
                }

                JsonNode operation = pathItem.get(method);
                String endpointName = method.toUpperCase() + " " + path;

                // Проверяем, есть ли признаки SSRF-уязвимости
                boolean hasUrlParameter = hasUrlLikeParameter(operation);
                boolean hasSsrfContext = hasSsrfContext(path, operation);
                boolean hasProtection = hasSsrfProtectionMention(operation);

                if ((hasUrlParameter || hasSsrfContext) && !hasProtection) {
                    EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                    ModuleResult result = new ModuleResult("COMPLETED");

                    result.addFinding("Endpoint accepts user-supplied URLs without SSRF protection — vulnerable to internal service access or data exfiltration");
                    result.addDetail("risk_level", "HIGH");
                    result.addDetail("cwe", "CWE-918"); // Server-Side Request Forgery
                    result.addDetail("owasp_category", "API7:2023 - Server Side Request Forgery");
                    foundIssues = true;

                    container.addAnalyzerResult(endpointName + "_ssrf", result);

                    if (analysis != null) {
                        analysis.setAnalyzer("SSRF vulnerability suspected");
                    }
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints may be vulnerable to SSRF"
            : "No SSRF issues detected");
        container.addAnalyzerResult("ssrf_global", globalResult);

        System.out.println("  ✅ Server-Side Request Forgery check completed. " +
            (foundIssues ? "Vulnerabilities suspected." : "No issues found."));
    }

    // --- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ---

    private EndpointAnalysis findOrCreateAnalysis(ContainerApi container, String endpointName) {
        for (EndpointAnalysis ea : container.getAnalysisTable()) {
            if (endpointName.equals(ea.getEndpointName())) {
                return ea;
            }
        }
        EndpointAnalysis newAnalysis = new EndpointAnalysis();
        newAnalysis.setEndpointName(endpointName);
        container.addEndpointAnalysis(newAnalysis);
        return newAnalysis;
    }

    // Проверяет параметры (query, path, header) и тело запроса на наличие URL-подобных полей
    private boolean hasUrlLikeParameter(JsonNode operation) {
        // 1. Параметры (query, path, header)
        JsonNode parameters = operation.get("parameters");
        if (parameters != null && parameters.isArray()) {
            for (JsonNode param : parameters) {
                String name = param.has("name") ? param.get("name").asText().toLowerCase() : "";
                if (URL_LIKE_FIELD_NAMES.contains(name)) {
                    return true;
                }
            }
        }

        // 2. Тело запроса (requestBody)
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody != null) {
            Set<String> fields = extractRequestBodyFieldNames(requestBody);
            for (String field : fields) {
                if (URL_LIKE_FIELD_NAMES.contains(field.toLowerCase())) {
                    return true;
                }
            }
        }

        return false;
    }

    // Извлекает имена полей из тела запроса (JSON schema)
    private Set<String> extractRequestBodyFieldNames(JsonNode requestBody) {
        Set<String> fields = new HashSet<>();
        JsonNode content = requestBody.get("content");
        if (content != null) {
            Iterator<String> mediaTypes = content.fieldNames();
            while (mediaTypes.hasNext()) {
                String mediaType = mediaTypes.next();
                if (mediaType.contains("json")) {
                    JsonNode schema = content.get(mediaType).get("schema");
                    if (schema != null && schema.has("properties")) {
                        Iterator<String> propNames = schema.get("properties").fieldNames();
                        propNames.forEachRemaining(fields::add);
                    }
                }
            }
        }
        return fields;
    }

    // Проверяет, есть ли контекст SSRF в пути или описании
    private boolean hasSsrfContext(String path, JsonNode operation) {
        String text = (path + " " + getTextFromOperation(operation)).toLowerCase();
        return SSRF_CONTEXT_KEYWORDS.stream().anyMatch(text::contains);
    }

    // Проверяет, упоминается ли защита от SSRF
    private boolean hasSsrfProtectionMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return SSRF_PROTECTION_KEYWORDS.stream().anyMatch(text::contains);
    }

    private String getTextFromOperation(JsonNode operation) {
        StringBuilder sb = new StringBuilder();
        if (operation.has("summary")) sb.append(operation.get("summary").asText()).append(" ");
        if (operation.has("description")) sb.append(operation.get("description").asText()).append(" ");
        if (operation.has("operationId")) sb.append(operation.get("operationId").asText()).append(" ");
        return sb.toString().toLowerCase();
    }
}