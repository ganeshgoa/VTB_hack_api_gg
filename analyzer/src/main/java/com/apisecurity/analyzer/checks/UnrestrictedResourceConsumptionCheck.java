// com.apisecurity.analyzer.checks/UnrestrictedResourceConsumptionCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class UnrestrictedResourceConsumptionCheck implements SecurityCheck {

    // Ключевые слова, указывающие на рискованные операции
    private static final Set<String> RISKY_OPERATION_KEYWORDS = Set.of(
        "upload", "download", "file", "sms", "email", "otp", "reset_password",
        "forgot", "recovery", "batch", "graphql", "export", "import", "report",
        "thumbnail", "resize", "process", "validate", "third_party"
    );

    // Параметры, контролирующие объём данных
    private static final Set<String> PAGINATION_PARAMS = Set.of("limit", "size", "count", "per_page");
    private static final Set<String> OFFSET_PARAMS = Set.of("offset", "page", "start");

    @Override
    public String getName() {
        return "UnrestrictedResourceConsumption";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Unrestricted Resource Consumption (API4:2023)...");

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
                if (!"get".equals(method) && !"post".equals(method) && !"put".equals(method) &&
                    !"patch".equals(method) && !"delete".equals(method)) {
                    continue;
                }

                JsonNode operation = pathItem.get(method);
                String endpointName = method.toUpperCase() + " " + path;

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");
                boolean vulnerable = false;

                // === 1. Отсутствие упоминаний rate limiting ===
                // проверяем rate limiting ТОЛЬКО для критичных эндпоинтов:
                if (isHighRiskEndpoint(path, operation) && !hasRateLimitingMention(operation)) {
                    result.addFinding("High-risk endpoint lacks rate limiting — vulnerable to brute force or resource exhaustion");
                    result.addDetail("risk_level", "HIGH");
                    result.addDetail("cwe", "CWE-799");
                    vulnerable = true;
                }

                // === 2. Операции, требующие ограничений (upload, sms и т.д.) ===
                if (isRiskyOperation(path, operation)) {
                    // a) Upload без ограничения размера
                    if (isFileUploadOperation(operation) && !hasFileSizeLimitMention(operation)) {
                        result.addFinding("File upload operation lacks size limit — vulnerable to storage exhaustion");
                        result.addDetail("risk_level", "HIGH");
                        result.addDetail("cwe", "CWE-770"); // Allocation of Resources Without Limits
                        vulnerable = true;
                    }

                    // b) Third-party вызовы без spending limit
                    if (isThirdPartyOperation(operation) && !hasSpendingLimitMention(operation)) {
                        result.addFinding("Third-party integration (SMS/email) lacks spending limit — can cause financial loss");
                        result.addDetail("risk_level", "HIGH");
                        result.addDetail("cwe", "CWE-400"); // Uncontrolled Resource Consumption
                        vulnerable = true;
                    }

                    // c) GraphQL batching без ограничений
                    if (isGraphQLEndpoint(path) && !hasBatchingLimitMention(operation)) {
                        result.addFinding("GraphQL endpoint allows unlimited batching — vulnerable to DoS");
                        result.addDetail("risk_level", "HIGH");
                        result.addDetail("cwe", "CWE-400");
                        vulnerable = true;
                    }
                }

                // === 3. Пагинация без ограничения limit ===
                if (hasPaginationParameter(operation) && !hasLimitRestrictionMention(operation)) {
                    result.addFinding("Pagination parameter (e.g., 'limit') is not restricted — can cause large response DoS");
                    result.addDetail("risk_level", "MEDIUM");
                    result.addDetail("cwe", "CWE-770");
                    vulnerable = true;
                }

                // === 4. Отсутствие ограничений в теле запроса (массивы, вложенные объекты) ===
                if (hasUnboundedRequestBody(operation)) {
                    result.addFinding("Request body may contain unbounded arrays/objects — risk of CPU/memory exhaustion");
                    result.addDetail("risk_level", "MEDIUM");
                    result.addDetail("cwe", "CWE-400");
                    vulnerable = true;
                }

                if (vulnerable) {
                    result.addDetail("owasp_category", "API4:2023 - Unrestricted Resource Consumption");
                    container.addAnalyzerResult(endpointName + "_urc", result);
                    foundIssues = true;
                }

                if (analysis != null) {
                    analysis.setAnalyzer(
                        vulnerable
                            ? "Unrestricted resource consumption issues suspected"
                            : "No issues detected"
                    );
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints show signs of unrestricted resource consumption"
            : "No unrestricted resource consumption issues detected");
        container.addAnalyzerResult("urc_global", globalResult);

        System.out.println("  ✅ Unrestricted Resource Consumption check completed. " +
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

    private boolean hasRateLimitingMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("rate") || text.contains("limit") || text.contains("throttle") ||
               text.contains("quota") || text.contains("max request") || text.contains("per minute") ||
               text.contains("per second") || text.contains("rps") || text.contains("rpm");
    }

    private boolean isRiskyOperation(String path, JsonNode operation) {
        String text = path.toLowerCase() + " " + getTextFromOperation(operation);
        return RISKY_OPERATION_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isFileUploadOperation(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("upload") || text.contains("file") || text.contains("multipart");
    }

    private boolean hasFileSizeLimitMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("max size") || text.contains("file size") || text.contains("limit") ||
               text.contains("mb") || text.contains("kb") || text.contains("byte");
    }

    private boolean isThirdPartyOperation(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("sms") || text.contains("email") || text.contains("phone") ||
               text.contains("otp") || text.contains("third party") || text.contains("external");
    }

    private boolean hasSpendingLimitMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("spending limit") || text.contains("cost limit") || text.contains("budget") ||
               text.contains("alert") || text.contains("billing") || text.contains("charge");
    }

    private boolean isGraphQLEndpoint(String path) {
        return path.toLowerCase().contains("graphql");
    }

    private boolean hasBatchingLimitMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("batch") && (text.contains("limit") || text.contains("max"));
    }

    private boolean hasPaginationParameter(JsonNode operation) {
        JsonNode parameters = operation.get("parameters");
        if (parameters != null && parameters.isArray()) {
            for (JsonNode param : parameters) {
                String name = param.has("name") ? param.get("name").asText().toLowerCase() : "";
                if (PAGINATION_PARAMS.contains(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasLimitRestrictionMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("max limit") || text.contains("restricted") || text.contains("capped") ||
               (text.contains("limit") && (text.contains("100") || text.contains("500") || text.contains("1000")));
    }

    private boolean hasUnboundedRequestBody(JsonNode operation) {
        // Простая эвристика: если в схеме есть массив без maxItems
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody != null) {
            JsonNode content = requestBody.get("content");
            if (content != null && content.has("application/json")) {
                JsonNode schema = content.get("application/json").get("schema");
                if (schema != null) {
                    return hasUnboundedArray(schema);
                }
            }
        }
        return false;
    }

    private boolean hasUnboundedArray(JsonNode schema) {
        if (schema.has("type") && "array".equals(schema.get("type").asText())) {
            // Если нет maxItems — потенциально неограничен
            return !schema.has("maxItems");
        }
        if (schema.has("properties")) {
            JsonNode props = schema.get("properties");
            for (Iterator<String> it = props.fieldNames(); it.hasNext(); ) {
                String fieldName = it.next();
                if (hasUnboundedArray(props.get(fieldName))) {
                    return true;
                }
            }
        }
        return false;
    }

    private String getTextFromOperation(JsonNode operation) {
        StringBuilder text = new StringBuilder();
        if (operation.has("summary")) text.append(operation.get("summary").asText()).append(" ");
        if (operation.has("description")) text.append(operation.get("description").asText()).append(" ");
        if (operation.has("operationId")) text.append(operation.get("operationId").asText()).append(" ");
        return text.toString().toLowerCase();
    }

    private boolean isHighRiskEndpoint(String path, JsonNode operation) {
        String text = (path + " " + getTextFromOperation(operation)).toLowerCase();
        return text.contains("login") || text.contains("auth") || text.contains("token") ||
               text.contains("forgot") || text.contains("reset") || text.contains("password") ||
               text.contains("sms") || text.contains("email") || text.contains("otp") ||
               text.contains("graphql") || text.contains("batch") || text.contains("upload");
    }
}