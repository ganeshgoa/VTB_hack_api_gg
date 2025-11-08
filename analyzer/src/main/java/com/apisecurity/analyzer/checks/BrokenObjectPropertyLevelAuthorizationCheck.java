// com.apisecurity.analyzer.checks/BrokenObjectPropertyLevelAuthorizationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class BrokenObjectPropertyLevelAuthorizationCheck implements SecurityCheck {

    // Поля, которые обычно НЕ должны возвращаться обычным пользователям
    private static final Set<String> SENSITIVE_RESPONSE_FIELDS = Set.of(
        "password", "pass", "secret", "token", "api_key", "apikey", "jwt",
        "email", "phone", "ssn", "tax_id", "dob", "date_of_birth",
        "address", "zip", "postal_code", "full_name", "first_name", "last_name",
        "internal_id", "user_id", "owner_id", "created_by", "updated_by",
        "ip_address", "device_id", "session_id", "balance", "account_number",
        "credit_card", "cvv", "expiry", "pan", "iban", "bic",
        "is_admin", "is_verified", "role", "permissions", "scopes",
        "recent_location", "location", "coordinates", "geolocation",
        "blocked", "suspended", "approved", "status", "internal_status",
        "total_stay_price", "price", "cost", "revenue"
    );

    // Поля, которые обычно НЕ должны приниматься от клиента (Mass Assignment)
    private static final Set<String> SENSITIVE_REQUEST_FIELDS = Set.of(
        "password", "pass", "secret", "token", "api_key", "apikey",
        "email", "phone", "role", "permissions", "scopes", "is_admin",
        "user_id", "owner_id", "created_by", "updated_by",
        "balance", "account_number", "credit_card", "cvv",
        "blocked", "suspended", "approved", "status", "internal_status",
        "total_stay_price", "price", "cost", "revenue",
        "id", "uuid", "internal_id"
    );

    @Override
    public String getName() {
        return "BrokenObjectPropertyLevelAuthorization";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Broken Object Property Level Authorization (API3:2023)...");

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

                // === 1. Excessive Data Exposure (чувствительные поля в ответе) ===
                Set<String> responseFields = extractResponseFields(operation);
                Set<String> sensitiveResponseFields = new HashSet<>();
                for (String field : responseFields) {
                    if (isSensitiveResponseField(field)) {
                        sensitiveResponseFields.add(field);
                    }
                }

                if (!sensitiveResponseFields.isEmpty()) {
                    result.addFinding("Excessive Data Exposure: endpoint returns sensitive fields: " + String.join(", ", sensitiveResponseFields));
                    result.addDetail("risk_level", "MEDIUM");
                    vulnerable = true;
                }

                // === 2. Mass Assignment (чувствительные поля в теле запроса) ===
                Set<String> requestFields = extractRequestBodyFields(operation);
                Set<String> sensitiveRequestFields = new HashSet<>();
                for (String field : requestFields) {
                    if (isSensitiveRequestField(field)) {
                        sensitiveRequestFields.add(field);
                    }
                }

                if (!sensitiveRequestFields.isEmpty()) {
                    // Только для методов, которые МОГУТ менять данные
                    if (!"get".equals(method) && !"delete".equals(method)) {
                        result.addFinding("Potential Mass Assignment: endpoint accepts sensitive/internal fields: " + String.join(", ", sensitiveRequestFields));
                        result.addDetail("risk_level", "HIGH");
                        vulnerable = true;
                    }
                }

                if (vulnerable) {
                    result.addDetail("owasp_category", "API3:2023 - Broken Object Property Level Authorization");
                    container.addAnalyzerResult(endpointName + "_bopla", result);
                    foundIssues = true;
                }

                if (analysis != null) {
                    analysis.setAnalyzer(
                        vulnerable
                            ? "Broken object property level authorization issues suspected"
                            : "No issues detected"
                    );
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints show signs of broken object property level authorization"
            : "No broken object property level authorization issues detected");
        container.addAnalyzerResult("bopla_global", globalResult);

        System.out.println("  ✅ Broken Object Property Level Authorization check completed. " +
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

    private Set<String> extractResponseFields(JsonNode operation) {
        Set<String> fields = new HashSet<>();
        JsonNode responses = operation.get("responses");
        if (responses != null) {
            // Проверяем успешные ответы: 200, 201, etc.
            Iterator<String> statusCodes = responses.fieldNames();
            while (statusCodes.hasNext()) {
                String code = statusCodes.next();
                if (code.startsWith("2")) { // 2xx
                    JsonNode response = responses.get(code);
                    JsonNode content = response.get("content");
                    if (content != null) {
                        Iterator<String> mediaTypes = content.fieldNames();
                        while (mediaTypes.hasNext()) {
                            String mediaType = mediaTypes.next();
                            if (mediaType.contains("json")) {
                                JsonNode schema = content.get(mediaType).get("schema");
                                if (schema != null) {
                                    extractFieldsFromSchema(schema, fields);
                                }
                            }
                        }
                    }
                }
            }
        }
        return fields;
    }

    private Set<String> extractRequestBodyFields(JsonNode operation) {
        Set<String> fields = new HashSet<>();
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody != null) {
            JsonNode content = requestBody.get("content");
            if (content != null) {
                Iterator<String> mediaTypes = content.fieldNames();
                while (mediaTypes.hasNext()) {
                    String mediaType = mediaTypes.next();
                    if (mediaType.contains("json")) {
                        JsonNode schema = content.get(mediaType).get("schema");
                        if (schema != null) {
                            extractFieldsFromSchema(schema, fields);
                        }
                    }
                }
            }
        }
        return fields;
    }

    private void extractFieldsFromSchema(JsonNode schema, Set<String> fields) {
        if (schema.has("properties")) {
            JsonNode props = schema.get("properties");
            Iterator<String> names = props.fieldNames();
            names.forEachRemaining(fields::add);
        }
        // Простая рекурсия для вложенных объектов (ограничена)
        if (schema.has("type") && "object".equals(schema.get("type").asText())) {
            if (schema.has("additionalProperties")) {
                // Если additionalProperties: true — потенциальный Mass Assignment
                // Но пока пропустим
            }
        }
    }

    private boolean isSensitiveResponseField(String fieldName) {
        String lower = fieldName.toLowerCase();
        return SENSITIVE_RESPONSE_FIELDS.stream().anyMatch(lower::contains) ||
               SENSITIVE_RESPONSE_FIELDS.contains(lower);
    }

    private boolean isSensitiveRequestField(String fieldName) {
        String lower = fieldName.toLowerCase();
        return SENSITIVE_REQUEST_FIELDS.stream().anyMatch(lower::contains) ||
               SENSITIVE_REQUEST_FIELDS.contains(lower);
    }
}