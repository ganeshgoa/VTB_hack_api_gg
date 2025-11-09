// com.apisecurity.analyzer.checks/BrokenObjectPropertyLevelAuthorizationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class BrokenObjectPropertyLevelAuthorizationCheck implements SecurityCheck {

    // Поля, которые обычно НЕ должны возвращаться обычным пользователям (Excessive Data Exposure)
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
    public void run(JsonNode spec, ContainerApi container, com.apisecurity.analyzer.context.DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Broken Object Property Level Authorization (API3:2023) — static analysis...");

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

                // === 1. Excessive Data Exposure (CWE-213) ===
                Set<String> responseFields = extractResponseFields(operation);
                Set<String> sensitiveResponseFields = new HashSet<>();
                for (String field : responseFields) {
                    if (isSensitiveResponseField(field)) {
                        sensitiveResponseFields.add(field);
                    }
                }

                if (!sensitiveResponseFields.isEmpty()) {
                    String finding = "Excessive Data Exposure: endpoint returns sensitive fields: " + String.join(", ", sensitiveResponseFields);
                    result.addFinding(finding);
                    result.addDetail("risk_level", "MEDIUM");
                    result.addDetail("cwe_id", "CWE-213");
                    result.addDetail("cwe_name", "Exposure of Sensitive Information Due to Incompatible Policies");
                    result.addDetail("owasp_category", "API3:2023 - Broken Object Property Level Authorization");
                    result.addDetail("remediation", "Avoid generic serialization (e.g., to_json()). Return only necessary fields. Validate that the user is authorized to access each returned property.");
                    vulnerable = true;
                }

                // === 2. Mass Assignment (CWE-915) ===
                if (!"get".equals(method) && !"delete".equals(method)) {
                    Set<String> requestFields = extractRequestBodyFields(operation);
                    Set<String> sensitiveRequestFields = new HashSet<>();
                    for (String field : requestFields) {
                        if (isSensitiveRequestField(field)) {
                            sensitiveRequestFields.add(field);
                        }
                    }

                    if (!sensitiveRequestFields.isEmpty()) {
                        String finding = "Potential Mass Assignment: endpoint accepts sensitive/internal fields: " + String.join(", ", sensitiveRequestFields);
                        result.addFinding(finding);
                        result.addDetail("risk_level", "HIGH");
                        result.addDetail("cwe_id", "CWE-915");
                        result.addDetail("cwe_name", "Improperly Controlled Modification of Dynamically-Determined Object Attributes");
                        result.addDetail("owasp_category", "API3:2023 - Broken Object Property Level Authorization");
                        result.addDetail("remediation", "Do not auto-bind client input to internal object properties. Use allowlists of permitted fields. Validate that the user is authorized to modify each property.");
                        vulnerable = true;
                    }
                }

                if (vulnerable) {
                    result.addDetail("dynamic_status", "STATIC_ONLY");
                    container.addAnalyzerResult(endpointName + "_bopla", result);
                    foundIssues = true;
                }

                if (analysis != null) {
                    String status = vulnerable
                        ? "BOPA issues suspected (static analysis)"
                        : "No BOPA issues detected";
                    analysis.setAnalyzer(status);
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints show signs of broken object property level authorization (static analysis)"
            : "No broken object property level authorization issues detected (static analysis)");
        globalResult.addDetail("owasp_category", "API3:2023 - Broken Object Property Level Authorization");
        globalResult.addDetail("cwe_references", "CWE-213, CWE-915");
        container.addAnalyzerResult("bopla_global", globalResult);

        System.out.println("  ✅ Broken Object Property Level Authorization check completed (static only). " +
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
        // Поддержка allOf, anyOf, oneOf
        for (String combiner : Arrays.asList("allOf", "anyOf", "oneOf")) {
            if (schema.has(combiner)) {
                for (JsonNode sub : schema.get(combiner)) {
                    extractFieldsFromSchema(sub, fields);
                }
            }
        }
    }

    private boolean isSensitiveResponseField(String fieldName) {
        String lower = fieldName.toLowerCase();
        return SENSITIVE_RESPONSE_FIELDS.contains(lower) ||
               SENSITIVE_RESPONSE_FIELDS.stream().anyMatch(lower::contains);
    }

    private boolean isSensitiveRequestField(String fieldName) {
        String lower = fieldName.toLowerCase();
        return SENSITIVE_REQUEST_FIELDS.contains(lower) ||
               SENSITIVE_REQUEST_FIELDS.stream().anyMatch(lower::contains);
    }
}