// com.apisecurity.analyzer.checks/BOLACheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import com.apisecurity.analyzer.context.DynamicContext;
public class BOLACheck implements SecurityCheck {

    @Override
    public String getName() {
        return "BOLA";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Broken Object Level Authorization (BOLA)...");

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            System.out.println("  ⚠️ No paths defined in spec.");
            return;
        }

        boolean foundAnyBOLA = false;

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

                // Пропускаем эндпоинты аутентификации (например, /auth/...)
                if (isAuthenticationEndpoint(path)) {
                    continue;
                }

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");

                if (hasObjectIdParameter(path, operation)) {
                    if (!hasSufficientAuthorization(operation, spec)) {
                        result.addFinding("Potential BOLA vulnerability: endpoint accesses resource by ID but lacks robust authorization checks");
                        result.addDetail("risk_level", "HIGH");
                        result.addDetail("owasp_category", "API1:2023 - Broken Object Level Authorization");
                        result.addDetail("parameter_hint", "Endpoint contains ID-like parameter");
                        foundAnyBOLA = true;
                    }
                }

                container.addAnalyzerResult(endpointName + "_bola", result);

                if (analysis != null) {
                    analysis.setAnalyzer(
                        result.getFindings().isEmpty()
                            ? "No BOLA issues detected"
                            : "BOLA vulnerability suspected"
                    );
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundAnyBOLA ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundAnyBOLA
            ? "One or more endpoints are potentially vulnerable to BOLA"
            : "No BOLA vulnerabilities detected");
        container.addAnalyzerResult("bola_global", globalResult);

        System.out.println("  ✅ BOLA check completed. " +
            (foundAnyBOLA ? "Vulnerabilities suspected." : "No issues found."));
    }

    // Пропускаем пути, связанные с аутентификацией
    private boolean isAuthenticationEndpoint(String path) {
        String lowerPath = path.toLowerCase();
        return lowerPath.contains("/auth") ||
               lowerPath.contains("/token") ||
               lowerPath.contains("/login") ||
               lowerPath.contains("/oauth") ||
               lowerPath.contains("/signin") ||
               lowerPath.contains("/jwks");
    }

    // Находит или создаёт EndpointAnalysis по endpointName (без setPath/setMethod)
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

    // Проверяет, содержит ли эндпоинт параметры, похожие на ID объекта (но не auth-параметры)
    private boolean hasObjectIdParameter(String path, JsonNode operation) {
        // 1. Путь содержит {xxxId} или {id}
        if (path.matches(".*/\\{[^}]*[iI][dD][^}]*\\}.*")) {
            return true;
        }

        // 2. Query или header параметры
        JsonNode parameters = operation.get("parameters");
        if (parameters != null && parameters.isArray()) {
            for (JsonNode param : parameters) {
                if (!param.has("name") || !param.has("in")) continue;
                String name = param.get("name").asText();
                String in = param.get("in").asText();
                if (("query".equals(in) || "header".equals(in)) && isIdLikeParameter(name)) {
                    return true;
                }
            }
        }

        // 3. Тело запроса (requestBody)
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody != null) {
            JsonNode content = requestBody.get("content");
            if (content != null && content.has("application/json")) {
                JsonNode schema = content.get("application/json").get("schema");
                if (schema != null) {
                    Set<String> fields = extractSchemaFieldNames(schema);
                    for (String field : fields) {
                        if (isIdLikeParameter(field)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    // Извлекает имена полей из схемы (только верхний уровень)
    private Set<String> extractSchemaFieldNames(JsonNode schema) {
        Set<String> fields = new HashSet<>();
        if (schema.has("properties")) {
            JsonNode props = schema.get("properties");
            Iterator<String> names = props.fieldNames();
            names.forEachRemaining(fields::add);
        }
        return fields;
    }

    // Определяет, является ли имя параметра "объектным ID", а не auth-метаданными
    private boolean isIdLikeParameter(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase().trim();

        boolean looksLikeObjectId =
            lower.equals("id") ||
            lower.endsWith("id") ||
            lower.contains("identifier") ||
            lower.matches(".*_id$");

        boolean isAuthOrSystemParam =
            lower.equals("client_secret") ||
            lower.equals("grant_type") ||
            lower.equals("scope") ||
            lower.equals("redirect_uri") ||
            lower.equals("code") ||
            lower.equals("refresh_token") ||
            lower.equals("access_token") ||
            lower.contains("token") ||
            lower.equals("audience") ||
            lower.equals("issuer") ||
            lower.equals("jti") ||
            lower.equals("nonce") ||
            lower.equals("state");

        return looksLikeObjectId && !isAuthOrSystemParam;
    }

    // Проверяет, указана ли авторизация (security) на уровне операции или спецификации
    private boolean hasSufficientAuthorization(JsonNode operation, JsonNode spec) {
        if (hasSecurityRequirement(operation)) {
            return true;
        }
        if (hasSecurityRequirement(spec)) {
            return true;
        }

        // Дополнительная эвристика: описание содержит слова о безопасности
        String summary = operation.has("summary") ? operation.get("summary").asText().toLowerCase() : "";
        String desc = operation.has("description") ? operation.get("description").asText().toLowerCase() : "";
        return summary.contains("admin") || desc.contains("owner") ||
               summary.contains("auth") || desc.contains("authorized") ||
               summary.contains("access control") || desc.contains("permission");
    }

    // Проверяет наличие непустого security-массива
    private boolean hasSecurityRequirement(JsonNode node) {
        JsonNode security = node.get("security");
        return security != null && security.isArray() && security.size() > 0;
    }
}