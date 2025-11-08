// com.apisecurity.analyzer.checks/BrokenFunctionLevelAuthorizationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class BrokenFunctionLevelAuthorizationCheck implements SecurityCheck {

    // Ключевые слова, указывающие на административные/чувствительные функции
    private static final Set<String> ADMIN_KEYWORDS = Set.of(
        "admin", "manage", "delete", "remove", "drop", "export", "import",
        "create", "update", "modify", "disable", "enable", "activate", "deactivate",
        "grant", "revoke", "permission", "role", "group", "user", "invite",
        "all", "bulk", "batch", "internal", "system", "setting", "config",
        "override", "force", "impersonate", "audit", "log", "debug"
    );

    // Опасные HTTP-методы для чувствительных операций
    private static final Set<String> DANGEROUS_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    @Override
    public String getName() {
        return "BrokenFunctionLevelAuthorization";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Broken Function Level Authorization (API5:2023)...");

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

                // === ПРОПУСКАЕМ обычные эндпоинты ===
                if (!isSensitiveOrAdminEndpoint(path, operation, method)) {
                    continue;
                }

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");
                boolean vulnerable = false;

                // === Проверка: есть ли авторизация? ===
                boolean hasAuth = hasSecurityRequirement(operation, spec) || 
                                  hasAuthorizationMention(operation);

                if (!hasAuth) {
                    result.addFinding("Sensitive/administrative endpoint lacks authorization checks — may be accessible to unauthorized users");
                    result.addDetail("risk_level", "HIGH");
                    result.addDetail("cwe", "CWE-285"); // Improper Authorization
                    result.addDetail("owasp_category", "API5:2023 - Broken Function Level Authorization");
                    vulnerable = true;
                    foundIssues = true;
                }

                if (vulnerable) {
                    container.addAnalyzerResult(endpointName + "_bfla", result);
                }

                if (analysis != null) {
                    analysis.setAnalyzer(
                        vulnerable
                            ? "Broken function level authorization suspected"
                            : "No issues detected"
                    );
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more sensitive endpoints lack authorization checks"
            : "No broken function level authorization issues detected");
        container.addAnalyzerResult("bfla_global", globalResult);

        System.out.println("  ✅ Broken Function Level Authorization check completed. " +
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

    // Определяет, является ли эндпоинт чувствительным/административным
    private boolean isSensitiveOrAdminEndpoint(String path, JsonNode operation, String method) {
        String pathLower = path.toLowerCase();
        String text = pathLower + " " + getTextFromOperation(operation);

        // 1. Путь содержит админ-ключевые слова
        boolean isAdminPath = ADMIN_KEYWORDS.stream().anyMatch(pathLower::contains);

        // 2. Операция использует опасный HTTP-метод И содержит чувствительные слова
        boolean isDangerousMethod = DANGEROUS_METHODS.contains(method.toUpperCase());
        boolean isDangerousAndSensitive = isDangerousMethod && ADMIN_KEYWORDS.stream().anyMatch(text::contains);

        // 3. Экспорт/импорт, управление пользователями, ролями
        boolean isManagement = text.contains("export") || text.contains("import") ||
                              text.contains("role") || text.contains("permission") ||
                              (text.contains("user") && (text.contains("all") || text.contains("list all")));

        // 4. Прямое упоминание "admin"
        boolean explicitAdmin = text.contains("admin");

        return explicitAdmin || isAdminPath || isDangerousAndSensitive || isManagement;
    }

    // Есть ли в OpenAPI security?
    private boolean hasSecurityRequirement(JsonNode operation, JsonNode spec) {
        JsonNode localSec = operation.get("security");
        if (localSec != null && localSec.isArray() && !localSec.isEmpty()) {
            return true;
        }
        JsonNode globalSec = spec.get("security");
        if (globalSec != null && globalSec.isArray() && !globalSec.isEmpty()) {
            return true;
        }
        return false;
    }

    // Есть ли упоминание авторизации в описании?
    private boolean hasAuthorizationMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return text.contains("auth") || text.contains("authorization") ||
               text.contains("role") || text.contains("admin") ||
               text.contains("permission") || text.contains("allowed") ||
               text.contains("restricted") || text.contains("privileged");
    }

    private String getTextFromOperation(JsonNode operation) {
        StringBuilder sb = new StringBuilder();
        if (operation.has("summary")) sb.append(operation.get("summary").asText()).append(" ");
        if (operation.has("description")) sb.append(operation.get("description").asText()).append(" ");
        if (operation.has("operationId")) sb.append(operation.get("operationId").asText()).append(" ");
        return sb.toString().toLowerCase();
    }
}