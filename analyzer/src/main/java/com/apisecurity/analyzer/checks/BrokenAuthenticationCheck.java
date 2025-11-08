// com.apisecurity.analyzer.checks/BrokenAuthenticationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.regex.Pattern;
import com.apisecurity.analyzer.context.DynamicContext;
public class BrokenAuthenticationCheck implements SecurityCheck {

    private static final Set<String> AUTH_PATH_KEYWORDS = Set.of(
        "login", "auth", "signin", "sign-in", "token", "oauth",
        "password", "forgot", "reset", "recovery", "credential"
    );

    private static final Set<String> SENSITIVE_PATH_SEGMENTS = Set.of(
        "account", "balance", "transaction", "payment", "profile",
        "user", "settings", "email", "phone", "2fa", "mfa", "admin"
    );

    private static final Pattern SENSITIVE_OPERATION_PATTERN = Pattern.compile(
        ".*(email|phone|password|2fa|mfa|security|delete|settings|profile).*",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() {
        return "BrokenAuthentication";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Broken Authentication (API2:2023)...");

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            System.out.println("  ⚠️ No paths defined in spec.");
            return;
        }

        boolean foundIssues = false;
        boolean hasAuthEndpoints = false;

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

                // === 1. Эндпоинт аутентификации? ===
                boolean isAuthEndpoint = isAuthenticationEndpoint(path);
                if (isAuthEndpoint) {
                    hasAuthEndpoints = true;

                    // GET с credentials в URL
                    if ("get".equals(method) && hasCredentialsInUrl(operation)) {
                        result.addFinding("Authentication via GET request — credentials exposed in URL/logs");
                        result.addDetail("risk_level", "HIGH");
                        vulnerable = true;
                    }

                    // Нет упоминаний защиты от брутфорса
                    if (!hasRateLimitingOrLockout(operation)) {
                        result.addFinding("Auth endpoint lacks rate limiting, lockout, or captcha — vulnerable to brute force");
                        result.addDetail("risk_level", "HIGH");
                        vulnerable = true;
                    }

                    // JWT: проверка по описанию (если есть)
                    if (mentionsJWT(operation)) {
                        if (!hasJwtExpirationCheck(operation)) {
                            result.addFinding("JWT tokens accepted without expiration validation");
                            result.addDetail("risk_level", "HIGH");
                            vulnerable = true;
                        }
                    }
                }

                // === 2. Чувствительный эндпоинт БЕЗ аутентификации ===
                boolean isSensitivePath = isSensitivePath(path);
                boolean hasSecurity = hasSecurityRequirement(operation, spec);

                if (isSensitivePath && !hasSecurity) {
                    result.addFinding("Sensitive endpoint (" + path + ") is not protected by authentication");
                    result.addDetail("risk_level", "HIGH");
                    vulnerable = true;
                }

                // === 3. Чувствительная операция без подтверждения пароля ===
                if (isSensitiveOperation(path) && !requiresPasswordConfirmation(operation)) {
                    result.addFinding("Sensitive operation does not require current password confirmation");
                    result.addDetail("risk_level", "HIGH");
                    vulnerable = true;
                }

                // === 4. API-ключ для пользовательской аутентификации ===
                if (usesApiKeyForUserAuth(operation, spec)) {
                    result.addFinding("API key is used for user authentication — API keys should only identify clients");
                    result.addDetail("risk_level", "MEDIUM");
                    vulnerable = true;
                }

                if (vulnerable) {
                    result.addDetail("owasp_category", "API2:2023 - Broken Authentication");
                    container.addAnalyzerResult(endpointName + "_auth", result);
                    foundIssues = true;
                }

                if (analysis != null) {
                    analysis.setAnalyzer(
                        vulnerable
                            ? "Broken authentication issues suspected"
                            : "No broken authentication issues detected"
                    );
                }
            }
        }

        // Глобальный результат
        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints show signs of broken authentication"
            : "No broken authentication issues detected");
        container.addAnalyzerResult("broken_auth_global", globalResult);

        System.out.println("  ✅ Broken Authentication check completed. " +
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

    private boolean isAuthenticationEndpoint(String path) {
        String p = path.toLowerCase();
        return AUTH_PATH_KEYWORDS.stream().anyMatch(p::contains);
    }

    private boolean isSensitivePath(String path) {
        String p = path.toLowerCase();
        return SENSITIVE_PATH_SEGMENTS.stream().anyMatch(p::contains);
    }

    private boolean isSensitiveOperation(String path) {
        return SENSITIVE_OPERATION_PATTERN.matcher(path).matches();
    }

    private boolean hasCredentialsInUrl(JsonNode operation) {
        JsonNode parameters = operation.get("parameters");
        if (parameters != null && parameters.isArray()) {
            for (JsonNode param : parameters) {
                String name = param.has("name") ? param.get("name").asText().toLowerCase() : "";
                String in = param.has("in") ? param.get("in").asText() : "";
                if ("query".equals(in)) {
                    if (name.contains("password") || name.contains("token") || name.equals("apikey")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean hasRateLimitingOrLockout(JsonNode operation) {
        String text = "";
        if (operation.has("summary")) text += operation.get("summary").asText().toLowerCase();
        if (operation.has("description")) text += operation.get("description").asText().toLowerCase();
        return text.contains("rate") || text.contains("limit") || text.contains("lock") ||
               text.contains("captcha") || text.contains("throttle") || text.contains("retry") ||
               text.contains("max attempt") || text.contains("brute");
    }

    private boolean mentionsJWT(JsonNode operation) {
        String text = "";
        if (operation.has("summary")) text += operation.get("summary").asText().toLowerCase();
        if (operation.has("description")) text += operation.get("description").asText().toLowerCase();
        return text.contains("jwt") || text.contains("bearer");
    }

    private boolean hasJwtExpirationCheck(JsonNode operation) {
        String text = "";
        if (operation.has("summary")) text += operation.get("summary").asText().toLowerCase();
        if (operation.has("description")) text += operation.get("description").asText().toLowerCase();
        return text.contains("exp") || text.contains("expiration");
    }

    private boolean requiresPasswordConfirmation(JsonNode operation) {
        String text = "";
        if (operation.has("summary")) text += operation.get("summary").asText().toLowerCase();
        if (operation.has("description")) text += operation.get("description").asText().toLowerCase();
        return text.contains("currentpassword") || text.contains("oldpassword") ||
               text.contains("confirmpassword") || text.contains("password confirmation");
    }

    private boolean hasSecurityRequirement(JsonNode operation, JsonNode spec) {
        // Локальная
        JsonNode localSec = operation.get("security");
        if (localSec != null && localSec.isArray() && !localSec.isEmpty()) {
            return true;
        }

        // Глобальная
        JsonNode globalSec = spec.get("security");
        if (globalSec != null && globalSec.isArray() && !globalSec.isEmpty()) {
            return true;
        }

        return false;
    }

    private boolean usesApiKeyForUserAuth(JsonNode operation, JsonNode spec) {
        JsonNode security = operation.get("security");
        if (security == null || !security.isArray() || security.isEmpty()) {
            security = spec.get("security"); // fallback to global
        }

        if (security == null || !security.isArray() || security.isEmpty()) {
            return false;
        }

        JsonNode components = spec.get("components");
        if (components == null || !components.has("securitySchemes")) {
            return false;
        }
        JsonNode schemes = components.get("securitySchemes");

        for (JsonNode secReq : security) {
            if (secReq.isObject()) {
                Iterator<String> names = secReq.fieldNames();
                while (names.hasNext()) {
                    String schemeName = names.next();
                    if (schemes.has(schemeName)) {
                        JsonNode scheme = schemes.get(schemeName);
                        if (scheme.has("type") && "apiKey".equals(scheme.get("type").asText())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}