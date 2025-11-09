// com.apisecurity.analyzer.checks/UnrestrictedBusinessFlowAccessCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import com.apisecurity.analyzer.context.DynamicContext;
public class UnrestrictedBusinessFlowAccessCheck implements SecurityCheck {

    // Чувствительные бизнес-операции (требуют защиты от автоматизации)
    private static final Set<String> SENSITIVE_BUSINESS_ACTIONS = Set.of(
        // Покупки и оплата
        "purchase", "buy", "order", "checkout", "payment", "pay", "transaction",
        // Бронирование
        "reserve", "reservation", "booking", "appointment", "slot", "ticket", "seat", "flight",
        // Рефералы и кредиты
        "invite", "referral", "referral_code", "credit", "reward", "bonus", "gift",
        // Контент (риск спама)
        "comment", "post", "review", "rating", "submit", "create",
        // Регистрация (массовая)
        "register", "signup", "sign-up", "join", "enroll", "account",
        // Управление запасами/ценами
        "stock", "inventory", "auction", "bid", "offer", "deal", "promo", "discount", "price"
    );

    // Слова, исключающие эндпоинт из проверки (не бизнес-поток)
    private static final Set<String> EXCLUDED_CONTEXTS = Set.of(
        "auth", "login", "logout", "token", "oauth", "health", "jwks", "well-known",
        "validate", "verify", "confirm", "status", "info", "metadata", "version"
    );

    // Защитные механизмы (если упомянуты — уязвимость не срабатывает)
    private static final Set<String> PROTECTION_KEYWORDS = Set.of(
        "captcha", "bot", "automation", "fingerprint", "human", "headless",
        "rate limit", "throttle", "queue", "waiting", "delay", "slow",
        "tor", "proxy", "suspicious", "fraud", "abuse", "monitoring",
        "behavior", "pattern", "verification", "challenge", "recaptcha"
    );

    @Override
    public String getName() {
        return "UnrestrictedBusinessFlowAccess";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("Checking Unrestricted Access to Sensitive Business Flows (API6:2023)...");

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            System.out.println("No paths defined in spec.");
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
                // Только методы, изменяющие состояние
                if (!"post".equals(method) && !"put".equals(method) &&
                    !"patch".equals(method) && !"delete".equals(method)) {
                    continue;
                }

                JsonNode operation = pathItem.get(method);
                String endpointName = method.toUpperCase() + " " + path;

                // Пропускаем, если эндпоинт не участвует в чувствительном бизнес-потоке
                if (!isSensitiveBusinessFlowEndpoint(path, operation)) {
                    continue;
                }

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");
                boolean vulnerable = false;

                // Проверяем, упоминается ли защита от автоматизации
                if (!hasAutomationProtectionMention(operation)) {
                    result.addFinding("Sensitive business flow endpoint lacks protection against automated abuse (e.g., scalping, spam, reservation hoarding)");
                    result.addDetail("risk_level", "MEDIUM");
                    result.addDetail("owasp_category", "API6:2023 - Unrestricted Access to Sensitive Business Flows");
                    //result.addDetail("cwe", "CWE-837"); // Improper Enforcement of a Semantic Security Policy
                    vulnerable = true;
                    foundIssues = true;
                }

                if (vulnerable) {
                    container.addAnalyzerResult(endpointName + "_ubfa", result);
                }

                if (analysis != null) {
                    analysis.setAnalyzer(
                        vulnerable
                            ? "Unrestricted business flow access suspected"
                            : "No issues detected"
                    );
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints expose sensitive business flows without anti-automation measures"
            : "No unrestricted business flow access issues detected");
        container.addAnalyzerResult("ubfa_global", globalResult);

        System.out.println("Unrestricted Business Flow Access check completed. " +
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

    private boolean isSensitiveBusinessFlowEndpoint(String path, JsonNode operation) {
        String fullText = (path + " " + getTextFromOperation(operation)).toLowerCase();

        // Исключаем эндпоинты аутентификации, метаданных и т.д.
        if (EXCLUDED_CONTEXTS.stream().anyMatch(fullText::contains)) {
            return false;
        }

        // Должен содержать чувствительное действие
        return SENSITIVE_BUSINESS_ACTIONS.stream().anyMatch(fullText::contains);
    }

    private boolean hasAutomationProtectionMention(JsonNode operation) {
        String text = getTextFromOperation(operation);
        return PROTECTION_KEYWORDS.stream().anyMatch(text::contains);
    }

    private String getTextFromOperation(JsonNode operation) {
        StringBuilder sb = new StringBuilder();
        if (operation.has("summary")) sb.append(operation.get("summary").asText()).append(" ");
        if (operation.has("description")) sb.append(operation.get("description").asText()).append(" ");
        if (operation.has("operationId")) sb.append(operation.get("operationId").asText()).append(" ");
        return sb.toString().toLowerCase();
    }
}