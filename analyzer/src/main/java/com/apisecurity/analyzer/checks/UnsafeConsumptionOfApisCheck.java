// com.apisecurity.analyzer.checks/UnsafeConsumptionOfApisCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import com.apisecurity.analyzer.context.DynamicContext;
public class UnsafeConsumptionOfApisCheck implements SecurityCheck {

    // Ключевые слова, указывающие на интеграцию с внешними API
    private static final Set<String> INTEGRATION_KEYWORDS = Set.of(
        "third-party", "thirdparty", "external", "integration", "webhook",
        "import", "fetch", "pull", "sync", "provider", "service", "api",
        "forward", "proxy", "callback", "enrich", "partner"
    );

    // Ключевые слова, указывающие на защиту
    private static final Set<String> PROTECTION_KEYWORDS = Set.of(
        "validate", "sanitize", "filter", "escape", "encoding",
        "https", "tls", "ssl", "redirect", "follow", "timeout",
        "allowlist", "whitelist", "limit", "size", "max"
    );

    @Override
    public String getName() {
        return "UnsafeConsumptionOfApis";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Unsafe Consumption of APIs (API10:2023)...");

        String fullSpecText = spec.toString().toLowerCase();

        // Проверяем, есть ли вообще упоминания интеграций
        boolean hasIntegrationMention = INTEGRATION_KEYWORDS.stream()
            .anyMatch(fullSpecText::contains);

        if (!hasIntegrationMention) {
            // Нет признаков интеграций — пропускаем
            System.out.println("  ⚪ No third-party integrations mentioned — skipping detailed check.");
            ModuleResult globalResult = new ModuleResult("COMPLETED");
            globalResult.addDetail("summary", "No evidence of third-party API consumption");
            container.addAnalyzerResult("unsafe_consumption_global", globalResult);
            return;
        }

        boolean foundIssue = false;

        // === 1. Проверка: нет ли описания защиты? ===
        boolean hasProtection = PROTECTION_KEYWORDS.stream()
            .anyMatch(fullSpecText::contains);

        if (!hasProtection) {
            addGlobalFinding(
                "API mentions third-party integrations but lacks documentation on input validation, TLS, or redirect handling",
                "MEDIUM",
                "CWE-20", // Improper Input Validation
                container
            );
            foundIssue = true;
        }

        // === 2. Проверка HTTPS (глобально) ===
        if (!isHttpsEnforced(spec)) {
            addGlobalFinding(
                "API allows HTTP communication — unsafe for third-party integrations",
                "HIGH",
                "CWE-319", // Cleartext Transmission
                container
            );
            foundIssue = true;
        }

        ModuleResult globalResult = new ModuleResult(foundIssue ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssue
            ? "Potential unsafe consumption of APIs due to missing security documentation"
            : "Third-party integrations appear to be documented with security considerations");
        container.addAnalyzerResult("unsafe_consumption_global", globalResult);

        System.out.println("  ✅ Unsafe Consumption of APIs check completed. " +
            (foundIssue ? "Risks identified." : "No issues found."));
    }

    private void addGlobalFinding(String finding, String riskLevel, String cwe, ContainerApi container) {
        ModuleResult result = new ModuleResult("ISSUES_FOUND");
        result.addFinding(finding);
        result.addDetail("risk_level", riskLevel);
        result.addDetail("cwe", cwe);
        result.addDetail("owasp_category", "API10:2023 - Unsafe Consumption of APIs");
        String key = "unsafe_consumption_issue_" + System.currentTimeMillis();
        container.addAnalyzerResult(key, result);
    }

    // Проверка HTTPS (такая же, как в SecurityMisconfigurationCheck)
    private boolean isHttpsEnforced(JsonNode spec) {
        JsonNode servers = spec.get("servers");
        if (servers == null || !servers.isArray() || servers.isEmpty()) {
            return true; // неизвестно — не считаем уязвимостью
        }

        for (JsonNode server : servers) {
            if (server.has("url")) {
                String url = server.get("url").asText().trim().toLowerCase();
                if (url.startsWith("https://")) {
                    return true;
                }
                if (url.startsWith("http://")) {
                    String host = url.substring(7);
                    if (!host.startsWith("localhost") &&
                        !host.startsWith("127.0.0.1") &&
                        !host.startsWith("[::1]")) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}