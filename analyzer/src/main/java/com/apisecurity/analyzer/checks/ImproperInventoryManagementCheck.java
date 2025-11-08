// com.apisecurity.analyzer.checks/ImproperInventoryManagementCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class ImproperInventoryManagementCheck implements SecurityCheck {

    @Override
    public String getName() {
        return "ImproperInventoryManagement";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Improper Inventory Management (API9:2023)...");

        boolean hasIssue = false;

        // 1. Проверка версии API
        if (!hasApiVersion(spec)) {
            addGlobalFinding("API version is missing — complicates inventory and patching",
                "MEDIUM", "CWE-1059", container);
            hasIssue = true;
        }

        // 2. Проверка описания окружения (prod/staging/test)
        if (!hasEnvironmentInfo(spec)) {
            addGlobalFinding("API environment (prod/staging/dev) is not documented — increases risk of exposing test endpoints",
                "MEDIUM", "CWE-1059", container);
            hasIssue = true;
        }

        // 3. Проверка аудитории (публичный/внутренний)
        if (!hasAudienceInfo(spec)) {
            addGlobalFinding("API audience (public/internal/partners) is not documented — may lead to overexposure",
                "MEDIUM", "CWE-1059", container);
            hasIssue = true;
        }

        // 4. Проверка политики устаревания
        if (!hasDeprecationPolicy(spec)) {
            addGlobalFinding("No deprecation or retirement policy documented — old versions may remain exposed",
                "LOW", "CWE-1059", container);
            // LOW, потому что это процесс, а не прямая уязвимость
        }

        // 5. Очень короткое/пустое описание
        if (isPoorlyDocumented(spec)) {
            addGlobalFinding("API documentation is minimal or missing — hinders inventory and security analysis",
                "MEDIUM", "CWE-1059", container);
            hasIssue = true;
        }

        ModuleResult globalResult = new ModuleResult(hasIssue ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", hasIssue
            ? "Documentation gaps may lead to improper inventory management"
            : "No documentation gaps detected");
        container.addAnalyzerResult("inventory_global", globalResult);

        System.out.println("  ✅ Improper Inventory Management check completed. " +
            (hasIssue ? "Documentation gaps found." : "No issues found."));
    }

    private void addGlobalFinding(String finding, String riskLevel, String cwe, ContainerApi container) {
        ModuleResult result = new ModuleResult("ISSUES_FOUND");
        result.addFinding(finding);
        result.addDetail("risk_level", riskLevel);
        result.addDetail("cwe", cwe);
        result.addDetail("owasp_category", "API9:2023 - Improper Inventory Management");
        // Используем уникальный ключ для избежания перезаписи
        String key = "inventory_issue_" + container.getAnalyzerResults().size();
        container.addAnalyzerResult(key, result);
    }

    private boolean hasApiVersion(JsonNode spec) {
        JsonNode info = spec.get("info");
        return info != null && info.has("version") && !info.get("version").asText().trim().isEmpty();
    }

    private boolean hasEnvironmentInfo(JsonNode spec) {
        String desc = getFullText(spec);
        return desc.contains("prod") || desc.contains("production") ||
               desc.contains("staging") || desc.contains("test") ||
               desc.contains("dev") || desc.contains("development") ||
               desc.contains("environment");
    }

    private boolean hasAudienceInfo(JsonNode spec) {
        String desc = getFullText(spec);
        return desc.contains("public") || desc.contains("internal") ||
               desc.contains("partner") || desc.contains("private") ||
               desc.contains("audience") || desc.contains("access") ||
               desc.contains("authorized");
    }

    private boolean hasDeprecationPolicy(JsonNode spec) {
        String desc = getFullText(spec);
        return desc.contains("deprecat") || desc.contains("retire") ||
               desc.contains("versioning") || desc.contains("lifecycle") ||
               desc.contains("sunset");
    }

    private boolean isPoorlyDocumented(JsonNode spec) {
        String desc = getFullText(spec);
        // Если описание короче 50 символов — считаем недостаточным
        return desc.length() < 50;
    }

    private String getFullText(JsonNode spec) {
        StringBuilder sb = new StringBuilder();
        if (spec.has("info")) {
            JsonNode info = spec.get("info");
            if (info.has("title")) sb.append(info.get("title").asText()).append(" ");
            if (info.has("description")) sb.append(info.get("description").asText()).append(" ");
        }
        if (spec.has("servers")) {
            sb.append(spec.get("servers").toString()).append(" ");
        }
        return sb.toString().toLowerCase();
    }
}