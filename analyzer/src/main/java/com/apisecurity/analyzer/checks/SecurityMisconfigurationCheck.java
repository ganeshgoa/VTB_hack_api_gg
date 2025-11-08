// com.apisecurity.analyzer.checks/SecurityMisconfigurationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import com.apisecurity.analyzer.context.DynamicContext;
public class SecurityMisconfigurationCheck implements SecurityCheck {

    @Override
    public String getName() {
        return "SecurityMisconfiguration";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("  🔍 Checking Security Misconfiguration (API8:2023)...");

        boolean foundIssues = false;

        // === 1. Проверка HTTPS в servers ===
        if (!isHttpsEnforced(spec)) {
            handleGlobalIssue("API is not served over HTTPS — sensitive data transmitted in clear text",
                "HIGH", "CWE-319", container);
            foundIssues = true;
        }

        // === 2. Проверка CORS (если есть / или указание на Web) ===
        if (isWebFacingApi(spec) && !hasCorsMention(spec)) {
            handleGlobalIssue("Web-facing API lacks CORS policy — may be vulnerable to cross-origin attacks",
                "MEDIUM", "CWE-942", container);
            foundIssues = true;
        }

        // === 3. Анализ эндпоинтов на утечки в ошибках ===
        if (spec.has("paths")) {
            Iterator<Map.Entry<String, JsonNode>> pathIt = spec.get("paths").fields();
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

                    // Проверка: есть ли примеры ошибок со stack trace?
                    if (hasSensitiveErrorExamples(operation)) {
                        EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                        ModuleResult result = new ModuleResult("COMPLETED");
                        result.addFinding("Error responses may expose stack traces or internal details");
                        result.addDetail("risk_level", "MEDIUM");
                        result.addDetail("cwe", "CWE-209");
                        result.addDetail("owasp_category", "API8:2023 - Security Misconfiguration");
                        container.addAnalyzerResult(endpointName + "_misconfig", result);
                        foundIssues = true;

                        if (analysis != null) {
                            analysis.setAnalyzer("Security misconfiguration suspected");
                        }
                    }
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "Security misconfigurations detected"
            : "No security misconfigurations detected");
        container.addAnalyzerResult("misconfig_global", globalResult);

        System.out.println("  ✅ Security Misconfiguration check completed. " +
            (foundIssues ? "Vulnerabilities suspected." : "No issues found."));
    }

    // Обработка глобальных проблем (без привязки к эндпоинту)
    private void handleGlobalIssue(String finding, String riskLevel, String cwe, ContainerApi container) {
        ModuleResult result = new ModuleResult("ISSUES_FOUND");
        result.addFinding(finding);
        result.addDetail("risk_level", riskLevel);
        result.addDetail("cwe", cwe);
        result.addDetail("owasp_category", "API8:2023 - Security Misconfiguration");
        container.addAnalyzerResult("security_misconfig_global", result);
    }

    // === ПРОВЕРКА HTTPS ===
    private boolean isHttpsEnforced(JsonNode spec) {
        JsonNode servers = spec.get("servers");
        if (servers == null || !servers.isArray() || servers.isEmpty()) {
            // Если servers нет — не можем знать. Считаем, что HTTPS может быть.
            return true;
        }

        for (JsonNode server : servers) {
            if (server.has("url")) {
                String url = server.get("url").asText().trim().toLowerCase();
                if (url.startsWith("https://")) {
                    return true; // хотя бы один HTTPS — достаточно
                }
                // Если есть http:// и не localhost — проблема
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
        // Если все серверы — localhost по HTTP — допустимо
        return true;
    }

    // === ОПРЕДЕЛЕНИЕ Web-facing API ===
    private boolean isWebFacingApi(JsonNode spec) {
        String text = "";
        if (spec.has("info")) {
            JsonNode info = spec.get("info");
            if (info.has("description")) text += info.get("description").asText().toLowerCase();
            if (info.has("title")) text += info.get("title").asText().toLowerCase();
        }
        if (spec.has("paths") && spec.get("paths").has("/")) {
            return true; // наличие корня часто означает Web
        }
        return text.contains("web") || text.contains("browser") || text.contains("frontend");
    }

    // === ПРОВЕРКА CORS ===
    private boolean hasCorsMention(JsonNode spec) {
        String text = spec.toString().toLowerCase();
        return text.contains("cors") || text.contains("cross-origin") || text.contains("access-control");
    }

    // === ПРОВЕРКА УТЕЧЕК В ОШИБКАХ ===
    private boolean hasSensitiveErrorExamples(JsonNode operation) {
        JsonNode responses = operation.get("responses");
        if (responses == null) return false;

        // Проверяем 4xx и 5xx ответы
        for (Iterator<String> it = responses.fieldNames(); it.hasNext(); ) {
            String code = it.next();
            if (code.startsWith("4") || code.startsWith("5")) {
                JsonNode response = responses.get(code);
                if (hasSensitiveExample(response)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasSensitiveExample(JsonNode response) {
        if (response.has("content")) {
            JsonNode content = response.get("content");
            for (Iterator<String> mediaIt = content.fieldNames(); mediaIt.hasNext(); ) {
                String mediaType = mediaIt.next();
                JsonNode example = content.get(mediaType).get("example");
                if (example != null && example.isTextual()) {
                    String exampleText = example.asText().toLowerCase();
                    if (exampleText.contains("stack") || exampleText.contains("exception") ||
                        exampleText.contains("trace") || exampleText.contains("error") ||
                        exampleText.contains("file:") || exampleText.contains("line ") ||
                        exampleText.contains("at com.") || exampleText.contains("java.lang")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // --- ВСПОМОГАТЕЛЬНЫЙ МЕТОД ---

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
}