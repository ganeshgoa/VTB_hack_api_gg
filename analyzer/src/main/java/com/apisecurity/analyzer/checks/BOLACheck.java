// com.apisecurity.analyzer.checks/BOLACheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.apisecurity.analyzer.context.DynamicContext;
import com.apisecurity.analyzer.executor.ApiCallResult;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BOLACheck implements SecurityCheck {
    private static final int MIN_DELAY_MS = 50;
    private static final int MAX_DELAY_MS = 200;

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
        String baseUrl = getBaseUrl(spec, container.getConfiguration());

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

                // Пропускаем служебные эндпоинты
                if (isAuthenticationEndpoint(path) || path.contains("/health") || path.contains("/jwks")) {
                    continue;
                }

                JsonNode operation = pathItem.get(method);
                String endpointName = method.toUpperCase() + " " + path;

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");

                if (hasObjectIdParameter(path, operation)) {
                    result.addFinding("Potential BOLA: endpoint accesses object by ID — dynamic check required");
                    result.addDetail("risk_level", "HIGH");
                    result.addDetail("owasp_category", "API1:2023 - Broken Object Level Authorization");
                    result.addDetail("cwe_id", "639");
                    result.addDetail("cwe_name", "Authorization Bypass Through User-Controlled Key");
                    result.addDetail("remediation", "Validate that the authenticated user owns the requested resource. Do not trust client-provided IDs.");

                    if (dynamicContext != null && dynamicContext.isAvailable()) {
                        String poc = performDynamicBOLATest(method, path, baseUrl, dynamicContext);
                        if (poc != null) {
                            result.addDetail("dynamic_status", "CONFIRMED");
                            result.addDetail("proof_of_concept", poc);
                        } else {
                            result.addDetail("dynamic_status", "NOT_CONFIRMED");
                        }
                    } else {
                        result.addDetail("dynamic_status", "NOT_TESTED");
                    }

                    foundAnyBOLA = true;
                }

                container.addAnalyzerResult(endpointName + "_bola", result);

                if (analysis != null) {
                    String status = "No BOLA issues";
                    if (result.getFindings().isEmpty()) {
                        status = "No BOLA issues";
                    } else if ("CONFIRMED".equals(result.getDetails().get("dynamic_status"))) {
                        status = "BOLA CONFIRMED";
                    } else {
                        status = "BOLA suspected (dynamic test: " + result.getDetails().get("dynamic_status") + ")";
                    }
                    analysis.setAnalyzer(status);
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundAnyBOLA ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundAnyBOLA
            ? "BOLA vulnerabilities detected or suspected"
            : "No BOLA issues found");
        container.addAnalyzerResult("bola_global", globalResult);

        System.out.println("  ✅ BOLA check completed.");
    }

    private String performDynamicBOLATest(String method, String path, String baseUrl, DynamicContext ctx) {
        String paramName = extractIdParameterName(path);
        if (paramName == null) return null;

        if (!ctx.getExecutionContext().has(paramName)) {
            System.out.println("  ⚠️ No " + paramName + " in params.json — skipping dynamic test for " + path);
            return null;
        }

        String originalId = ctx.getExecutionContext().get(paramName).toString();

        Set<String> triedIds = new HashSet<>();
        triedIds.add(originalId);

        // 🔁 Максимум 5 уникальных попыток
        for (int attempt = 0; attempt < 5; attempt++) {
            String mutatedId = mutateId(originalId, triedIds);
            if (mutatedId == null || mutatedId.isEmpty() || triedIds.contains(mutatedId)) {
                continue;
            }
            triedIds.add(mutatedId);

            String testPath = path.replace("{" + paramName + "}", mutatedId);
            if (testPath.contains("{")) continue; // безопасность: пропускаем неполные пути


            ApiCallResult res = ctx.getExecutor().callEndpoint(method.toUpperCase(), testPath, ctx.getExecutionContext());

            // ⚠️ Если 429 — прерываем тест для этого эндпоинта (сервер нас блокирует)
            if (res.statusCode == 429) {
                System.out.println("  ⚠️ 429 Too Many Requests — stopping BOLA test for this endpoint to avoid ban");
                break;
            }

            // ✅ Успех: 2xx → BOLA подтверждена
            if (res.isSuccess()) {
                String url = baseUrl + testPath;
                Map<String, String> headers = new HashMap<>();
                if (ctx.getExecutor().getAccessToken() != null) {
                    headers.put("Authorization", "Bearer " + ctx.getExecutor().getAccessToken());
                }
                for (String key : ctx.getExecutionContext().getKeys()) {
                    if (key.startsWith("x-")) {
                        headers.put(key, ctx.getExecutionContext().get(key).toString());
                    }
                }
                return buildCurlCommand(method, url, headers);
            }

            // ⏱️ Задержка между запросами
            try {
                int delay = MIN_DELAY_MS + new Random().nextInt(MAX_DELAY_MS - MIN_DELAY_MS + 1);
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return null;
    }

    private String mutateId(String id, Set<String> triedIds) {
        if (id == null || id.isEmpty()) return null;
        Random rand = new Random();

        // 🔢 Сначала пробуем числовую мутацию
        Pattern numPattern = Pattern.compile("\\d+");
        Matcher matcher = numPattern.matcher(id);
        if (matcher.find()) {
            String numberStr = matcher.group();
            try {
                long num = Long.parseLong(numberStr);
                // Пробуем +1, +10, -1, случайное
                long[] offsets = {1, 10, -1, rand.nextInt(50) + 1};
                for (long offset : offsets) {
                    long mutatedNum = num + offset;
                    if (mutatedNum > 0) {
                        String mutated = id.replaceFirst("\\d+", String.valueOf(mutatedNum));
                        if (!triedIds.contains(mutated)) {
                            return mutated;
                        }
                    }
                }
            } catch (NumberFormatException ignored) {}
        }

        // 🔠 Если чисел нет — мутируем символы
        for (int i = 0; i < 10; i++) { // до 10 попыток
            char[] chars = id.toCharArray();
            int idx = rand.nextInt(chars.length);
            char c = chars[idx];
            char newC = c;
            if (Character.isDigit(c)) {
                do {
                    newC = (char) ('0' + rand.nextInt(10));
                } while (newC == c);
            } else if (Character.isLetter(c)) {
                do {
                    if (Character.isLowerCase(c)) {
                        newC = (char) ('a' + rand.nextInt(26));
                    } else {
                        newC = (char) ('A' + rand.nextInt(26));
                    }
                } while (newC == c);
            }
            chars[idx] = newC;
            String mutated = new String(chars);
            if (!triedIds.contains(mutated)) {
                return mutated;
            }
        }
        return null;
    }

    private String extractIdParameterName(String path) {
        Pattern pattern = Pattern.compile("\\{([^}]+)\\}");
        Matcher matcher = pattern.matcher(path);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private String buildCurlCommand(String method, String url, Map<String, String> headers) {
        StringBuilder curl = new StringBuilder();
        curl.append("curl -X ").append(method.toUpperCase()).append(" '").append(url).append("'");
        for (Map.Entry<String, String> h : headers.entrySet()) {
            curl.append(" \\\n  -H '").append(h.getKey()).append(": ").append(h.getValue()).append("'");
        }
        return curl.toString();
    }

    private String getBaseUrl(JsonNode spec, Configuration config) {
        JsonNode servers = spec.get("servers");
        if (servers != null && servers.isArray() && servers.size() > 0) {
            return servers.get(0).get("url").asText().replaceAll("/+$", "");
        }
        String fromConfig = config.getAnalyzerBaseUrl();
        return fromConfig != null ? fromConfig.trim().replaceAll("/+$", "") : "http://localhost";
    }

    private boolean isAuthenticationEndpoint(String path) {
        String p = path.toLowerCase();
        return p.contains("/auth") || p.contains("/token") || p.contains("/login") || p.contains("/oauth");
    }

    private EndpointAnalysis findOrCreateAnalysis(ContainerApi container, String endpointName) {
        for (EndpointAnalysis ea : container.getAnalysisTable()) {
            if (endpointName.equals(ea.getEndpointName())) {
                return ea;
            }
        }
        EndpointAnalysis ea = new EndpointAnalysis();
        ea.setEndpointName(endpointName);
        container.addEndpointAnalysis(ea);
        return ea;
    }

    private boolean hasObjectIdParameter(String path, JsonNode operation) {
        if (path.matches(".*/\\{[^}]*[iI][dD][^}]*\\}.*")) {
            return true;
        }
        JsonNode params = operation.get("parameters");
        if (params != null && params.isArray()) {
            for (JsonNode p : params) {
                String name = p.has("name") ? p.get("name").asText() : "";
                String in = p.has("in") ? p.get("in").asText() : "";
                if (("query".equals(in) || "header".equals(in)) && isIdLikeParameter(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isIdLikeParameter(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase();
        boolean isObjectId = lower.equals("id") || lower.endsWith("id") || lower.contains("identifier") || lower.matches(".*_id$");
        boolean isAuth = lower.equals("client_id") || lower.equals("client_secret") || lower.contains("token");
        return isObjectId && !isAuth;
    }
}