// com.apisecurity.analyzer.checks/BrokenAuthenticationCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.*;
import com.apisecurity.analyzer.context.DynamicContext;
import com.apisecurity.analyzer.context.ExecutionContext;
import com.apisecurity.analyzer.executor.ApiCallResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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

    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper =
        new com.fasterxml.jackson.databind.ObjectMapper();

    @Override
    public String getName() {
        return "BrokenAuthentication";
    }

    @Override
    public void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext) {
        System.out.println("Checking Broken Authentication (API2:2023)...");

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            System.out.println("No paths defined in spec.");
            return;
        }

        boolean foundIssues = false;
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

                JsonNode operation = pathItem.get(method);
                String endpointName = method.toUpperCase() + " " + path;

                EndpointAnalysis analysis = findOrCreateAnalysis(container, endpointName);
                ModuleResult result = new ModuleResult("COMPLETED");

                boolean vulnerable = false;

                // === 1. Authentication endpoint checks ===
                if (isAuthenticationEndpoint(path)) {
                    // 1a. Credentials in URL (GET)
                    if ("get".equals(method) && hasCredentialsInUrl(operation)) {
                        addFinding(result,
                            "Authentication via GET request — credentials exposed in URL/logs",
                            "HIGH",
                            "CWE-598: Use of GET Request Method With Sensitive Data",
                            "Send credentials in request body over HTTPS, never in URL.");
                        vulnerable = true;
                    }

                    // 1b. Missing brute-force protection
                    if (!hasRateLimitingOrLockout(operation)) {
                        addFinding(result,
                            "Auth endpoint lacks rate limiting, lockout, or captcha — vulnerable to brute force",
                            "HIGH",
                            "CWE-307: Improper Restriction of Excessive Authentication Attempts",
                            "Implement rate limiting, account lockout, or CAPTCHA after N failed attempts.");
                        vulnerable = true;

                        // Dynamic brute-force test
                        if (dynamicContext != null && dynamicContext.isAvailable()) {
                            String poc = performBruteForceTest(method, path, baseUrl, dynamicContext);
                            if (poc != null) {
                                result.addDetail("dynamic_status", "CONFIRMED");
                                result.addDetail("proof_of_concept", poc);
                                System.out.println("  💥 Brute-force vulnerability CONFIRMED on " + endpointName);
                            } else {
                                result.addDetail("dynamic_status", "NOT_CONFIRMED");
                            }
                        } else {
                            result.addDetail("dynamic_status", "NOT_TESTED");
                        }
                    } else {
                        result.addDetail("dynamic_status", "PROTECTED");
                    }

                    // 1c. JWT without expiration check
                    if (mentionsJWT(operation) && !hasJwtExpirationCheck(operation)) {
                        addFinding(result,
                            "JWT tokens accepted without expiration validation",
                            "HIGH",
                            "CWE-613: Insufficient Session Expiration",
                            "Validate 'exp' claim in all JWT tokens and reject expired ones.");
                        vulnerable = true;
                    }
                }

                // === 2. Sensitive endpoint without authentication ===
                boolean isSensitivePath = isSensitivePath(path);
                boolean hasSecurity = hasSecurityRequirement(operation, spec);

                if (isSensitivePath && !hasSecurity) {
                    addFinding(result,
                        "Sensitive endpoint (" + path + ") is not protected by authentication",
                        "HIGH",
                        "CWE-306: Missing Authentication for Critical Function",
                        "Apply authentication (e.g., OAuth2 Bearer token) to all sensitive endpoints.");
                    vulnerable = true;
                }

                // === 3. Sensitive operation without password confirmation ===
                if (isSensitiveOperation(path) && !requiresPasswordConfirmation(operation)) {
                    addFinding(result,
                        "Sensitive operation does not require current password confirmation",
                        "HIGH",
                        "CWE-640: Weak Password Recovery Mechanism for Forgotten Password",
                        "Require current password or OTP before allowing sensitive changes (email, password, 2FA).");
                    vulnerable = true;

                    // Dynamic test: try to change email without password
                    if (dynamicContext != null && dynamicContext.isAvailable()) {
                        String poc = performPasswordConfirmationBypassTest(method, path, baseUrl, dynamicContext);
                        if (poc != null) {
                            result.addDetail("dynamic_status", "CONFIRMED");
                            result.addDetail("proof_of_concept", poc);
                            System.out.println("  💥 Password confirmation bypass CONFIRMED on " + endpointName);
                        } else {
                            result.addDetail("dynamic_status", "NOT_CONFIRMED");
                        }
                    } else {
                        result.addDetail("dynamic_status", "NOT_TESTED");
                    }
                }

                // === 4. API key used for user authentication ===
                if (usesApiKeyForUserAuth(operation, spec)) {
                    addFinding(result,
                        "API key is used for user authentication — API keys should only identify clients",
                        "MEDIUM",
                        "CWE-287: Improper Authentication",
                        "Use OAuth2 tokens or session cookies for user auth; API keys are for client identification only.");
                    vulnerable = true;
                }

                if (vulnerable) {
                    result.addDetail("owasp_category", "API2:2023 - Broken Authentication");
                    container.addAnalyzerResult(endpointName + "_auth", result);
                    foundIssues = true;
                }

                if (analysis != null) {
                    String status = vulnerable
                        ? ("Broken authentication issues suspected (dynamic: " + result.getDetails().get("dynamic_status") + ")")
                        : "No broken authentication issues detected";
                    analysis.setAnalyzer(status);
                }
            }
        }

        ModuleResult globalResult = new ModuleResult(foundIssues ? "ISSUES_FOUND" : "COMPLETED");
        globalResult.addDetail("summary", foundIssues
            ? "One or more endpoints show signs of broken authentication"
            : "No broken authentication issues detected");
        container.addAnalyzerResult("broken_auth_global", globalResult);

        System.out.println("Broken Authentication check completed. " +
            (foundIssues ? "Vulnerabilities suspected." : "No issues found."));
    }

    private void addFinding(ModuleResult result, String message, String severity, String cwe, String remediation) {
        result.addFinding(message);
        result.addDetail("risk_level", severity);
        result.addDetail("cwe_name", cwe);
        result.addDetail("remediation", remediation);
    }

    // === DYNAMIC TESTS ===

    private String performBruteForceTest(String method, String path, String baseUrl, DynamicContext ctx) {
        ExecutionContext exec = ctx.getExecutionContext();
        if (!exec.getKeys().contains("username")) return null;

        String username = exec.get("username").toString();
        List<String> weakPasswords = Arrays.asList("123456", "password", "qwerty", "admin", "letmein");

        for (String pwd : weakPasswords) {
            ObjectNode body = objectMapper.createObjectNode();
            body.put("username", username);
            body.put("password", pwd);

            ApiCallResult res = ctx.getExecutor().callEndpointWithBody(method.toUpperCase(), path, body, exec);
            if (res.isSuccess()) {
                // Success with a weak password → vulnerability confirmed
                return buildCurlCommand(method, baseUrl + path, body, ctx.getExecutor().getAccessToken(), exec);
            }
        }
        return null;
    }

    private String performPasswordConfirmationBypassTest(String method, String path, String baseUrl, DynamicContext ctx) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("email", "attacker@example.com"); // attempt to change email

        ApiCallResult res = ctx.getExecutor().callEndpointWithBody(method.toUpperCase(), path, body, ctx.getExecutionContext());
        if (res.isSuccess()) {
            return buildCurlCommand(method, baseUrl + path, body, ctx.getExecutor().getAccessToken(), ctx.getExecutionContext());
        }
        return null;
    }

    private String buildCurlCommand(String method, String url, JsonNode body, String token, ExecutionContext ctx) {
        StringBuilder curl = new StringBuilder();
        curl.append("curl -X ").append(method.toUpperCase()).append(" '").append(url).append("'");

        if (token != null) {
            curl.append(" \\\n  -H 'Authorization: Bearer ").append(token).append("'");
        }

        for (String key : ctx.getKeys()) {
            if (key.startsWith("x-")) {
                curl.append(" \\\n  -H '").append(key).append(": ").append(ctx.get(key)).append("'");
            }
        }

        if (body != null) {
            String jsonStr = body.toString().replace("'", "'\"'\"'"); // escape single quotes for shell
            curl.append(" \\\n  -H 'Content-Type: application/json' \\\n  -d '").append(jsonStr).append("'");
        }

        return curl.toString();
    }

    // === HELPER METHODS ===

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
               text.contains("max attempt") || text.contains("brute") || text.contains("block");
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
        JsonNode localSec = operation.get("security");
        if (localSec != null && localSec.isArray() && !localSec.isEmpty()) {
            return true;
        }
        JsonNode globalSec = spec.get("security");
        return globalSec != null && globalSec.isArray() && !globalSec.isEmpty();
    }

    private boolean usesApiKeyForUserAuth(JsonNode operation, JsonNode spec) {
        JsonNode security = operation.get("security");
        if (security == null || !security.isArray() || security.isEmpty()) {
            security = spec.get("security");
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

    private String getBaseUrl(JsonNode spec, Configuration config) {
        JsonNode servers = spec.get("servers");
        if (servers != null && servers.isArray() && servers.size() > 0) {
            return servers.get(0).get("url").asText().replaceAll("/+$", "");
        }
        String fromConfig = config.getAnalyzerBaseUrl();
        return fromConfig != null ? fromConfig.trim().replaceAll("/+$", "") : "http://localhost";
    }
}