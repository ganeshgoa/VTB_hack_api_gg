// com.apisecurity.analyzer.context/ParameterCollector.java

package com.apisecurity.analyzer.context;

import com.apisecurity.analyzer.discovery.EndpointSignature;
import com.apisecurity.shared.Configuration;
import com.apisecurity.shared.ContainerApi; // ✅ ДОБАВЛЕНО
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.*;

/**
 * Собирает параметры из params.json и устанавливает base_url в ContainerApi.
 */
public class ParameterCollector {

    private static final String DEFAULT_PARAMS_FILE = "params.json";
    private final Configuration config;
    private final ContainerApi container; // ✅ вместо signatures напрямую
    private final Map<String, EndpointSignature> signatures;

    // ✅ КОНСТРУКТОР ИЗМЕНЁН
    public ParameterCollector(Configuration config, ContainerApi container, Map<String, EndpointSignature> signatures) {
        this.config = config;
        this.container = container;
        this.signatures = signatures;
    }

    public ExecutionContext collect() {
        ExecutionContext ctx = new ExecutionContext();

        File paramsFile = new File(DEFAULT_PARAMS_FILE);
        JsonNode root = null;
        if (paramsFile.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                root = mapper.readTree(paramsFile);

                // ✅ Устанавливаем base_url в ContainerApi
                if (root.has("base_url")) {
                    String baseUrl = root.get("base_url").asText().trim().replaceAll("/+$", "");
                    container.setAnalyzerBaseUrl(baseUrl);
                    System.out.println("✅ Loaded base_url from " + DEFAULT_PARAMS_FILE + ": " + baseUrl);
                } else {
                    System.out.println("⚠️ base_url not found in " + DEFAULT_PARAMS_FILE);
                }
            } catch (Exception e) {
                System.err.println("❌ Failed to parse " + DEFAULT_PARAMS_FILE + ": " + e.getMessage());
            }
        } else {
            System.out.println("ℹ️ " + DEFAULT_PARAMS_FILE + " not found.");
        }

        // === Сбор параметров (без изменений) ===
        Set<String> allRequiredParams = collectAllRequiredParameters();
        System.out.println("🔍 Required dynamic parameters: " + allRequiredParams);

        Map<String, String> jsonParams = new HashMap<>();
        if (root != null) {
            for (String param : allRequiredParams) {
                if (root.has(param)) {
                    JsonNode valueNode = root.get(param);
                    String value = null;
                    if (valueNode.isArray() && valueNode.size() > 0) {
                        value = valueNode.get(0).asText();
                    } else if (valueNode.isTextual()) {
                        value = valueNode.asText();
                    }
                    if (value != null && !value.trim().isEmpty()) {
                        jsonParams.put(param, value);
                        System.out.println("✅ Loaded from " + DEFAULT_PARAMS_FILE + ": " + param + " = " + maskSecret(param, value));
                    }
                }
            }
        }

        for (String param : allRequiredParams) {
            if (jsonParams.containsKey(param)) {
                ctx.provide(param, jsonParams.get(param));
            } else {
                if ("client_id".equals(param) && config.getAnalyzerClientId() != null) {
                    ctx.provide(param, config.getAnalyzerClientId());
                    System.out.println("✅ Using config: client_id = " + config.getAnalyzerClientId());
                } else if ("client_secret".equals(param) && config.getAnalyzerClientSecret() != null) {
                    ctx.provide(param, config.getAnalyzerClientSecret());
                    System.out.println("✅ Using config: client_secret = *** (hidden)");
                } else {
                    System.out.println("⚠️ Missing value for parameter: " + param);
                }
            }
        }

        return ctx;
    }

    private Set<String> collectAllRequiredParameters() {
        Set<String> params = new LinkedHashSet<>();
        params.add("client_id");
        params.add("client_secret");
        for (EndpointSignature sig : signatures.values()) {
            for (Map.Entry<String, String> input : sig.inputs.entrySet()) {
                String location = input.getValue();
                if ("path".equals(location) || "query".equals(location) || "header".equals(location)) {
                    params.add(input.getKey());
                }
            }
        }
        return params;
    }

    private String maskSecret(String paramName, String value) {
        if ("client_secret".equals(paramName) || "password".equals(paramName) || "token".equals(paramName)) {
            return "*** (hidden)";
        }
        return value;
    }
}