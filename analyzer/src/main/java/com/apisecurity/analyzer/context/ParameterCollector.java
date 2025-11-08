// com.apisecurity.analyzer.context/ParameterCollector.java
package com.apisecurity.analyzer.context;

import com.apisecurity.analyzer.discovery.EndpointSignature;
import com.apisecurity.shared.Configuration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.*;

/**
 * Собирает ВСЕ параметры из JSON-файла, с fallback на конфигурацию.
 */
public class ParameterCollector {

    private static final String DEFAULT_PARAMS_FILE = "params.json";
    private final Configuration config;
    private final Map<String, EndpointSignature> signatures;

    public ParameterCollector(Configuration config, Map<String, EndpointSignature> signatures) {
        this.config = config;
        this.signatures = signatures;
    }

    public ExecutionContext collect() {
        ExecutionContext ctx = new ExecutionContext();

        // 1. Собираем ВСЕ требуемые параметры (включая client_id, client_secret)
        Set<String> allRequiredParams = collectAllRequiredParameters();
        System.out.println("🔍 Required dynamic parameters: " + allRequiredParams);

        // 2. Запрос пути к файлу
        System.out.println("📁 Please specify path to JSON file with example values (press Enter for default: " + DEFAULT_PARAMS_FILE + "):");
        String filePath = readUserInput();
        if (filePath.trim().isEmpty()) {
            filePath = DEFAULT_PARAMS_FILE;
        }

        File file = new File(filePath);
        Map<String, String> jsonParams = new HashMap<>();

        if (file.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode root = mapper.readTree(file);

                for (String param : allRequiredParams) {
                    if (root.has(param)) {
                        JsonNode valueNode = root.get(param);
                        String value = null;
                        if (valueNode.isArray() && valueNode.size() > 0) {
                            value = valueNode.get(0).asText();
                        } else if (valueNode.isTextual()) {
                            value = valueNode.asText();
                        }
                        if (value != null) {
                            jsonParams.put(param, value);
                            System.out.println("✅ Loaded from JSON: " + param + " = " + value);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("❌ Failed to parse JSON: " + e.getMessage());
            }
        } else {
            System.out.println("ℹ️  JSON file not found: " + file.getAbsolutePath() + " — using config defaults.");
        }

        // 3. Заполняем ExecutionContext: сначала из JSON, потом из конфига (fallback)
        for (String param : allRequiredParams) {
            if (jsonParams.containsKey(param)) {
                ctx.provide(param, jsonParams.get(param));
            } else {
                // Fallback на конфигурацию
                if ("client_id".equals(param) && config.getAnalyzerClientId() != null) {
                    ctx.provide(param, config.getAnalyzerClientId());
                    System.out.println("✅ Using config default: client_id = " + config.getAnalyzerClientId());
                } else if ("client_secret".equals(param) && config.getAnalyzerClientSecret() != null) {
                    ctx.provide(param, config.getAnalyzerClientSecret());
                    System.out.println("✅ Using config default: client_secret = *** (hidden)");
                } else {
                    System.out.println("⚠️  Missing value for parameter: " + param);
                }
            }
        }

        return ctx;
    }

    private Set<String> collectAllRequiredParameters() {
        Set<String> params = new LinkedHashSet<>();
        for (EndpointSignature sig : signatures.values()) {
            for (Map.Entry<String, String> input : sig.inputs.entrySet()) {
                // Включаем все обязательные параметры: path, query, и даже "body", если имя скалярное
                String in = input.getValue();
                if ("path".equals(in) || "query".equals(in) || "header".equals(in)) {
                    params.add(input.getKey());
                }
                // Для body — можно добавить эвристику, но пока пропустим
            }
        }
        return params;
    }

    private String readUserInput() {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            return reader.readLine();
        } catch (Exception e) {
            return "";
        }
    }
}