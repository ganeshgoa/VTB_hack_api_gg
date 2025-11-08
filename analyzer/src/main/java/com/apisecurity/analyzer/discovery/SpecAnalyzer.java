// com.apisecurity.analyzer.discovery/SpecAnalyzer.java
package com.apisecurity.analyzer.discovery;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

/**
 * Анализирует OpenAPI-спецификацию и строит сигнатуры эндпоинтов:
 * - inputs: параметры, необходимые для вызова
 * - outputs: поля, возвращаемые в успешных (2xx) ответах
 */
public class SpecAnalyzer {

    private final JsonNode componentsSchemas;

    /**
     * Конструктор принимает ПОЛНУЮ OpenAPI-спецификацию для разрешения $ref.
     */
    public SpecAnalyzer(JsonNode fullSpec) {
        JsonNode components = fullSpec != null ? fullSpec.get("components") : null;
        this.componentsSchemas = (components != null && components.has("schemas"))
            ? components.get("schemas")
            : null;
    }

    /**
     * Строит карту сигнатур всех эндпоинтов.
     * Ключ: "GET /accounts"
     */
    public Map<String, EndpointSignature> buildEndpointSignatures(JsonNode spec) {
        Map<String, EndpointSignature> signatures = new LinkedHashMap<>();

        JsonNode paths = spec.get("paths");
        if (paths == null || !paths.isObject()) {
            return signatures;
        }

        Iterator<Map.Entry<String, JsonNode>> pathIt = paths.fields();
        while (pathIt.hasNext()) {
            Map.Entry<String, JsonNode> pathEntry = pathIt.next();
            String path = pathEntry.getKey();
            JsonNode pathItem = pathEntry.getValue();

            if (!pathItem.isObject()) continue;

            Iterator<String> methodIt = pathItem.fieldNames();
            while (methodIt.hasNext()) {
                String method = methodIt.next().toLowerCase();
                if (!isHttpMethod(method)) continue;

                JsonNode operation = pathItem.get(method);
                if (!operation.isObject()) continue;

                String opId = operation.has("operationId")
                    ? operation.get("operationId").asText()
                    : generateOperationId(method, path);

                EndpointSignature sig = new EndpointSignature(path, method, opId);

                extractInputs(operation, sig.inputs);
                extractOutputs(operation, sig.outputs);

                String key = method.toUpperCase() + " " + path;
                signatures.put(key, sig);
            }
        }

        return signatures;
    }

    private boolean isHttpMethod(String method) {
        return "get".equals(method) || "post".equals(method) || "put".equals(method) ||
               "patch".equals(method) || "delete".equals(method) || "head".equals(method) ||
               "options".equals(method);
    }

    private String generateOperationId(String method, String path) {
        return method + path.replaceAll("[^a-zA-Z0-9]", "_");
    }

    // --- ИЗВЛЕЧЕНИЕ ВХОДОВ ---

    private void extractInputs(JsonNode operation, Map<String, String> inputs) {
        // 1. Параметры (path, query, header)
        JsonNode parameters = operation.get("parameters");
        if (parameters != null && parameters.isArray()) {
            for (JsonNode param : parameters) {
                if (!param.has("name") || !param.has("in")) continue;
                String name = param.get("name").asText();
                String in = param.get("in").asText();
                if ("path".equals(in) || "query".equals(in) || "header".equals(in)) {
                    inputs.put(name, in);
                }
            }
        }

        // 2. Тело запроса (body)
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody != null) {
            Set<String> bodyFields = extractFieldsFromContent(requestBody.get("content"));
            for (String field : bodyFields) {
                inputs.put(field, "body");
            }
        }
    }

    // --- ИЗВЛЕЧЕНИЕ ВЫХОДОВ ---

    private void extractOutputs(JsonNode operation, Set<String> outputs) {
        JsonNode responses = operation.get("responses");
        if (responses == null || !responses.isObject()) return;

        for (Iterator<String> it = responses.fieldNames(); it.hasNext(); ) {
            String code = it.next();
            if (code.startsWith("2")) { // 2xx успешные ответы
                JsonNode response = responses.get(code);
                Set<String> responseFields = extractFieldsFromContent(response.get("content"));
                outputs.addAll(responseFields);
            }
        }
    }

    // --- ИЗВЛЕЧЕНИЕ ПОЛЕЙ ИЗ content (например, application/json) ---

    private Set<String> extractFieldsFromContent(JsonNode content) {
        Set<String> fields = new LinkedHashSet<>();
        if (content == null || !content.isObject()) return fields;

        for (Iterator<String> mediaIt = content.fieldNames(); mediaIt.hasNext(); ) {
            String mediaType = mediaIt.next();
            if (!mediaType.contains("json")) continue;

            JsonNode schema = content.get(mediaType).get("schema");
            if (schema != null) {
                extractFieldsFromSchema(schema, fields);
            }
        }
        return fields;
    }

    // --- РЕКУРСИВНОЕ ИЗВЛЕЧЕНИЕ ПОЛЕЙ С ПОДДЕРЖКОЙ $ref И allOf ---

    private void extractFieldsFromSchema(JsonNode schema, Set<String> fields) {
        if (schema == null || schema.isNull()) return;

        // 1. Разрешение $ref
        if (schema.has("$ref")) {
            JsonNode resolved = resolveRef(schema);
            if (resolved != null) {
                extractFieldsFromSchema(resolved, fields);
            }
            return;
        }

        // 2. Обработка allOf (часто используется в OpenAPI)
        if (schema.has("allOf")) {
            for (JsonNode item : schema.get("allOf")) {
                extractFieldsFromSchema(item, fields);
            }
            return;
        }

        // 3. Массив
        if ("array".equals(getType(schema))) {
            JsonNode items = schema.get("items");
            if (items != null) {
                extractFieldsFromSchema(items, fields);
            }
            return;
        }

        // 4. Объект с properties
        if ("object".equals(getType(schema)) || schema.has("properties")) {
            JsonNode properties = schema.get("properties");
            if (properties != null && properties.isObject()) {
                for (Iterator<String> propIt = properties.fieldNames(); propIt.hasNext(); ) {
                    String propName = propIt.next();
                    JsonNode propSchema = properties.get(propName);

                    String propType = getType(propSchema);
                    if (isScalarType(propType)) {
                        fields.add(propName);
                    } else {
                        // Рекурсивно заходим в объекты и вложенные структуры
                        extractFieldsFromSchema(propSchema, fields);
                    }
                }
            }
            return;
        }

        // 5. Другие типы (например, примитивы на верхнем уровне) — игнорируем
    }

    private JsonNode resolveRef(JsonNode refNode) {
        if (componentsSchemas == null) return null;
        String ref = refNode.get("$ref").asText();
        if (ref.startsWith("#/components/schemas/")) {
            String schemaName = ref.substring("#/components/schemas/".length());
            return componentsSchemas.get(schemaName);
        }
        return null;
    }

    private String getType(JsonNode schema) {
        if (schema != null && schema.has("type")) {
            return schema.get("type").asText();
        }
        return "object";
    }

    private boolean isScalarType(String type) {
        return "string".equals(type) || "number".equals(type) || "integer".equals(type) ||
               "boolean".equals(type) || "null".equals(type);
    }
}