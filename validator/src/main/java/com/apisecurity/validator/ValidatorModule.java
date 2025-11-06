package com.apisecurity.validator;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class ValidatorModule {
    
    public void process(ContainerApi container) {
        long startTime = System.currentTimeMillis();
        System.out.println("🔧 Starting API specification validation...");
        
        JsonNode spec = container.getFullSpecification();
        
        // Проверка структуры спецификации
        validateOpenAPIStructure(spec, container);
        
        // Валидация эндпоинтов
        validateEndpoints(spec, container);
        
        // Валидация схем данных
        validateSchemas(spec, container);
        
        // Валидация параметров
        validateParameters(spec, container);
        
        long endTime = System.currentTimeMillis();
        System.out.println("✅ Validation completed in " + (endTime - startTime) + "ms");
    }
    
    private void validateOpenAPIStructure(JsonNode spec, ContainerApi container) {
        ModuleResult result = new ModuleResult("COMPLETED");
        
        // Проверка обязательных полей OpenAPI
        if (!spec.has("openapi")) {
            result.addFinding("Missing required field: 'openapi'");
        }
        
        if (!spec.has("info")) {
            result.addFinding("Missing required field: 'info'");
        }
        
        if (!spec.has("paths")) {
            result.addFinding("Missing required field: 'paths'");
        }
        
        if (spec.has("info")) {
            JsonNode info = spec.get("info");
            if (!info.has("title")) {
                result.addFinding("Missing required field: 'info.title'");
            }
            if (!info.has("version")) {
                result.addFinding("Missing required field: 'info.version'");
            }
        }
        
        container.addValidatorResult("openapi_structure", result);
    }
    
    private void validateEndpoints(JsonNode spec, ContainerApi container) {
        JsonNode paths = spec.get("paths");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            // Извлечение метода и пути из имени эндпоинта
            String[] parts = endpointName.split(" ", 2);
            if (parts.length == 2) {
                String method = parts[0].toLowerCase();
                String path = parts[1];
                
                JsonNode pathNode = paths.get(path);
                if (pathNode != null) {
                    JsonNode methodNode = pathNode.get(method);
                    if (methodNode != null) {
                        validateEndpointStructure(methodNode, result, endpointName);
                    } else {
                        result.addFinding("Method " + method + " not found for path " + path);
                    }
                } else {
                    result.addFinding("Path " + path + " not found in specification");
                }
            }
            
            container.addValidatorResult(endpointName, result);
            analysis.setValidator(result.toString());
        }
    }
    
    private void validateEndpointStructure(JsonNode endpoint, ModuleResult result, String endpointName) {
        // Проверка обязательных полей эндпоинта
        if (!endpoint.has("responses")) {
            result.addFinding("Missing 'responses' field in endpoint " + endpointName);
        }
        
        // Проверка формата responses
        if (endpoint.has("responses")) {
            JsonNode responses = endpoint.get("responses");
            if (!responses.has("200") && !responses.has("201")) {
                result.addFinding("No success responses (200, 201) defined for " + endpointName);
            }
        }
        
        // Проверка security
        if (!endpoint.has("security")) {
            result.addFinding("No security defined for " + endpointName);
        }
    }
    
    private void validateSchemas(JsonNode spec, ContainerApi container) {
        ModuleResult result = new ModuleResult("COMPLETED");
        
        if (spec.has("components") && spec.get("components").has("schemas")) {
            JsonNode schemas = spec.get("components").get("schemas");
            
            schemas.fieldNames().forEachRemaining(schemaName -> {
                JsonNode schema = schemas.get(schemaName);
                validateSchema(schema, schemaName, result);
            });
        }
        
        container.addValidatorResult("schemas", result);
    }
    
    private void validateSchema(JsonNode schema, String schemaName, ModuleResult result) {
        if (!schema.has("type") && !schema.has("$ref")) {
            result.addFinding("Schema '" + schemaName + "' missing 'type' or '$ref'");
        }
        
        if (schema.has("properties")) {
            JsonNode properties = schema.get("properties");
            properties.fieldNames().forEachRemaining(propertyName -> {
                JsonNode property = properties.get(propertyName);
                if (!property.has("type")) {
                    result.addFinding("Property '" + propertyName + "' in schema '" + schemaName + "' missing 'type'");
                }
            });
        }
    }
    
    private void validateParameters(JsonNode spec, ContainerApi container) {
        ModuleResult result = new ModuleResult("COMPLETED");
        JsonNode paths = spec.get("paths");
        
        paths.fieldNames().forEachRemaining(path -> {
            JsonNode pathItem = paths.get(path);
            pathItem.fieldNames().forEachRemaining(method -> {
                if (isHttpMethod(method)) {
                    JsonNode endpoint = pathItem.get(method);
                    if (endpoint.has("parameters")) {
                        validateParameterDefinitions(endpoint.get("parameters"), path + " " + method, result);
                    }
                }
            });
        });
        
        container.addValidatorResult("parameters", result);
    }
    
    private void validateParameterDefinitions(JsonNode parameters, String endpoint, ModuleResult result) {
        for (JsonNode param : parameters) {
            if (!param.has("name")) {
                result.addFinding("Parameter missing 'name' in " + endpoint);
            }
            if (!param.has("in")) {
                result.addFinding("Parameter missing 'in' (query, path, header) in " + endpoint);
            }
            if (!param.has("schema") && !param.has("type")) {
                result.addFinding("Parameter missing 'schema' or 'type' in " + endpoint);
            }
        }
    }
    
    private boolean isHttpMethod(String method) {
        return method.equals("get") || method.equals("post") || 
               method.equals("put") || method.equals("delete") || 
               method.equals("patch") || method.equals("head") || 
               method.equals("options") || method.equals("trace");
    }
}