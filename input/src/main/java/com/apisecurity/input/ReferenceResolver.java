package com.apisecurity.input;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class ReferenceResolver {
    private final ObjectMapper objectMapper;
    
    public ReferenceResolver(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
    
    public JsonNode resolveReferences(JsonNode rootNode) {
        return resolveReferencesRecursive(rootNode, rootNode, "#");
    }
    
    private JsonNode resolveReferencesRecursive(JsonNode currentNode, JsonNode rootNode, String currentPath) {
        if (currentNode.isObject()) {
            ObjectNode resultNode = objectMapper.createObjectNode();
            currentNode.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                JsonNode value = entry.getValue();
                
                if ("$ref".equals(key) && value.isTextual()) {
                    String refPath = value.asText();
                    if (refPath.startsWith("#/")) {
                        JsonNode resolved = resolveReference(refPath, rootNode);
                        if (resolved != null) {
                            resultNode.setAll((ObjectNode) resolveReferencesRecursive(resolved, rootNode, refPath));
                        }
                    }
                } else {
                    resultNode.set(key, resolveReferencesRecursive(value, rootNode, currentPath + "/" + key));
                }
            });
            return resultNode;
        } else if (currentNode.isArray()) {
            var resultArray = objectMapper.createArrayNode();
            for (JsonNode element : currentNode) {
                resultArray.add(resolveReferencesRecursive(element, rootNode, currentPath));
            }
            return resultArray;
        }
        return currentNode;
    }
    
    private JsonNode resolveReference(String refPath, JsonNode rootNode) {
        String[] pathSegments = refPath.substring(2).split("/");
        JsonNode current = rootNode;
        
        for (String segment : pathSegments) {
            current = current.get(segment);
            if (current == null) {
                System.err.println("⚠️ Reference not found: " + refPath);
                return null;
            }
        }
        return current;
    }
}