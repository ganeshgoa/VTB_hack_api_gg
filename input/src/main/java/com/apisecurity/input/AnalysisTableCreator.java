package com.apisecurity.input;

import com.apisecurity.shared.ContainerApi;
import com.apisecurity.shared.EndpointAnalysis;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Iterator;

public class AnalysisTableCreator {
    
    public void createTable(JsonNode fullSpec, ContainerApi container) {
        JsonNode paths = fullSpec.get("paths");
        if (paths == null) {
            System.err.println("❌ No paths found in OpenAPI specification");
            return;
        }
        
        int endpointNumber = 1;
        
        for (Iterator<String> it = paths.fieldNames(); it.hasNext(); ) {
            String path = it.next();
            JsonNode pathItem = paths.get(path);
            
            for (Iterator<String> methodIt = pathItem.fieldNames(); methodIt.hasNext(); ) {
                String method = methodIt.next();
                if (isHttpMethod(method)) {
                    String endpointName = method.toUpperCase() + " " + path;
                    
                    EndpointAnalysis analysis = new EndpointAnalysis(endpointName, endpointNumber++);
                    container.addEndpointAnalysis(analysis);
                    
                    System.out.println("📝 Added endpoint: " + endpointName);
                }
            }
        }
        
        System.out.println("✅ Analysis table created with " + (endpointNumber - 1) + " endpoints");
    }
    
    private boolean isHttpMethod(String method) {
        return method.equals("get") || method.equals("post") || 
               method.equals("put") || method.equals("delete") || 
               method.equals("patch") || method.equals("head") || 
               method.equals("options") || method.equals("trace");
    }
}