package com.apisecurity.analyzer;

import com.apisecurity.shared.*;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class AnalyzerModule {
    
    public void process(ContainerApi container) {
        long startTime = System.currentTimeMillis();
        System.out.println("🛡️ Starting OWASP Top 10 security analysis...");
        
        JsonNode spec = container.getFullSpecification();
        
        // OWASP Top 10 анализ
        checkBOLA(spec, container);
        checkIDOR(spec, container);
        checkInjection(spec, container);
        checkAuthentication(spec, container);
        checkDataExposure(spec, container);
        checkMassAssignment(spec, container);
        checkSecurityMisconfiguration(spec, container);
        
        long endTime = System.currentTimeMillis();
        System.out.println("✅ Security analysis completed in " + (endTime - startTime) + "ms");
    }
    
    private void checkBOLA(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Broken Object Level Authorization (BOLA)...");
        
        JsonNode paths = spec.get("paths");
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (containsIdParameter(endpointName)) {
                // Проверка эндпоинтов с ID параметрами
                if (!hasProperAuthorization(endpointName, spec)) {
                    result.addFinding("Potential BOLA vulnerability: endpoint with ID parameters may lack proper authorization checks");
                    result.addDetail("risk_level", "HIGH");
                    result.addDetail("owasp_category", "API1:2023 - Broken Object Level Authorization");
                }
            }
            
            container.addAnalyzerResult(endpointName + "_bola", result);
            analysis.setAnalyzer(result.getFindings().isEmpty() ? "No BOLA issues" : result.toString());
        }
        
        container.addAnalyzerResult("bola_global", globalResult);
    }
    
    private void checkIDOR(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Insecure Direct Object References (IDOR)...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (hasDirectObjectReferences(endpointName, spec)) {
                result.addFinding("Potential IDOR vulnerability: direct object references detected");
                result.addDetail("risk_level", "MEDIUM");
                result.addDetail("owasp_category", "API1:2023 - Broken Object Level Authorization");
            }
            
            container.addAnalyzerResult(endpointName + "_idor", result);
        }
        
        container.addAnalyzerResult("idor_global", globalResult);
    }
    
    private void checkInjection(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Injection vulnerabilities...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (hasUnvalidatedInput(endpointName, spec)) {
                result.addFinding("Potential injection vulnerability: unvalidated input parameters detected");
                result.addDetail("risk_level", "HIGH");
                result.addDetail("owasp_category", "API8:2023 - Injection");
            }
            
            container.addAnalyzerResult(endpointName + "_injection", result);
        }
        
        container.addAnalyzerResult("injection_global", globalResult);
    }
    
    private void checkAuthentication(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Authentication issues...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        boolean hasUnauthenticatedEndpoints = false;
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (!hasAuthentication(endpointName, spec)) {
                result.addFinding("Endpoint without authentication: potential security risk");
                result.addDetail("risk_level", "HIGH");
                result.addDetail("owasp_category", "API2:2023 - Broken Authentication");
                hasUnauthenticatedEndpoints = true;
            }
            
            container.addAnalyzerResult(endpointName + "_auth", result);
        }
        
        if (hasUnauthenticatedEndpoints) {
            globalResult.addFinding("Found endpoints without authentication requirements");
        }
        
        container.addAnalyzerResult("authentication_global", globalResult);
    }
    
    private void checkDataExposure(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Excessive Data Exposure...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (mayExposeSensitiveData(endpointName, spec)) {
                result.addFinding("Potential excessive data exposure: endpoint may return sensitive information");
                result.addDetail("risk_level", "MEDIUM");
                result.addDetail("owasp_category", "API3:2023 - Broken Object Property Level Authorization");
            }
            
            container.addAnalyzerResult(endpointName + "_data_exposure", result);
        }
        
        container.addAnalyzerResult("data_exposure_global", globalResult);
    }
    
    private void checkMassAssignment(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Mass Assignment vulnerabilities...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            ModuleResult result = new ModuleResult("COMPLETED");
            String endpointName = analysis.getEndpointName();
            
            if (isPostOrPutMethod(endpointName) && hasLargePayload(endpointName, spec)) {
                result.addFinding("Potential mass assignment vulnerability: large payload without validation");
                result.addDetail("risk_level", "MEDIUM");
                result.addDetail("owasp_category", "API6:2023 - Unrestricted Access to Sensitive Business Flows");
            }
            
            container.addAnalyzerResult(endpointName + "_mass_assignment", result);
        }
        
        container.addAnalyzerResult("mass_assignment_global", globalResult);
    }
    
    private void checkSecurityMisconfiguration(JsonNode spec, ContainerApi container) {
        System.out.println("  🔍 Checking Security Misconfigurations...");
        
        ModuleResult globalResult = new ModuleResult("COMPLETED");
        
        // Проверка на debug endpoints
        if (hasDebugEndpoints(spec)) {
            globalResult.addFinding("Potential debug endpoints detected");
            globalResult.addDetail("risk_level", "HIGH");
        }
        
        // Проверка на test data exposure
        if (mayExposeTestData(spec)) {
            globalResult.addFinding("Potential test data exposure");
            globalResult.addDetail("risk_level", "MEDIUM");
        }
        
        container.addAnalyzerResult("security_misconfig_global", globalResult);
    }
    
    // Вспомогательные методы для анализа
    private boolean containsIdParameter(String endpointName) {
        return endpointName.matches(".*/\\{.*[Ii]d.*\\}.*") || 
               endpointName.matches(".*/\\{.*[Uu]ser.*\\}.*") ||
               endpointName.matches(".*/\\{.*[Aa]ccount.*\\}.*");
    }
    
    private boolean hasProperAuthorization(String endpointName, JsonNode spec) {
        // Упрощенная проверка - в реальном приложении нужен более сложный анализ
        return endpointName.contains("/auth/") || 
               endpointName.contains("/admin/") ||
               hasSecurityDefinitions(endpointName, spec);
    }
    
    private boolean hasSecurityDefinitions(String endpointName, JsonNode spec) {
        // Проверка наличия security definitions в спецификации
        return spec.has("components") && 
               spec.get("components").has("securitySchemes");
    }
    
    private boolean hasDirectObjectReferences(String endpointName, JsonNode spec) {
        return endpointName.matches(".*/\\{.*\\}.*") && 
               !endpointName.contains("/auth/");
    }
    
    private boolean hasUnvalidatedInput(String endpointName, JsonNode spec) {
        return endpointName.contains("query") || 
               endpointName.contains("search") ||
               endpointName.contains("filter");
    }
    
    private boolean hasAuthentication(String endpointName, JsonNode spec) {
        // Проверка public endpoints которые не должны требовать аутентификации
        if (endpointName.contains("/public/") || 
            endpointName.contains("/health") ||
            endpointName.contains("/docs")) {
            return true; // Это нормально для public endpoints
        }
        
        return hasSecurityDefinitions(endpointName, spec);
    }
    
    private boolean mayExposeSensitiveData(String endpointName, JsonNode spec) {
        return endpointName.contains("/user") || 
               endpointName.contains("/account") ||
               endpointName.contains("/profile") ||
               endpointName.contains("/personal");
    }
    
    private boolean isPostOrPutMethod(String endpointName) {
        return endpointName.startsWith("POST") || endpointName.startsWith("PUT");
    }
    
    private boolean hasLargePayload(String endpointName, JsonNode spec) {
        // Упрощенная проверка - в реальном приложении анализировать схемы
        return endpointName.contains("/create") || 
               endpointName.contains("/update") ||
               endpointName.contains("/bulk");
    }
    
    private boolean hasDebugEndpoints(JsonNode spec) {
        JsonNode paths = spec.get("paths");
        for (Iterator<String> it = paths.fieldNames(); it.hasNext(); ) {
            String path = it.next();
            if (path.contains("/debug") || path.contains("/test") || 
                path.contains("/admin") || path.contains("/console")) {
                return true;
            }
        }
        return false;
    }
    
    private boolean mayExposeTestData(JsonNode spec) {
        if (spec.has("info") && spec.get("info").has("description")) {
            String description = spec.get("info").get("description").asText().toLowerCase();
            return description.contains("test") || description.contains("sandbox") || 
                   description.contains("example") || description.contains("demo");
        }
        return false;
    }
}