package com.apisecurity.shared;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

public class ContainerApi {
    private JsonNode fullSpecification;
    private Map<String, ModuleResult> validatorResults = new HashMap<>();
    private Map<String, ModuleResult> analyzerResults = new HashMap<>();
    private Map<String, ModuleResult> aiResults = new HashMap<>();
    private Map<String, ModuleResult> testingResults = new HashMap<>();
    private Map<String, List<String>> recommendations = new HashMap<>();
    private List<EndpointAnalysis> analysisTable = new ArrayList<>();
    private Configuration configuration;
    private Map<String, Object> discoveredParameterValues = new HashMap<>(); // <-- НОВОЕ
    private String baseUrl;
    public JsonNode getFullSpecification() { return fullSpecification; }
    public void setFullSpecification(JsonNode fullSpecification) { this.fullSpecification = fullSpecification; }
    
    public Map<String, ModuleResult> getValidatorResults() { return validatorResults; }
    public Map<String, ModuleResult> getAnalyzerResults() { return analyzerResults; }
    public Map<String, ModuleResult> getAiResults() { return aiResults; }
    public Map<String, ModuleResult> getTestingResults() { return testingResults; }
    public Map<String, List<String>> getRecommendations() { return recommendations; }
    
    public List<EndpointAnalysis> getAnalysisTable() { return analysisTable; }
    public void addEndpointAnalysis(EndpointAnalysis endpointAnalysis) {
        this.analysisTable.add(endpointAnalysis);
    }
    
    public void addValidatorResult(String endpoint, ModuleResult result) {
        this.validatorResults.put(endpoint, result);
    }
    
    public void addAnalyzerResult(String endpoint, ModuleResult result) {
        this.analyzerResults.put(endpoint, result);
    }
    
    public void addAiResult(String endpoint, ModuleResult result) {
        this.aiResults.put(endpoint, result);
    }
    
    public void addTestingResult(String endpoint, ModuleResult result) {
        this.testingResults.put(endpoint, result);
    }
    
    public void addRecommendation(String endpoint, String recommendation) {
        this.recommendations.computeIfAbsent(endpoint, k -> new ArrayList<>()).add(recommendation);
    }

    public Configuration getConfiguration() { return configuration; }
    public void setConfiguration(Configuration configuration) { 
        this.configuration = configuration;
    }

    // НОВЫЕ геттер и сеттер
    public Map<String, Object> getDiscoveredParameterValues() {
        return discoveredParameterValues;
    }

    public void setDiscoveredParameterValues(Map<String, Object> discoveredParameterValues) {
        this.discoveredParameterValues = discoveredParameterValues;
    }
    // ✅ ДОБАВЛЕНО: методы для baseUrl
    public String getAnalyzerBaseUrl() {
        return this.baseUrl.trim().replaceAll("/+$", "");
    }

    public void setAnalyzerBaseUrl(String baseUrl) {
        if (baseUrl != null && !baseUrl.trim().isEmpty()) {
            this.baseUrl = baseUrl.trim();
        }
    }
}