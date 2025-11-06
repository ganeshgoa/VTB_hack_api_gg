package com.apisecurity.shared;

import java.util.Arrays;
import java.util.List;

public class OpenAIConfig {
    private String apiKey;
    private String baseUrl = "https://openrouter.ai/api/v1";
    private List<String> models = Arrays.asList(
        "deepseek/deepseek-r1-distill-llama-70b",
        "deepseek/deepseek-r1-0528-qwen3-8b"
    );
    private int timeoutSeconds = 30;
    
    // Конструкторы
    public OpenAIConfig() {}
    
    public OpenAIConfig(String apiKey) {
        this.apiKey = apiKey;
    }
    
    // Геттеры и сеттеры
    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    
    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    
    public List<String> getModels() { return models; }
    public void setModels(List<String> models) { this.models = models; }
    
    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
    
    @Override
    public String toString() {
        return String.format("OpenAIConfig{baseUrl='%s', models=%s, timeoutSeconds=%d}", 
                           baseUrl, models, timeoutSeconds);
    }
}