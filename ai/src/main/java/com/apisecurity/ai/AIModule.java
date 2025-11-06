package com.apisecurity.ai;
import com.apisecurity.shared.ModuleResult;
import com.apisecurity.shared.EndpointAnalysis;
import com.apisecurity.shared.ContainerApi;
import com.apisecurity.shared.Configuration;
import com.apisecurity.shared.OpenAIConfig;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;


public class AIModule {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OkHttpClient httpClient;
    
    private static final String PROMPT_TEMPLATE = """
        Анализируй OpenAPI спецификацию на уязвимости безопасности API.
        
        Формат ответа (ТОЛЬКО JSON):
        {
            "vulnerabilities": [
                {
                    "type": "тип",
                    "endpoint": "метод путь", 
                    "severity": "высокая/средняя/низкая",
                    "description": "описание",
                    "recommendation": "рекомендация"
                }
            ],
            "overall_recommendations": ["recommendation1", "recommendation2"]
        }
        
        Критерии: аутентификация, авторизация, инъекции, валидация данных, чувствительные данные.
        
        Спецификация:
        %s
        
        Ответь ТОЛЬКО в указанном JSON формате.
        """;
    
    private static final List<String> WORKING_MODELS = Arrays.asList(
        "deepseek/deepseek-r1-distill-llama-70b",
        "meta-llama/llama-3.3-70b-instruct", 
        "qwen/qwen-2.5-coder-32b-instruct",
        "google/gemini-2.0-flash-exp",
        "meta-llama/llama-3.1-8b-instruct",
        "microsoft/wizardlm-2-8x22b",
        "qwen/qwen-2.5-coder-32b-instruct"
    );
    
    public AIModule() {
        this.objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, false);
        this.objectMapper.configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES, false);
        
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }
    
    public void process(ContainerApi container) {
        try {
            Files.createDirectories(Paths.get("reports/ai_responses"));
        } catch (IOException e) {
            System.err.println("⚠️ Failed to create AI responses directory: " + e.getMessage());
        }
        long startTime = System.currentTimeMillis();
        System.out.println("🤖 Starting AI security analysis...");
    
        JsonNode spec = container.getFullSpecification();
        String apiSpec = spec.toString();
        
        // СИЛЬНО ограничим размер спецификации
        if (apiSpec.length() > 25000) {
            apiSpec = apiSpec.substring(0, 25000) + "... [truncated]";
            System.out.println("📏 API spec truncated to 12000 chars");
        }
    
        final OpenAIConfig aiConfigFinal = getAIConfig(container);
        final String apiSpecFinal = apiSpec;

        List<String> modelsToUse = WORKING_MODELS;
        System.out.println("🎯 Using models: " + modelsToUse);
        
        List<AIResponse> successfulResponses = new ArrayList<>();
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        List<Future<AIResponse>> futures = new ArrayList<>();

        for (String model : modelsToUse) {
            futures.add(executor.submit(() -> {
                try {
                    Thread.sleep(1000); // Задержка 1 секунда между запросами
                    return analyzeWithModel(model, apiSpecFinal, aiConfigFinal);
                } catch (Exception e) {
                    System.err.println("❌ " + model + " failed: " + e.getMessage());
                    return new AIResponse(model, Collections.emptyList(), Collections.emptyList());
                }
            }));
        }

        for (Future<AIResponse> future : futures) {
            try {
                AIResponse response = future.get(2, TimeUnit.MINUTES);
                if (!response.getVulnerabilities().isEmpty() || !response.getOverallRecommendations().isEmpty()) {
                    successfulResponses.add(response);
                    
                    // Сохраняем ответ модели в отдельный файл
                    saveModelResponseToFile(response, apiSpecFinal.substring(0, Math.min(apiSpecFinal.length(), 2000)));
                    
                    processSingleAIResponse(response, container);
                }
            } catch (Exception e) {
                System.err.println("❌ Error: " + e.getMessage());
            }
        }
        
        executor.shutdown();
    
        long endTime = System.currentTimeMillis();
        System.out.println("✅ AI analysis completed in " + (endTime - startTime) + "ms");
        System.out.println("📊 Successful: " + successfulResponses.size() + "/" + modelsToUse.size());
    }
    
    private OpenAIConfig getAIConfig(ContainerApi container) {
        if (container.getConfiguration() != null && 
            container.getConfiguration().getAiConfig() != null &&
            container.getConfiguration().getAiConfig().getApiKey() != null) {
            
            OpenAIConfig aiConfig = container.getConfiguration().getAiConfig();
            System.out.println("✅ Using API key from configuration");
            return aiConfig;
        }
    
        OpenAIConfig aiConfig = new OpenAIConfig();
        String apiKey = System.getenv("OPENROUTER_API_KEY");
    
        if (apiKey == null || apiKey.trim().isEmpty()) {
            apiKey = "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";
            System.out.println("⚠️  Using hardcoded API key");
        }
    
        aiConfig.setApiKey(apiKey);
        return aiConfig;
    }
    
    private AIResponse analyzeWithModel(String model, String apiSpec, OpenAIConfig config) throws Exception {
        System.out.println("  🤖 Analyzing with: " + model);
        
        String prompt = String.format(PROMPT_TEMPLATE, apiSpec);
        System.out.println("  📝 Prompt length: " + prompt.length() + " chars");
        
        try {
            String response = callOpenRouterAPI(model, prompt, config);
            saveRawResponseToFile(model, response, prompt);
            return parseAIResponse(response, model);
        } catch (Exception e) {
            System.err.println("  ❌ Model " + model + " failed: " + e.getMessage());
            // Попробуем с сокращенным промптом
            if (prompt.length() > 30000) {
                System.out.println("  🔄 Retrying with shorter prompt...");
                String shortPrompt = prompt.substring(0, 30000) + "... [truncated]";
                try {
                    String response = callOpenRouterAPI(model, shortPrompt, config);
                    return parseAIResponse(response, model);
                } catch (Exception ex) {
                    System.err.println("  ❌ Retry also failed: " + ex.getMessage());
                }
            }
            throw e;
        }
    }
    
    private String callOpenRouterAPI(String model, String prompt, OpenAIConfig config) throws Exception {
        String apiKey = config.getApiKey().trim();
        String fullUrl = "https://openrouter.ai/api/v1/chat/completions";

        // Создаем JSON запрос
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("model", model);
        
        List<Map<String, String>> messages = new ArrayList<>();
        Map<String, String> message = new HashMap<>();
        message.put("role", "user");
        message.put("content", prompt);
        messages.add(message);
        
        requestMap.put("messages", messages);
        requestMap.put("max_tokens", 4000);
        requestMap.put("temperature", 0.1);
        
        // Инициализируем requestBody
        String requestBody = objectMapper.writeValueAsString(requestMap);
        
        System.out.println("    🔄 Sending request to: " + fullUrl);
        System.out.println("    📦 Request body size: " + requestBody.length() + " chars");
        
        // Создаем HTTP запрос с явным указанием UTF-8
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        RequestBody body = RequestBody.create(requestBody, JSON);
        
        Request request = new Request.Builder()
            .url(fullUrl)
            .header("Authorization", "Bearer " + apiKey)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("HTTP-Referer", "https://github.com/apisecurity-analyzer")
            .header("X-Title", "API Security Analyzer")
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body().string();
                System.err.println("    ❌ API Error: " + errorBody);
                throw new RuntimeException("HTTP " + response.code() + ": " + errorBody);
            }
            
            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                throw new RuntimeException("Empty response body");
            }
            
            String responseText = responseBody.string();
            System.out.println("    📥 Raw response length: " + responseText.length());
            System.out.println("    📥 Response preview: " + 
                responseText.substring(0, Math.min(responseText.length(), 300)));
            
            JsonNode jsonResponse = objectMapper.readTree(responseText);
            
            String content = jsonResponse.path("choices").get(0).path("message").path("content").asText();
            System.out.println("    ✅ Extracted content length: " + content.length());
            System.out.println("    ✅ Content preview: " + content.substring(0, Math.min(content.length(), 200)));
            
            return content;
        }
    }
    
    private AIResponse parseAIResponse(String response, String model) {
        System.out.println("    🔍 Parsing response from " + model);
        System.out.println("    📄 Response length: " + response.length());
        System.out.println("    📄 Response preview: " + response.substring(0, Math.min(response.length(), 300)));
        
        try {
            // Очистка ответа от возможных не-JSON частей
            String cleanResponse = response.trim();
            
            // Удаляем BOM маркер если есть
            if (cleanResponse.startsWith("\uFEFF")) {
                cleanResponse = cleanResponse.substring(1);
            }
            
            // Ищем JSON в ответе
            int jsonStart = cleanResponse.indexOf('{');
            int jsonEnd = cleanResponse.lastIndexOf('}') + 1;
            
            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                cleanResponse = cleanResponse.substring(jsonStart, jsonEnd);
            }
            
            System.out.println("    🔧 Cleaned response: " + cleanResponse.substring(0, Math.min(cleanResponse.length(), 300)));
            
            JsonNode jsonNode = objectMapper.readTree(cleanResponse);
            
            List<AIVulnerability> vulnerabilities = new ArrayList<>();
            List<String> recommendations = new ArrayList<>();
            
            if (jsonNode.has("vulnerabilities")) {
                for (JsonNode vulnNode : jsonNode.get("vulnerabilities")) {
                    AIVulnerability vuln = new AIVulnerability();
                    vuln.setType(vulnNode.path("type").asText(""));
                    vuln.setEndpoint(vulnNode.path("endpoint").asText(""));
                    vuln.setSeverity(vulnNode.path("severity").asText(""));
                    vuln.setDescription(vulnNode.path("description").asText(""));
                    vuln.setRecommendation(vulnNode.path("recommendation").asText(""));
                    
                    // Логируем найденные уязвимости для отладки
                    if (!vuln.getType().isEmpty()) {
                        System.out.println("      ✅ Found: " + vuln.getType() + " at " + vuln.getEndpoint());
                        vulnerabilities.add(vuln);
                    }
                }
            }
            
            if (jsonNode.has("overall_recommendations")) {
                for (JsonNode recNode : jsonNode.get("overall_recommendations")) {
                    String recommendation = recNode.asText("");
                    if (!recommendation.isEmpty()) {
                        recommendations.add(recommendation);
                        System.out.println("      💡 Recommendation: " + recommendation.substring(0, Math.min(recommendation.length(), 100)));
                    }
                }
            }
            
            System.out.println("    ✅ " + model + " found " + vulnerabilities.size() + " vulnerabilities and " + recommendations.size() + " recommendations");
            return new AIResponse(model, vulnerabilities, recommendations);
            
        } catch (Exception e) {
            System.err.println("    ⚠️ JSON parse failed for " + model + ": " + e.getMessage());
            System.err.println("    📋 Problematic response: " + response.substring(0, Math.min(response.length(), 500)));
            e.printStackTrace();
            return new AIResponse(model, Collections.emptyList(), Collections.emptyList());
        }
    }
    private void saveModelResponseToFile(AIResponse response, String apiSpecPreview) {
        try {
            String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            String safeModelName = response.getModel().replace("/", "_").replace(":", "_");
            String filename = String.format("reports/ai_responses/%s_%s.txt", safeModelName, timestamp);
            
            Files.createDirectories(Paths.get("reports/ai_responses"));
            
            try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(filename), StandardCharsets.UTF_8))) {
                
                writer.println("=".repeat(80));
                writer.println("AI MODEL SECURITY ANALYSIS REPORT");
                writer.println("=".repeat(80));
                writer.println();
                writer.println("Model:        " + response.getModel());
                writer.println("Timestamp:    " + new Date());
                writer.println("Vulnerabilities: " + response.getVulnerabilities().size());
                writer.println("Recommendations: " + response.getOverallRecommendations().size());
                writer.println();
                
                writer.println("API SPECIFICATION PREVIEW");
                writer.println("-".repeat(80));
                writer.println(apiSpecPreview);
                writer.println();
                
                if (!response.getVulnerabilities().isEmpty()) {
                    writer.println("DETECTED VULNERABILITIES");
                    writer.println("-".repeat(80));
                    int counter = 1;
                    for (AIVulnerability vuln : response.getVulnerabilities()) {
                        writer.println(counter + ". [" + vuln.getSeverity().toUpperCase() + "] " + vuln.getType());
                        writer.println("   Endpoint:     " + vuln.getEndpoint());
                        writer.println("   Description:  " + vuln.getDescription());
                        writer.println("   Recommendation: " + vuln.getRecommendation());
                        writer.println();
                        counter++;
                    }
                } else {
                    writer.println("No vulnerabilities detected.");
                    writer.println();
                }
                
                if (!response.getOverallRecommendations().isEmpty()) {
                    writer.println("OVERALL RECOMMENDATIONS");
                    writer.println("-".repeat(80));
                    int counter = 1;
                    for (String recommendation : response.getOverallRecommendations()) {
                        writer.println(counter + ". " + recommendation);
                        counter++;
                    }
                }
                
                writer.println();
                writer.println("=".repeat(80));
                writer.println("End of Report");
                writer.println("=".repeat(80));
                
                System.out.println("    💾 Saved model response to: " + filename);
            }
        } catch (Exception e) {
            System.err.println("    ❌ Failed to save model response: " + e.getMessage());
        }
    }

    private void saveRawResponseToFile(String model, String rawResponse, String prompt) {
        try {
            String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            String filename = String.format("reports/ai_responses/raw_%s_%s.json", 
                model.replace("/", "_"), timestamp);
            
            Files.createDirectories(Paths.get("reports/ai_responses"));
            
            try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(filename), StandardCharsets.UTF_8))) {
                
                Map<String, Object> rawData = new HashMap<>();
                rawData.put("model", model);
                rawData.put("timestamp", new Date().toString());
                rawData.put("prompt_preview", prompt.substring(0, Math.min(prompt.length(), 1000)));
                rawData.put("raw_response", rawResponse);
                
                writer.write(objectMapper.writeValueAsString(rawData));
                System.out.println("    💾 Saved raw response to: " + filename);
            }
        } catch (Exception e) {
            System.err.println("    ❌ Failed to save raw response: " + e.getMessage());
        }
    }

    private void processSingleAIResponse(AIResponse response, ContainerApi container) {
        ModuleResult result = new ModuleResult("COMPLETED");
        result.addDetail("model", response.getModel());
        
        for (AIVulnerability vuln : response.getVulnerabilities()) {
            String finding = String.format("[%s] %s: %s (Severity: %s)", 
                vuln.getType(), vuln.getEndpoint(), vuln.getDescription(), vuln.getSeverity());
            result.addFinding(finding);
            
            if (vuln.getEndpoint() != null && !vuln.getEndpoint().isEmpty()) {
                container.addRecommendation(vuln.getEndpoint(), vuln.getRecommendation());
            }
        }
        
        for (String recommendation : response.getOverallRecommendations()) {
            result.addDetail("recommendation", recommendation);
        }
        
        container.addAiResult("ai_analysis_" + response.getModel(), result);
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            if (!response.getVulnerabilities().isEmpty()) {
                analysis.setAi("Found " + response.getVulnerabilities().size() + " vulnerabilities");
                analysis.setRecommendation("Review AI security findings");
            }
        }
    }
}

class AIResponse {
    private String model;
    private List<AIVulnerability> vulnerabilities;
    private List<String> overallRecommendations;
    
    public AIResponse(String model, List<AIVulnerability> vulnerabilities, List<String> overallRecommendations) {
        this.model = model;
        this.vulnerabilities = vulnerabilities;
        this.overallRecommendations = overallRecommendations;
    }
    
    public String getModel() { return model; }
    public List<AIVulnerability> getVulnerabilities() { return vulnerabilities; }
    public List<String> getOverallRecommendations() { return overallRecommendations; }
}

class AIVulnerability {
    private String type;
    private String endpoint;
    private String severity;
    private String description;
    private String recommendation;
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
}