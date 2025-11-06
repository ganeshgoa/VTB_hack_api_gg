package com.apisecurity.input;

import com.apisecurity.shared.*;
import com.apisecurity.validator.ValidatorModule;
import com.apisecurity.analyzer.AnalyzerModule;
import com.apisecurity.ai.AIModule;
import com.apisecurity.testing.TestingModule;
import com.apisecurity.reportmaker.ReportMakerModule;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.FileWriter;
import java.util.*;

public class InputProcessor {
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public ContainerApi processInput(String openApiSpec, String configJson) throws Exception {
        System.out.println("🚀 Starting API Security Analysis...");
        
        // Парсинг конфигурации
        Configuration config = parseConfiguration(configJson);
        ContainerApi container = new ContainerApi();
        container.setConfiguration(config);
        
        // Обработка OpenAPI спецификации
        JsonNode fullSpec = resolveReferences(openApiSpec);
        container.setFullSpecification(fullSpec);
        
        // Создание таблицы эндпоинтов
        createAnalysisTable(fullSpec, container);
        
        // Сохранение полной спецификации
        saveFullSpecification(fullSpec);
        
        // Запуск модулей
        startModules(config, container);
        
        System.out.println("✅ API Security Analysis completed!");
        return container;
    }
    
    private Configuration parseConfiguration(String configJson) throws Exception {
        return objectMapper.readValue(configJson, Configuration.class);
    }
    
    private JsonNode resolveReferences(String openApiSpec) throws Exception {
        System.out.println("🔍 Resolving $ref references...");
        JsonNode rootNode = objectMapper.readTree(openApiSpec);
        ReferenceResolver resolver = new ReferenceResolver(objectMapper);
        return resolver.resolveReferences(rootNode);
    }
    
    private void createAnalysisTable(JsonNode fullSpec, ContainerApi container) {
        System.out.println("📊 Creating analysis table...");
        AnalysisTableCreator tableCreator = new AnalysisTableCreator();
        tableCreator.createTable(fullSpec, container);
    }
    
    private void saveFullSpecification(JsonNode fullSpec) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        
        String fullSpecJson = objectMapper.writeValueAsString(fullSpec);
        
        // Сохраняем в файл
        try (FileWriter writer = new FileWriter("reports/full-specification.json")) {
            writer.write(fullSpecJson);
            System.out.println("💾 Full specification saved: reports/full-specification.json");
        }
        
        System.out.println("📄 Full specification processed (" + fullSpecJson.length() + " characters)");
    }
    
    private void startModules(Configuration config, ContainerApi container) {
        List<Thread> threads = new ArrayList<>();
        long startTime = System.currentTimeMillis();
        
        if (config.isValidatorEnabled()) {
            threads.add(new Thread(() -> {
                System.out.println("🔧 Starting Validator module...");
                new ValidatorModule().process(container);
            }));
        }
        
        if (config.isAnalyzerEnabled()) {
            threads.add(new Thread(() -> {
                System.out.println("🛡️ Starting Analyzer module...");
                new AnalyzerModule().process(container);
            }));
        }
        
        if (config.isAiEnabled()) {
            threads.add(new Thread(() -> {
                System.out.println("🤖 Starting AI module...");
                new AIModule().process(container);
            }));
        }
        
        if (config.isTestingEnabled()) {
            threads.add(new Thread(() -> {
                System.out.println("🧪 Starting Testing module...");
                new TestingModule().process(container);
            }));
        }
        
        // Запуск всех потоков
        threads.forEach(Thread::start);
        
        // Ожидание завершения
        threads.forEach(thread -> {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.err.println("❌ Thread interrupted: " + e.getMessage());
            }
        });
        
        // Запуск reportmaker после всех модулей
        if (config.isReportmakerEnabled()) {
            System.out.println("📄 Starting ReportMaker module...");
            new ReportMakerModule().process(container);
        }
        
        long endTime = System.currentTimeMillis();
        System.out.println("⏱️ Total execution time: " + (endTime - startTime) + "ms");
    }
}