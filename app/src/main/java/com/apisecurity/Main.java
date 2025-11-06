package com.apisecurity;

import com.apisecurity.input.InputProcessor;
import com.apisecurity.shared.Configuration;
import com.apisecurity.shared.ContainerApi;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        System.out.println("🔒 API Security Analyzer v1.0.0");
        System.out.println("================================\n");
        
        try {
            // Загрузка спецификации OpenAPI
            String openApiSpec = loadFile("openapi_s.json");
            if (openApiSpec == null) {
                System.err.println("❌ OpenAPI specification file 'openapi_s.json' not found");
                return;
            }
            
            // Загрузка конфигурации
            String configJson = loadFile("config.json");
            if (configJson == null) {
                // Использование конфигурации по умолчанию
                configJson = """
                    {
                        "validatorEnabled": true,
                        "analyzerEnabled": true,
                        "aiEnabled": false,
                        "testingEnabled": true,
                        "reportmakerEnabled": true,
                        "aiConfig": {
                            "apiKey": "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",
                            "models": ["deepseek/deepseek-r1-distill-llama-70b"]
                        }
                    }
                    """;
                System.out.println("⚠️ Using default configuration (AI disabled - set OPENROUTER_API_KEY env variable to enable)");
            }
            
            // Запуск анализа
            InputProcessor processor = new InputProcessor();
            ContainerApi container = processor.processInput(openApiSpec, configJson);
            
            System.out.println("\n🎉 Analysis completed successfully!");
            System.out.println("📊 Check the 'reports/' directory for detailed analysis results.");
            
        } catch (Exception e) {
            System.err.println("❌ Analysis failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String loadFile(String filename) {
        try {
            // Явно указываем кодировку UTF-8 при чтении файла
            return new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
        } catch (Exception e) {
            System.err.println("❌ Error reading file " + filename + ": " + e.getMessage());
            return null;
        }
    }
}