package com.apisecurity.reportmaker;

import com.apisecurity.shared.ContainerApi;
import com.apisecurity.shared.Configuration;
import com.apisecurity.shared.EndpointAnalysis;
import com.apisecurity.shared.ModuleResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.JsonNode; 
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;

public class ReportMakerModule {
    private final ObjectMapper objectMapper;
    
    public ReportMakerModule() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }
    
    public void process(ContainerApi container) {
        long startTime = System.currentTimeMillis();
        System.out.println("📄 Generating security reports...");
        
        // Создание директории для отчетов
        createReportsDirectory();

        // Генерация отчетов спецификации ← ДОБАВЬТЕ ЭТУ СТРОЧКУ
        generateSpecificationReport(container);
        
        // Генерация HTML отчета
        generateHTMLReport(container);
        
        // Генерация JSON отчета
        generateJSONReport(container);
        // Генерация CSV таблицы
        generateCSVReport(container); 
        
        // Генерация сводного отчета
        generateSummaryReport(container);
        
        long endTime = System.currentTimeMillis();
        System.out.println("✅ Reports generated in " + (endTime - startTime) + "ms");
        System.out.println("📁 Reports saved to: ./reports/");
    }
    
    private void createReportsDirectory() {
        try {
            Files.createDirectories(Paths.get("reports"));
        } catch (IOException e) {
            System.err.println("❌ Failed to create reports directory: " + e.getMessage());
        }
    }
    
    private void generateHTMLReport(ContainerApi container) {
        // Явно указываем кодировку UTF-8 при создании файла
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream("reports/security-analysis.html"), StandardCharsets.UTF_8))) {
            
            writer.write(generateHTMLContent(container));
            System.out.println("  ✅ HTML report generated: reports/security-analysis.html");
        } catch (IOException e) {
            System.err.println("❌ Failed to generate HTML report: " + e.getMessage());
        }
    }
    
    private void generateJSONReport(ContainerApi container) {
        try {
            Map<String, Object> reportData = createReportData(container);
            objectMapper.writeValue(new File("reports/security-analysis.json"), reportData);
            System.out.println("  ✅ JSON report generated: reports/security-analysis.json");
        } catch (IOException e) {
            System.err.println("❌ Failed to generate JSON report: " + e.getMessage());
        }
    }
    
    private void generateSummaryReport(ContainerApi container) {
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream("reports/security-summary.txt"), StandardCharsets.UTF_8))) {
            
            writer.write(generateSummaryContent(container));
            System.out.println("  ✅ Summary report generated: reports/security-summary.txt");
        } catch (IOException e) {
            System.err.println("❌ Failed to generate summary report: " + e.getMessage());
        }
    }
    private void generateCSVReport(ContainerApi container) {
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream("reports/analysis-table.csv"), StandardCharsets.UTF_8))) {
            
            // Заголовок CSV
            writer.println("Endpoint Number,Endpoint Name,Input,Validator,Analyzer,AI,Testing,Recommendations");
            
            // Данные таблицы
            for (EndpointAnalysis analysis : container.getAnalysisTable()) {
                writer.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    analysis.getEndpointNumber(),
                    escapeCsv(analysis.getEndpointName()),
                    escapeCsv(analysis.getInput()),
                    escapeCsv(analysis.getValidator()),
                    escapeCsv(analysis.getAnalyzer()),
                    escapeCsv(analysis.getAi()),
                    escapeCsv(analysis.getTesting()),
                    escapeCsv(analysis.getRecommendation())
                );
            }
            
            System.out.println("  ✅ CSV table generated: reports/analysis-table.csv");
        } catch (IOException e) {
            System.err.println("❌ Failed to generate CSV table: " + e.getMessage());
        }
    }
    private void generateSpecificationReport(ContainerApi container) {
        try {
            JsonNode fullSpec = container.getFullSpecification();
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            
            // Сохраняем полную спецификацию
            objectMapper.writeValue(new File("reports/full-specification.json"), fullSpec);
            
            // Сохраняем упрощенную версию (только основные поля)
            Map<String, Object> simplifiedSpec = createSimplifiedSpecification(fullSpec);
            objectMapper.writeValue(new File("reports/simplified-specification.json"), simplifiedSpec);
            
            System.out.println("  ✅ Specification reports generated:");
            System.out.println("     - reports/full-specification.json");
            System.out.println("     - reports/simplified-specification.json");
            
        } catch (IOException e) {
            System.err.println("❌ Failed to generate specification reports: " + e.getMessage());
        }
    }

    private Map<String, Object> createSimplifiedSpecification(JsonNode fullSpec) {
        Map<String, Object> simplified = new HashMap<>();
        
        // Основная информация
        if (fullSpec.has("openapi")) {
            simplified.put("openapi", fullSpec.get("openapi").asText());
        }
        if (fullSpec.has("info")) {
            simplified.put("info", fullSpec.get("info"));
        }
        
        // Статистика по эндпоинтам
        if (fullSpec.has("paths")) {
            JsonNode paths = fullSpec.get("paths");
            Map<String, Object> pathsSummary = new HashMap<>();
            
            paths.fieldNames().forEachRemaining(path -> {
                JsonNode pathItem = paths.get(path);
                List<String> methods = new ArrayList<>();
                
                pathItem.fieldNames().forEachRemaining(method -> {
                    if (isHttpMethod(method)) {
                        methods.add(method.toUpperCase());
                    }
                });
                
                pathsSummary.put(path, methods);
            });
            
            simplified.put("paths", pathsSummary);
            simplified.put("totalEndpoints", countEndpoints(paths));
        }
        
        // Компоненты (только названия)
        if (fullSpec.has("components")) {
            JsonNode components = fullSpec.get("components");
            Map<String, Object> componentsSummary = new HashMap<>();
            
            components.fieldNames().forEachRemaining(componentType -> {
                JsonNode component = components.get(componentType);
                componentsSummary.put(componentType, component.size());
            });
            
            simplified.put("components", componentsSummary);
        }
        
        return simplified;
    }

    private int countEndpoints(JsonNode paths) {
        int count = 0;
        for (Iterator<String> it = paths.fieldNames(); it.hasNext(); ) {
            String path = it.next();
            JsonNode pathItem = paths.get(path);
            for (Iterator<String> methodIt = pathItem.fieldNames(); methodIt.hasNext(); ) {
                String method = methodIt.next();
                if (isHttpMethod(method)) {
                    count++;
                }
            }
        }
        return count;
    }

    private boolean isHttpMethod(String method) {
        return method.equals("get") || method.equals("post") || 
            method.equals("put") || method.equals("delete") || 
            method.equals("patch") || method.equals("head") || 
            method.equals("options");
    }


    private String escapeCsv(String value) {
        if (value == null) return "";
        // Экранируем кавычки и убираем переносы строк
        return value.replace("\"", "\"\"").replace("\n", " ").replace("\r", " ");
    }


    private String generateHTMLContent(ContainerApi container) {
        StringBuilder html = new StringBuilder();
        
        html.append("""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>API Security Analysis Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                    .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    .endpoint-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                    .endpoint-table th, .endpoint-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                    .endpoint-table th { background-color: #34495e; color: white; }
                    .endpoint-table tr:nth-child(even) { background-color: #f8f9fa; }
                    .vulnerability { background: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
                    .warning { background: #f39c12; color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
                    .info { background: #3498db; color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
                    .success { background: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
                    .section { margin-bottom: 30px; }
                    .section-title { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 API Security Analysis Report</h1>
                        <p>Generated on: """);
        
        html.append(new Date());
        html.append("""
                    </p>
                    </div>
                    
                    <div class="summary">
                        <h2>📊 Executive Summary</h2>
                        """);
        
        html.append(generateExecutiveSummary(container));
        html.append("""
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">🔍 Endpoint Analysis</h2>
                        """);
        
        html.append(generateEndpointTable(container));
        html.append("""
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">🛡️ Security Findings</h2>
                        """);
        
        html.append(generateSecurityFindings(container));
        html.append("""
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">🎯 Testing Results</h2>
                        """);
        
        html.append(generateTestingResults(container));
        html.append("""
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">🤖 AI Analysis</h2>
                        """);
        
        html.append(generateAIAnalysis(container));
        html.append("""
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">💡 Recommendations</h2>
                        """);
        
        html.append(generateRecommendations(container));
        html.append("""
                    </div>
                </div>
            </body>
            </html>""");
        
        return html.toString();
    }
    
    private Map<String, Object> createReportData(ContainerApi container) {
        Map<String, Object> reportData = new HashMap<>();
        
        // Основная информация
        reportData.put("generatedAt", new Date().toString());
        reportData.put("totalEndpoints", container.getAnalysisTable().size());
        
        // Данные анализа
        reportData.put("endpointAnalysis", container.getAnalysisTable());
        reportData.put("validatorResults", container.getValidatorResults());
        reportData.put("analyzerResults", container.getAnalyzerResults());
        reportData.put("aiResults", container.getAiResults());
        reportData.put("testingResults", container.getTestingResults());
        reportData.put("recommendations", container.getRecommendations());
        
        // Статистика
        Map<String, Object> stats = new HashMap<>();
        stats.put("validatorFindings", container.getValidatorResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count());
        stats.put("analyzerFindings", container.getAnalyzerResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count());
        stats.put("aiFindings", container.getAiResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count());
        stats.put("riskLevel", getRiskLevel((Long) stats.get("analyzerFindings")));
        
        reportData.put("statistics", stats);
        
        return reportData;
    }
    
    private String generateSummaryContent(ContainerApi container) {
        StringBuilder summary = new StringBuilder();
        summary.append("API SECURITY ANALYSIS SUMMARY\n")
               .append("=============================\n\n")
               .append("Generated: ").append(new Date()).append("\n\n");
        
        // Статистика
        long totalEndpoints = container.getAnalysisTable().size();
        long validatorFindings = container.getValidatorResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count();
        long analyzerFindings = container.getAnalyzerResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count();
        
        summary.append("EXECUTIVE SUMMARY:\n")
               .append("• Total Endpoints: ").append(totalEndpoints).append("\n")
               .append("• Specification Issues: ").append(validatorFindings).append("\n")
               .append("• Security Vulnerabilities: ").append(analyzerFindings).append("\n")
               .append("• Risk Level: ").append(getRiskLevel(analyzerFindings)).append("\n\n");
        
        // Критические находки
        summary.append("CRITICAL FINDINGS:\n");
        container.getAnalyzerResults().forEach((endpoint, result) -> {
            if (!result.getFindings().isEmpty()) {
                summary.append("• ").append(endpoint).append(":\n");
                for (String finding : result.getFindings()) {
                    if (finding.toLowerCase().contains("high") || finding.toLowerCase().contains("critical")) {
                        summary.append("  - ").append(finding).append("\n");
                    }
                }
            }
        });
        
        return summary.toString();
    }
    
    private String generateExecutiveSummary(ContainerApi container) {
        long totalEndpoints = container.getAnalysisTable().size();
        long validatorFindings = container.getValidatorResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count();
        long analyzerFindings = container.getAnalyzerResults().values().stream()
            .flatMap(r -> r.getFindings().stream()).count();
        
        String riskLevel = getRiskLevel(analyzerFindings);
        String riskClass = getRiskClass(analyzerFindings);
        
        return """
            <div class="executive-summary">
                <p><strong>Total Endpoints Analyzed:</strong> %d</p>
                <p><strong>Specification Issues Found:</strong> %d</p>
                <p><strong>Security Vulnerabilities Identified:</strong> %d</p>
                <p><strong>Overall Risk Level:</strong> <span class="%s">%s</span></p>
            </div>
            """.formatted(totalEndpoints, validatorFindings, analyzerFindings, riskClass, riskLevel);
    }
    
    private String generateEndpointTable(ContainerApi container) {
        StringBuilder table = new StringBuilder();
        table.append("""
            <table class="endpoint-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Endpoint</th>
                        <th>Validator</th>
                        <th>Analyzer</th>
                        <th>AI</th>
                        <th>Testing</th>
                        <th>Recommendations</th>
                    </tr>
                </thead>
                <tbody>
            """);
        
        for (EndpointAnalysis analysis : container.getAnalysisTable()) {
            table.append("<tr>")
                .append("<td>").append(analysis.getEndpointNumber()).append("</td>")
                .append("<td><strong>").append(analysis.getEndpointName()).append("</strong></td>")
                .append("<td>").append(formatStatus(analysis.getValidator())).append("</td>")
                .append("<td>").append(formatStatus(analysis.getAnalyzer())).append("</td>")
                .append("<td>").append(formatStatus(analysis.getAi())).append("</td>")
                .append("<td>").append(formatStatus(analysis.getTesting())).append("</td>")
                .append("<td>").append(formatStatus(analysis.getRecommendation())).append("</td>")
                .append("</tr>");
        }
        
        table.append("</tbody></table>");
        return table.toString();
    }
    
    private String generateSecurityFindings(ContainerApi container) {
        StringBuilder findings = new StringBuilder();
        
        // Validator findings
        findings.append("<h3>Specification Validation</h3>");
        container.getValidatorResults().forEach((endpoint, result) -> {
            if (!result.getFindings().isEmpty()) {
                findings.append("<div style=\"margin-bottom: 15px;\">")
                    .append("<strong>").append(endpoint).append("</strong><ul>");
                for (String finding : result.getFindings()) {
                    findings.append("<li>").append(finding).append("</li>");
                }
                findings.append("</ul></div>");
            }
        });
        
        // Analyzer findings
        findings.append("<h3>Security Analysis</h3>");
        container.getAnalyzerResults().forEach((endpoint, result) -> {
            if (!result.getFindings().isEmpty()) {
                findings.append("<div style=\"margin-bottom: 15px;\">")
                    .append("<strong>").append(endpoint).append("</strong><ul>");
                for (String finding : result.getFindings()) {
                    findings.append("<li>").append(finding).append("</li>");
                }
                findings.append("</ul></div>");
            }
        });
        
        return findings.toString();
    }
    
    private String generateTestingResults(ContainerApi container) {
        StringBuilder results = new StringBuilder();
        
        container.getTestingResults().forEach((endpoint, result) -> {
            if (!result.getFindings().isEmpty()) {
                results.append("<div style=\"margin-bottom: 15px;\">")
                    .append("<strong>").append(endpoint).append("</strong><ul>");
                for (String finding : result.getFindings()) {
                    results.append("<li>").append(finding).append("</li>");
                }
                results.append("</ul></div>");
            }
        });
        
        return results.toString();
    }
    
    private String generateAIAnalysis(ContainerApi container) {
        StringBuilder aiAnalysis = new StringBuilder();
        
        container.getAiResults().forEach((endpoint, result) -> {
            if (!result.getFindings().isEmpty()) {
                aiAnalysis.append("<div style=\"margin-bottom: 15px;\">")
                    .append("<strong>").append(endpoint).append("</strong><ul>");
                for (String finding : result.getFindings()) {
                    aiAnalysis.append("<li>").append(finding).append("</li>");
                }
                aiAnalysis.append("</ul></div>");
            }
        });
        
        return aiAnalysis.toString();
    }
    
    private String generateRecommendations(ContainerApi container) {
        StringBuilder recommendations = new StringBuilder("<ul>");
        
        // Сбор всех рекомендаций
        Set<String> allRecommendations = new HashSet<>();
        
        container.getRecommendations().forEach((endpoint, recs) -> {
            allRecommendations.addAll(recs);
        });
        
        for (String rec : allRecommendations) {
            recommendations.append("<li>").append(rec).append("</li>");
        }
        
        recommendations.append("</ul>");
        return recommendations.toString();
    }
    
    private String formatStatus(String status) {
        if (status == null || status.isEmpty()) return "<span class=\"info\">N/A</span>";
        if (status.toLowerCase().contains("fail") || status.toLowerCase().contains("error")) 
            return "<span class=\"vulnerability\">" + status + "</span>";
        if (status.toLowerCase().contains("warn") || status.toLowerCase().contains("potential")) 
            return "<span class=\"warning\">" + status + "</span>";
        if (status.toLowerCase().contains("success") || status.toLowerCase().contains("no issue")) 
            return "<span class=\"success\">" + status + "</span>";
        return "<span class=\"info\">" + status + "</span>";
    }
    
    private String getRiskLevel(long findingsCount) {
        if (findingsCount > 10) return "HIGH";
        if (findingsCount > 5) return "MEDIUM";
        if (findingsCount > 0) return "LOW";
        return "VERY LOW";
    }
    
    private String getRiskClass(long findingsCount) {
        if (findingsCount > 10) return "vulnerability";
        if (findingsCount > 5) return "warning";
        if (findingsCount > 0) return "info";
        return "success";
    }

}