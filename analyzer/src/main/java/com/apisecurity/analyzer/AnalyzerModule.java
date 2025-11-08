package com.apisecurity.analyzer;

import com.apisecurity.analyzer.checks.*;
import com.apisecurity.analyzer.discovery.*;
import com.apisecurity.analyzer.context.*;
import com.apisecurity.analyzer.executor.*;
import com.apisecurity.analyzer.graph.*;
import com.apisecurity.shared.ContainerApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import com.apisecurity.shared.ContainerApi;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.File;
import java.io.IOException;
import java.util.*;
// и другие при необходимости

public class AnalyzerModule {

    private final ObjectMapper objectMapper;
    private final List<SecurityCheck> checks;

    public AnalyzerModule() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.checks = Arrays.asList(
            new BOLACheck(),
            new BrokenAuthenticationCheck(),
            new BrokenObjectPropertyLevelAuthorizationCheck(),
            new UnrestrictedResourceConsumptionCheck(),
            new BrokenFunctionLevelAuthorizationCheck(),
            new UnrestrictedBusinessFlowAccessCheck(),
            new ServerSideRequestForgeryCheck(),
            new SecurityMisconfigurationCheck(),
            new ImproperInventoryManagementCheck(),
            new UnsafeConsumptionOfApisCheck()
        );
    }

    public void process(ContainerApi container) {
        long startTime = System.currentTimeMillis();
        System.out.println("🛡️ Starting OWASP Top 10 security analysis...");

        JsonNode spec = container.getFullSpecification();
        if (spec == null) {
            System.err.println("❌ No specification provided to AnalyzerModule.");
            return;
        }

        // 🔽 Сохраняем исходную спецификацию в spec.json
        saveSpecificationToFile(spec);

        // 🔽 Шаг 1: построить сигнатуры
        SpecAnalyzer specAnalyzer = new SpecAnalyzer(spec);
        Map<String, EndpointSignature> signatures = specAnalyzer.buildEndpointSignatures(spec);

        // Для отладки:
        System.out.println("🔍 Built " + signatures.size() + " endpoint signatures:");
        for (EndpointSignature sig : signatures.values()) {
            System.out.println("  - " + sig);
        }
        
        // 🔽 ШАГ 2: Построение графа вызовов
        DependencyGraph graph = new DependencyGraph(signatures);
        graph.printGraph(); // для отладки
        // === ШАГ 2: Сбор параметров от пользователя ===
        ParameterCollector collector = new ParameterCollector(container.getConfiguration(), signatures);
        ExecutionContext ctx = collector.collect();

        // Получаем baseUrl
        String baseUrl = container.getAnalyzerBaseUrl().trim().replaceAll("/+$", "");
        System.out.println("URL: " + baseUrl);

        // Создаём executor
        ApiExecutor executor = new ApiExecutor(baseUrl);

        // Получаем токен
        if (executor.obtainToken(spec, ctx)) {
            System.out.println("🔑 Token ready for dynamic analysis.");
        } else {
            System.out.println("⚠️ Token acquisition failed — dynamic checks may be limited.");
        }

        System.out.println("🔧 ExecutionContext initialized with: " + ctx.getKeys());

        DynamicContext dynamicContext = null;
        if (executor.getAccessToken() != null) {
            dynamicContext = new DynamicContext(executor, ctx);
            System.out.println("⚡ Dynamic analysis enabled.");
        } else {
            System.out.println("⚠️ Dynamic analysis disabled: token not available.");
        }

        if (spec.has("paths")) {
            for (SecurityCheck check : checks) {
                System.out.println("➡️ Running " + check.getName() + " check...");
                try {
                    check.run(spec, container);
                } catch (Exception e) {
                    System.err.println("❌ Error running " + check.getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } else {
            System.out.println("⚠️ Spec has no 'paths' — skipping security checks.");
        }

        long endTime = System.currentTimeMillis();
        System.out.println("✅ Security analysis completed in " + (endTime - startTime) + "ms");
    }

    // 🔽 Новый метод: сохранение спецификации в файл
    private void saveSpecificationToFile(JsonNode spec) {
        try {
            File outputFile = new File("spec.json");
            objectMapper.writeValue(outputFile, spec);
            System.out.println("📄 OpenAPI specification saved to: " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("⚠️ Failed to save spec.json: " + e.getMessage());
        }
    }
}