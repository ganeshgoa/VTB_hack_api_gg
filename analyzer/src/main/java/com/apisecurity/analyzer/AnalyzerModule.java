// com.apisecurity.analyzer/AnalyzerModule.java

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

import java.io.File;
import java.io.IOException;
import java.util.*;

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

        saveSpecificationToFile(spec);

        SpecAnalyzer specAnalyzer = new SpecAnalyzer(spec);
        Map<String, EndpointSignature> signatures = specAnalyzer.buildEndpointSignatures(spec);

        System.out.println("🔍 Built " + signatures.size() + " endpoint signatures:");
        for (EndpointSignature sig : signatures.values()) {
            System.out.println("  - " + sig);
        }

        DependencyGraph graph = new DependencyGraph(signatures);
        graph.printGraph();

        // ✅ ПЕРЕДАЁМ container в ParameterCollector
        ParameterCollector collector = new ParameterCollector(
            container.getConfiguration(), 
            container, // ← вот он!
            signatures
        );
        ExecutionContext ctx = collector.collect();

        // ✅ Получаем baseUrl из container (уже установлен в ParameterCollector)
        String baseUrl = container.getAnalyzerBaseUrl();
        System.out.println("🌐 Using base URL: " + baseUrl);

        // ✅ УБРАНО дублирование: только одно объявление executor
        ApiExecutor executor = new ApiExecutor(baseUrl);

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
                    check.run(spec, container, dynamicContext);
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
        
        if (executor != null) {
            executor.saveRequestLog();
        }
    }

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