package com.apisecurity.analyzer;

import com.apisecurity.analyzer.checks.*;
import com.apisecurity.shared.ContainerApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

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
            new SecurityMisconfigurationCheck()
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