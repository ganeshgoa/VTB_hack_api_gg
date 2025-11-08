// com.apisecurity.analyzer/AnalyzerModule.java
package com.apisecurity.analyzer;

import com.apisecurity.analyzer.checks.BOLACheck;
import com.apisecurity.analyzer.checks.BrokenAuthenticationCheck;
import com.apisecurity.analyzer.checks.BrokenObjectPropertyLevelAuthorizationCheck;
import com.apisecurity.analyzer.checks.SecurityCheck;
import com.apisecurity.shared.ContainerApi;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Arrays;

public class AnalyzerModule {

    // Можно расширить список: new MassAssignmentCheck(), new SSRFCheck() и т.д.
    private final List<SecurityCheck> checks = Arrays.asList(
        new BOLACheck(),
        new BrokenAuthenticationCheck(),
        new BrokenObjectPropertyLevelAuthorizationCheck()
    );

    public void process(ContainerApi container) {
        long startTime = System.currentTimeMillis();
        System.out.println("🛡️ Starting OWASP Top 10 security analysis...");

        JsonNode spec = container.getFullSpecification();
        if (spec != null && spec.has("paths")) {
            for (SecurityCheck check : checks) {
                System.out.println("➡️ Running " + check.getName() + " check...");
                check.run(spec, container);
            }
        } else {
            System.out.println("⚠️ No valid OpenAPI spec — skipping all checks.");
        }

        long endTime = System.currentTimeMillis();
        System.out.println("✅ Security analysis completed in " + (endTime - startTime) + "ms");
    }
}