// com.apisecurity.analyzer.checks/SecurityCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.ContainerApi;
import com.fasterxml.jackson.databind.JsonNode;

public interface SecurityCheck {
    void run(JsonNode spec, ContainerApi container);
    String getName();
}