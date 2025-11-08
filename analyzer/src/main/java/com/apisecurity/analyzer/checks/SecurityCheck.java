// com.apisecurity.analyzer.checks/SecurityCheck.java
package com.apisecurity.analyzer.checks;

import com.apisecurity.shared.ContainerApi;
import com.apisecurity.analyzer.context.DynamicContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.apisecurity.analyzer.context.DynamicContext;

public interface SecurityCheck {
    String getName();
    
    // Основной метод: с поддержкой динамического контекста
    void run(JsonNode spec, ContainerApi container, DynamicContext dynamicContext);
    
    // Удобный метод без динамики (для обратной совместимости)
    default void run(JsonNode spec, ContainerApi container) {
        run(spec, container, null);
    }
}