// com.apisecurity.analyzer.context/DynamicContext.java
package com.apisecurity.analyzer.context;

import com.apisecurity.analyzer.executor.ApiExecutor;

/**
 * Контекст для динамического анализа.
 * Передаётся в SecurityCheck, если доступен.
 */
public class DynamicContext {
    private final ApiExecutor executor;
    private final ExecutionContext executionContext;

    public DynamicContext(ApiExecutor executor, ExecutionContext executionContext) {
        this.executor = executor;
        this.executionContext = executionContext;
    }

    public ApiExecutor getExecutor() {
        return executor;
    }

    public ExecutionContext getExecutionContext() {
        return executionContext;
    }

    public boolean isAvailable() {
        return executor != null && executionContext != null;
    }
}