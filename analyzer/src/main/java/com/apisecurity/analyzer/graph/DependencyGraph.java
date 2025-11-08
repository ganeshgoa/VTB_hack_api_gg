// com.apisecurity.analyzer.graph/DependencyGraph.java
package com.apisecurity.analyzer.graph;

import com.apisecurity.analyzer.discovery.EndpointSignature;

import java.util.*;

/**
 * Граф зависимостей между эндпоинтами.
 * Позволяет находить "поставщиков" параметров для любого эндпоинта.
 */
public class DependencyGraph {
    // Ключ: эндпоинт-потребитель → список рёбер
    private final Map<String, List<DependencyEdge>> edgesByTarget = new LinkedHashMap<>();

    // Ключ: параметр → список эндпоинтов, которые его предоставляют
    private final Map<String, List<String>> providersByParam = new LinkedHashMap<>();

    public DependencyGraph(Map<String, EndpointSignature> signatures) {
        // 1. Индексируем поставщиков по параметрам
        for (Map.Entry<String, EndpointSignature> entry : signatures.entrySet()) {
            String endpointKey = entry.getKey();
            EndpointSignature sig = entry.getValue();

            for (String outputParam : sig.outputs) {
                providersByParam.computeIfAbsent(outputParam, k -> new ArrayList<>())
                                .add(endpointKey);
            }
        }

        // 2. Строим рёбра
        for (Map.Entry<String, EndpointSignature> entry : signatures.entrySet()) {
            String targetKey = entry.getKey();
            EndpointSignature targetSig = entry.getValue();

            List<DependencyEdge> edges = new ArrayList<>();

            // Для каждого входного параметра ищем поставщика
            for (String inputParam : targetSig.inputs.keySet()) {
                List<String> providers = providersByParam.get(inputParam);
                if (providers != null) {
                    for (String provider : providers) {
                        // Не создаём цикл: эндпоинт не может зависеть от себя
                        if (!provider.equals(targetKey)) {
                            edges.add(new DependencyEdge(provider, targetKey, inputParam));
                        }
                    }
                }
            }

            if (!edges.isEmpty()) {
                edgesByTarget.put(targetKey, edges);
            }
        }
    }

    /**
     * Возвращает список эндпоинтов, которые могут предоставить указанный параметр.
     */
    public List<String> getProvidersForParameter(String paramName) {
        return providersByParam.getOrDefault(paramName, Collections.emptyList());
    }

    /**
     * Возвращает все зависимости для заданного эндпоинта.
     */
    public List<DependencyEdge> getDependenciesFor(String endpointKey) {
        return edgesByTarget.getOrDefault(endpointKey, Collections.emptyList());
    }

    /**
     * Возвращает все эндпоинты, которые зависят от данного.
     */
    public List<String> getDependentsOf(String endpointKey) {
        List<String> dependents = new ArrayList<>();
        for (List<DependencyEdge> edges : edgesByTarget.values()) {
            for (DependencyEdge edge : edges) {
                if (edge.sourceEndpointKey.equals(endpointKey)) {
                    dependents.add(edge.targetEndpointKey);
                }
            }
        }
        return dependents;
    }

    /**
     * Печать графа для отладки.
     */
    public void printGraph() {
        if (edgesByTarget.isEmpty()) {
            System.out.println("🕸️  Dependency graph is empty.");
            return;
        }
        System.out.println("🕸️  Built dependency graph:");
        for (List<DependencyEdge> edges : edgesByTarget.values()) {
            for (DependencyEdge edge : edges) {
                System.out.println("  - " + edge);
            }
        }
    }
}