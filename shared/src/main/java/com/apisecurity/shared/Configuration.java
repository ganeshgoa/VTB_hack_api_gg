package com.apisecurity.shared;

public class Configuration {
    private boolean validatorEnabled = true;
    private boolean analyzerEnabled = true;
    private boolean aiEnabled = true;
    private boolean testingEnabled = true;
    private boolean reportmakerEnabled = true;
    private OpenAIConfig aiConfig = new OpenAIConfig();
    
    // Жёстко заданные параметры для analyzer
    private String analyzerBaseUrl = "https://sbank.open.bankingapi.ru";
    private String analyzerClientId = "team154";
    private String analyzerClientSecret = "rihm8KZlNFqhH4DQ3H0LpK8hwub1Unpa";

    public boolean isValidatorEnabled() { return validatorEnabled; }
    public void setValidatorEnabled(boolean validatorEnabled) { this.validatorEnabled = validatorEnabled; }
    
    public boolean isAnalyzerEnabled() { return analyzerEnabled; }
    public void setAnalyzerEnabled(boolean analyzerEnabled) { this.analyzerEnabled = analyzerEnabled; }
    
    public boolean isAiEnabled() { return aiEnabled; }
    public void setAiEnabled(boolean aiEnabled) { this.aiEnabled = aiEnabled; }
    
    public boolean isTestingEnabled() { return testingEnabled; }
    public void setTestingEnabled(boolean testingEnabled) { this.testingEnabled = testingEnabled; }
    
    public boolean isReportmakerEnabled() { return reportmakerEnabled; }
    public void setReportmakerEnabled(boolean reportmakerEnabled) { this.reportmakerEnabled = reportmakerEnabled; }
    
    public OpenAIConfig getAiConfig() { return aiConfig; }
    public void setAiConfig(OpenAIConfig aiConfig) { this.aiConfig = aiConfig; }

    public String getAnalyzerClientId() { return analyzerClientId; }
    public String getAnalyzerBaseUrl() { return analyzerBaseUrl; }
    public String getAnalyzerClientSecret() { return analyzerClientSecret; }
    
    @Override
    public String toString() {
        return String.format(
            "Configuration{validatorEnabled=%s, analyzerEnabled=%s, aiEnabled=%s, testingEnabled=%s, reportmakerEnabled=%s}",
            validatorEnabled, analyzerEnabled, aiEnabled, testingEnabled, reportmakerEnabled
        );
    }
}