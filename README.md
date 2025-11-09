# API-SECURITY-ANALYZER
Aвтоматизированный инструмент анализа безопасности и корректности API.  
API Security Analyzer — это многомодульное Java-приложение для автоматизированного анализа безопасности API на основе OpenAPI, Swagger и AsyncAPI* спецификаций. Приложение выполняет валидацию, поиск уязвимостей, тестирование и генерацию отчетов с использованием современных подходов, включая анализ через ИИ.
# Запуск приложения 
## Требования
JAVA 17+  
Maven 3.6+  
Токен OpenRouter (для модуля AI)
## Команды 
1) Скачиваем проект:  
```
git clone git@github.com:ganeshgoa/API-SECURITY-ANALYZER.git
```
2) Заходим в папку проекта:  
```
cd API-SECURITY-ANALYZER  
```
3) Делаем компиляцию  
```
mvn clean compile  
```
4) Делаем сборку  
```
mvn clean package  
```
**Перед запуском необходимо добавить API KEY OpenRouter в config.json и Secret Client в params.json**
```
"apiKey": "your_openrouter_api_key" # Указать API KEY от OpenRouter в config.json
```
```
"client_secret": ["your_client_secret"] # Указать client_secret в params.json
```
5) Запускаем приложение:  
```
java -jar app/target/app-1.0.0-jar-with-dependencies.jar --spec .\openapi_s.json --conf .\config.json # Windows
```
```  
java -jar app/target/app-1.0.0-jar-with-dependencies.jar --spec ./openapi_s.json --conf ./config.json # Linux
```
6) Смотрим результаты в  
   `API-SECURITY-ANALYZER/reports/security-analysis.html` - отчёт в HTML  
   `API-SECURITY-ANALYZER/reports/security-analysis.json` - отчёт в JSON

## Конфигурационный файл (JSON)
```
{  
  "validatorEnabled": true,  
  "analyzerEnabled": true,  
  "aiEnabled": true,  
  "testingEnabled": true,  
  "reportmakerEnabled": true,  
  "aiConfig": {  
    "baseUrl": "https://openrouter.ai/api/v1",  
    "apiKey": "Your key",  
    "models": [  
      "deepseek/deepseek-r1-distill-llama-70b",   
      "deepseek/deepseek-r1-0528-qwen3-8b",   
      "deepseek/deepseek-chat-v3-0324",  
      "google/gemini-2.0-flash-exp",  
      "meta-llama/llama-3.3-70b-instruct",   
      "microsoft/wizardlm-2-8x22b",  
      "qwen/qwen-2.5-coder-32b-instruct"  
    ]  
  }  
}  
```
## Выходные данные 
Полная спецификация JSON можно найти в `/reports/full-specification.json`    
Таблица результатов по эндпоинтам можно найти в `/reports/analysis-table.csv`    
HTML отчёт с детализацией можно найти в `/reports/security-analysis.html`    
Json отчёт для машинной обработки в `/reports/security-analysis.json`    
Сырые и полные ответы ИИ можно найти в `/reports/ai_responses/*.json и .txt`

## Технологический стек
Язык: JAVA 17+  
Сборка: Maven  
CI/CD: GitHub Actions  
Анализ: OWASP, ИИ через OpenRouter  
Форматы: OpenApi 3.1+, Swagger 2.0, AsyncApi 2.6+*  
Отчёты: HTML, JSON

# 1. Обзор проекта
   API Security Analyzer — это многомодульное Java-приложение для автоматизированного анализа безопасности API на основе OpenAPI, Swagger и AsyncAPI* спецификаций. Приложение выполняет валидацию, поиск уязвимостей, тестирование и генерацию отчетов с использованием современных подходов, включая анализ через ИИ.

# 2. Архитектура проекта
Проект состоит из 7 модулей + CI/CD конфигурация: 
```
api-security-analyzer/  
├── pom.xml  
├── .github/workflows/ci-cd.yml  
├── input/  
├── validator/  
├── analyzer/  
├── ai/  
├── testing/  
├── reportmaker/  
└── shared/
```  
# 3. Описание модулей 
## Модуль input 
Это входная точка приложения, обработка спецификаций и инициализация потоков. Основные функция: принимает на вход спецификацию (OpenApi 3.1+, Swagger2.0 Json, AsyncApi 2.6+), конфигурационный файл JSON с настройками модулей. Обрабатывает #ref ссылки в спецификациях. Создает и сохраняет полную спецификацию и помещает в `ContainerApi`. Добавляет служебные поля для модулей: validator, analyzer, ai, recommendation, testing. Создает таблицу table с колонками для каждого модуля. Запускает потоки для активных модулей.
## Модуль validator
Отвечает за валидацию соответствия API его спецификации. Основные функции: проверка отсутствующих полей, неожиданные типы данных, неописанные эндпоинты. Записывает результаты в `ContainerApi.validator`, обновляет таблицу table в колонке validator. 
## Модуль analyzer 
Отвечает за анализ уязвимостей OWASP TOP 10. Основные функции: обнаружение BOLA, IDOR, инъекции, слабую аутентификацию, избыточные данные в ответах, debug-интерфейсы, тестовые данные. Записывает результаты в `ContainerApi.analyzer`, обновляет таблицу table в колонке analyzer. Также есть возможность на основе предоставленных пользователем тестовых входных данных выявлять уязвимости OWASP API Top 10+ динамически (на данный момент доступны не все проверки). 
## Модуль ai
Отвечает за анализ уязвимостей с помощью отправки промтов в сторону ИИ через OpenRouter.  
Используются бесплатные модели:  
  ```
  deepseek/deepseek-r1-distill-llama-70b   
  deepseek/deepseek-r1-0528-qwen3-8b  
  deepseek/deepseek-chat-v3-0324  
  google/gemini-2.0-flash-exp  
  meta-llama/llama-3.3-70b-instruct  
  microsoft/wizardlm-2-8x22b  
  qwen/qwen-2.5-coder-32b-instruct
```
Основные функции: отправка промтов, парсинг ответов, обработка неполных ответов, запись результатов: уязвимости в `ContainerApi.ai`, рекомендации в `ContainerApi.recommendation`, обновление таблицы в колонках ai и reccomendation. 
## Модуль testing* 
Отвечает за генерацию и выполнение тестовых запросов. Основные функции: генерирование запросов на основе спецификации, проверка гипотез об уязвимостях, фаззинг, отправка запросов и анализ ответов. Запись резцльтатов в `ContainerApi.testing`, обновление таблицы в колонке testing. Формат: [статус] [запрос]  
## Модуль reportmaker
Отвечает за создание финальных отчётов. Основные функции: сбор данных из `ContainerApi`, генерация отчётов в форматах HTML, JSON. Включение результатов всех модулей: валидация, уязвимости, результаты тестирования, рекомендации. 
## Модуль shared 
Отвечает за общие компоненты для всех модулей. Содержит общие классы, конфигурации, утилиты, `ContainerApi` - центральный контейнер данных, модели данных. 
# 4. CI/CD
## GitHub Actions 
Файл `.github/workflows/ci-cd.yml`    
Основные функции: сборка проекта, запуск тестов*, проверка кода. 






