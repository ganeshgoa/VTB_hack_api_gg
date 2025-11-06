dockerfile
FROM openjdk:17-jdk-slim

WORKDIR /app

# Копирование JAR файла (предполагается, что он уже собран)
COPY target/app-1.0.0-jar-with-dependencies.jar app.jar

# Создание директорий для работы
RUN mkdir -p /specs /reports

# Точка входа
ENTRYPOINT ["java", "-jar", "app.jar"]