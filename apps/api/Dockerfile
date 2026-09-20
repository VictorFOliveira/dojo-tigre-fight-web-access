FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd --create-home --uid 10001 cactus
COPY --from=build /app/target/cactus-fight-api-0.1.0.jar /app/app.jar
USER cactus
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
