# ---- Build stage ----
FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /app

# Copy Maven wrapper & pom first (better caching)
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

RUN ./mvnw dependency:go-offline

# Copy the source code
COPY src src

RUN ./mvnw package -DskipTests

# ---- Runtime stage ----
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy built jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Optional: JVM flags for low memory usage
ENV JAVA_OPTS="-Xms64m -Xmx256m \
               -XX:+UseSerialGC \
               -XX:+TieredCompilation \
               -XX:MaxMetaspaceSize=128m"

EXPOSE 9000

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]