# ================== build ==================
FROM gradle:9.1.0-jdk25 AS build
WORKDIR /workspace

# Copy Gradle build descriptors first to leverage Docker layer cache
COPY build.gradle settings.gradle ./
COPY src ./src

# Build (no tests for image build speed; enable if needed)
RUN gradle --no-daemon clean bootJar -x test

# ================== runtime ==================
FROM eclipse-temurin:25-jre
WORKDIR /opt/app
ENV JAVA_OPTS="" \
    SERVER_PORT=9000 \
    APP_ISSUER=http://localhost:9000

COPY --from=build /workspace/build/libs/*.jar app.jar
EXPOSE 9000
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]
