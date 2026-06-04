FROM eclipse-temurin:17-jdk-alpine

# Install system network route management utilities for transparent interception redirection
RUN apk update && apk add --no-cache curl iptables

WORKDIR /app

# Copy all Java classes into container space
COPY src/*.java /app/

# Compile the multi-threaded network engine application codebase
RUN javac ControlServer.java ProxyEngine.java ConnectionHandler.java HttpProcessor.java HttpsProcessor.java FilterManager.java CacheManager.java LogManager.java

# Expose both backend interception pipelines and dashboard interfaces
EXPOSE 8888 8080

CMD ["java", "ControlServer"]