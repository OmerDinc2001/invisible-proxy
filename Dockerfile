FROM openjdk:17-slim

# Install system network route management utilities for transparent interception redirection
RUN apt-get update && apt-get install -y iptables iproute2 procps curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all Java classes into container space
COPY *.java /app/

# Compile the multi-threaded network engine application codebase
RUN javac ControlServer.java ProxyEngine.java ConnectionHandler.java HttpProcessor.java HttpsProcessor.java FilterManager.java CacheManager.java LogManager.java

# Expose both backend interception pipelines and dashboard interfaces
EXPOSE 8888 8080

# Execute internal firewall redirection routing rules right before launching Java binary runtime engine
CMD iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8888 && \
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8888 && \
    java ControlServer