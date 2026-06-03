import java.io.*;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

public class HttpProcessor {

    public static void process(InputStream inFromClient, OutputStream outToClient, String clientIp) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inFromClient, "UTF-8"));

        String requestLine = reader.readLine();
        if (requestLine == null || requestLine.isEmpty()) {
            return;
        }

        System.out.println("\n[HTTP Processor] Intercepted: " + requestLine);

        String[] parts = requestLine.split(" ");
        if (parts.length < 3) {
            sendErrorResponse(outToClient, 400, "Bad Request");
            return;
        }

        String method = parts[0].toUpperCase();
        String uri = parts[1];

        if (!method.equals("GET") && !method.equals("POST") && !method.equals("HEAD") && !method.equals("OPTIONS")) {
            System.out.println("[HTTP Processor] BLOCKED: Method '" + method + "' is forbidden (405).");
            sendErrorResponse(outToClient, 405, "Method Not Allowed");
            return;
        }

        Map<String, String> clientHeaders = new HashMap<>();
        StringBuilder rawHeadersToSend = new StringBuilder();
        rawHeadersToSend.append(requestLine).append("\r\n");

        String headerLine;
        while ((headerLine = reader.readLine()) != null && !headerLine.isEmpty()) {
            int colonIndex = headerLine.indexOf(":");
            if (colonIndex != -1) {
                String key = headerLine.substring(0, colonIndex).trim();
                String value = headerLine.substring(colonIndex + 1).trim();
                clientHeaders.put(key.toLowerCase(), value);
            }
            rawHeadersToSend.append(headerLine).append("\r\n");
        }
        rawHeadersToSend.append("\r\n");

        String hostHeader = clientHeaders.get("host");
        if (hostHeader == null) {
            sendErrorResponse(outToClient, 400, "Bad Request: Missing Host Header");
            return;
        }

        String targetHost = hostHeader;
        int targetPort = 80;
        if (hostHeader.contains(":")) {
            String[] hostParts = hostHeader.split(":");
            targetHost = hostParts[0];
            targetPort = Integer.parseInt(hostParts[1]);
        }

        // --- ENFORCE DYNAMIC WEB-FILTERING POLICY ---
        if (FilterManager.isBanned(targetHost)) {
            System.out.println("[HTTP Processor] ENFORCED DROP: Target '" + targetHost + "' is blocked!");
            sendErrorResponse(outToClient, 401, "Unauthorized");
            LogManager.addLog(clientIp, targetHost, uri, method, "401 Blocked");
            return;
        }

        // --- CACHE VALIDATION ROUTING MAPS ---
        String resourceUrl = "http://" + hostHeader + uri;
        boolean hasLocalCache = CacheManager.hasCache(resourceUrl);
        String localLastModified = CacheManager.getLastModified(resourceUrl);

        if (hasLocalCache && localLastModified != null && method.equals("GET")) {
            System.out.println("[HTTP Processor] Cache structural match hit. Injecting Conditional GET validation rules...");
            rawHeadersToSend.setLength(rawHeadersToSend.length() - 2); // Pull back closing double \r\n
            rawHeadersToSend.append("If-Modified-Since: ").append(localLastModified).append("\r\n\r\n");
        }

        // Connect downstream to destination remote origin server
        try (Socket serverSocket = new Socket(targetHost, targetPort);
             OutputStream outToServer = serverSocket.getOutputStream();
             InputStream inFromServer = serverSocket.getInputStream()) {

            // Pass headers downstream
            outToServer.write(rawHeadersToSend.toString().getBytes("UTF-8"));
            outToServer.flush();

            // Handle incoming server headers
            BufferedInputStream bis = new BufferedInputStream(inFromServer);
            List<String> serverHeadersList = new ArrayList<>();
            String sLine = readLineRaw(inFromServer);
            if (sLine == null || sLine.isEmpty()) return;

            String statusLine = sLine;
            serverHeadersList.add(statusLine);

            String[] statusParts = statusLine.split(" ");
            int statusCode = 500;
            if (statusParts.length >= 2) {
                statusCode = Integer.parseInt(statusParts[1]);
            }

            // Read through remaining downstream validation header maps
            StringBuilder serverHeadersStr = new StringBuilder();
            serverHeadersStr.append(statusLine).append("\r\n");

            String remoteLastModified = null;
            while ((sLine = readLineRaw(inFromServer)) != null && !sLine.isEmpty()) {
                serverHeadersList.add(sLine);
                serverHeadersStr.append(sLine).append("\r\n");

                String lowerLine = sLine.toLowerCase();
                if (lowerLine.startsWith("last-modified:")) {
                    remoteLastModified = sLine.substring(14).trim();
                }
            }
            serverHeadersStr.append("\r\n");

            // --- CONDITIONAL 304 NOT MODIFIED LOGIC ---
            if (statusCode == 304 && hasLocalCache) {
                System.out.println("[HTTP Processor] 304 Verified. Serving assets locally from persistent disk cache.");
                CacheManager.serveFromCache(resourceUrl, outToClient);
                LogManager.addLog(clientIp, targetHost, uri, method, "304 Cache Hit");
                return;
            }

            // Forward server status line and response headers to the client
            outToClient.write(serverHeadersStr.toString().getBytes("UTF-8"));
            outToClient.flush();

            // --- DETECT RESPONSE BOUNDARIES / PAYLOAD ENCODING STRATEGY ---
            boolean isChunked = false;
            int contentLength = -1;

            for (String line : serverHeadersList) {
                String lowerLine = line.toLowerCase();
                if (lowerLine.startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                } else if (lowerLine.startsWith("transfer-encoding:") && lowerLine.contains("chunked")) {
                    isChunked = true;
                }
            }

            // Memory stream to capture payload bytes for caching
            ByteArrayOutputStream freshBodyBuffer = new ByteArrayOutputStream();

            if (contentLength >= 0) {
                // Scenario A: Fixed Size Content-Length Specification
                byte[] bodyChunk = new byte[8192];
                int totalRead = 0;
                while (totalRead < contentLength) {
                    int toRead = Math.min(bodyChunk.length, contentLength - totalRead);
                    int bytesRead = inFromServer.read(bodyChunk, 0, toRead);
                    if (bytesRead == -1) break;

                    outToClient.write(bodyChunk, 0, bytesRead);
                    if (method.equals("GET") && remoteLastModified != null && statusCode == 200) {
                        freshBodyBuffer.write(bodyChunk, 0, bytesRead);
                    }
                    totalRead += bytesRead;
                    outToClient.flush();
                }
            } else if (isChunked) {
                // Scenario B: Chunked Transfer Encoding Handling (Fixes Browser Hanging Cases)
                while (true) {
                    // 1. Read chunk length size line (hex string terminated by \r\n)
                    String sizeLine = readLineRaw(inFromServer);
                    if (sizeLine == null) break;

                    outToClient.write((sizeLine + "\r\n").getBytes("UTF-8"));

                    // Split out hex chunk extensions if any exist
                    String hexSize = sizeLine.split(";")[0].trim();
                    int chunkSize = Integer.parseInt(hexSize, 16);

                    // A chunk length of 0 designates the closing element
                    if (chunkSize == 0) {
                        String trailerLine = readLineRaw(inFromServer); // Consume terminal \r\n
                        outToClient.write((trailerLine + "\r\n").getBytes("UTF-8"));
                        outToClient.flush();
                        break;
                    }

                    // 2. Consume exactly chunk-size bytes sequentially
                    byte[] chunkBuf = new byte[chunkSize];
                    int chunkBytesRead = 0;
                    while (chunkBytesRead < chunkSize) {
                        int r = inFromServer.read(chunkBuf, chunkBytesRead, chunkSize - chunkBytesRead);
                        if (r == -1) throw new IOException("Unexpected End of Stream encountered during raw block transmission processing");
                        chunkBytesRead += r;
                    }

                    outToClient.write(chunkBuf);
                    if (method.equals("GET") && remoteLastModified != null && statusCode == 200) {
                        freshBodyBuffer.write(chunkBuf);
                    }

                    // 3. Forward the trailing \r\n demarcating the current chunk closure boundary
                    String crlf = readLineRaw(inFromServer);
                    outToClient.write((crlf + "\r\n").getBytes("UTF-8"));
                    outToClient.flush();
                }
            } else {
                // Scenario C: Fallback Interception (Read until stream disconnects)
                byte[] bodyChunk = new byte[8192];
                int bytesRead;
                while ((bytesRead = inFromServer.read(bodyChunk)) != -1) {
                    outToClient.write(bodyChunk, 0, bytesRead);
                    if (method.equals("GET") && remoteLastModified != null && statusCode == 200) {
                        freshBodyBuffer.write(bodyChunk, 0, bytesRead);
                    }
                    outToClient.flush();
                }
            }

            // Commit freshly generated copy parameters directly to Cache directory
            if (method.equals("GET") && remoteLastModified != null && statusCode == 200) {
                CacheManager.store(resourceUrl, remoteLastModified, freshBodyBuffer.toByteArray());
            }

            // Log successful transaction metrics globally to system history records
            if (statusCode == 200) {
                System.out.println("[HTTP Processor] Fresh transaction processed completely. Logging entry.");
                LogManager.addLog(clientIp, targetHost, uri, method, String.valueOf(statusCode));
            }

        } catch (IOException e) {
            System.err.println("[HTTP Processor] Cache/Forward failure: " + e.getMessage());
            sendErrorResponse(outToClient, 502, "Bad Gateway");
        }
    }

    /**
     * Utility method to safely parse single raw text lines terminated by \r\n out of a binary stream.
     */
    private static String readLineRaw(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\r') {
                int next = in.read();
                if (next == '\n') break;
                baos.write(c);
                baos.write(next);
            } else {
                baos.write(c);
            }
        }
        if (baos.size() == 0 && c == -1) return null;
        return baos.toString("UTF-8");
    }

    private static void sendErrorResponse(OutputStream out, int statusCode, String statusText) throws IOException {
        String response = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n" +
                "Content-Type: text/plain\r\n" +
                "Connection: close\r\n\r\n" +
                "Error " + statusCode + ": " + statusText;
        out.write(response.getBytes("UTF-8"));
        out.flush();
    }
}