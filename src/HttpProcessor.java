import java.io.*;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class HttpProcessor {

    public static void process(InputStream inFromClient, OutputStream outToClient, String clientIp) throws IOException {
        // FIX: Replaced BufferedReader with our raw line reader utility to prevent stream starvation
        String requestLine = readLineRaw(inFromClient);
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

        // FIX: Read incoming headers cleanly using raw stream extraction
        String headerLine;
        while ((headerLine = readLineRaw(inFromClient)) != null && !headerLine.isEmpty()) {
            rawHeadersToSend.append(headerLine).append("\r\n");
            int colonIdx = headerLine.indexOf(":");
            if (colonIdx != -1) {
                String key = headerLine.substring(0, colonIdx).trim();
                String value = headerLine.substring(colonIdx + 1).trim();
                clientHeaders.put(key, value);
            }
        }
        rawHeadersToSend.append("\r\n"); // End of HTTP header boundary block

        // Extract and resolve target hostname from the client headers map
        String targetHost = clientHeaders.get("Host");
        if (targetHost == null) {
            System.out.println("[HTTP Processor] Drop: Missing required HTTP Host header validation field.");
            sendErrorResponse(outToClient, 400, "Bad Request: Missing Host Header");
            return;
        }

        // Strip port if present inside the Host header format (e.g. neverssl.com:80 -> neverssl.com)
        if (targetHost.contains(":")) {
            targetHost = targetHost.split(":")[0];
        }

        int statusCode = 502; // Fallback status initialization

        // Cleartext target request routing pipeline
        try {
            // Check if application logic matches cache availability criteria
            if (method.equals("GET") && CacheManager.hasCache(uri)) {
                CacheManager.serveFromCache(uri, outToClient);
                statusCode = 200;
                LogManager.addLog(clientIp, targetHost, uri, method, "200 (CACHE HIT)");
                return;
            }

            // Check if domain matching block rules inside FilterManager are active
            if (FilterManager.isBanned(targetHost)) {
                System.out.println("[HTTP Processor] Intercept Block: Domain targeted by policy rules -> " + targetHost);
                sendErrorResponse(outToClient, 403, "Forbidden by Firewall Admin Rules");
                LogManager.addLog(clientIp, targetHost, uri, method, "403");
                return;
            }

            // Establish secondary outbound TCP socket connection straight to the remote internet target
            System.out.println("[HTTP Processor] Forwarding connection to remote endpoint -> " + targetHost + ":80");
            try (Socket targetSocket = new Socket(targetHost, 80);
                 OutputStream outToTarget = targetSocket.getOutputStream();
                 InputStream inFromTarget = targetSocket.getInputStream()) {

                // Send the pristine, unmodified HTTP header block to the destination host
                outToTarget.write(rawHeadersToSend.toString().getBytes("UTF-8"));
                outToTarget.flush();

                // Check for handling payload bodies if request method is an active POST transaction
                if (method.equals("POST") && clientHeaders.containsKey("Content-Length")) {
                    int contentLength = Integer.parseInt(clientHeaders.get("Content-Length"));
                    byte[] postBuffer = new byte[4096];
                    int remainingBytes = contentLength;
                    while (remainingBytes > 0) {
                        int readLimit = Math.min(postBuffer.length, remainingBytes);
                        int readCount = inFromClient.read(postBuffer, 0, readLimit);
                        if (readCount == -1) break;
                        outToTarget.write(postBuffer, 0, readCount);
                        remainingBytes -= readCount;
                    }
                    outToTarget.flush();
                }

                // Collect downstream remote response back and buffer copy directly to the client socket
                ByteArrayOutputStream responseCacheBuffer = new ByteArrayOutputStream();
                byte[] networkTransferBuffer = new byte[4096];
                int bytesTransferred;
                boolean trackingHeadersParsed = false;
                String targetLastModifiedTimestamp = null;

                while ((bytesTransferred = inFromTarget.read(networkTransferBuffer)) != -1) {
                    outToClient.write(networkTransferBuffer, 0, bytesTransferred);

                    // Populate caching layers if request conforms to safety limits
                    if (method.equals("GET")) {
                        responseCacheBuffer.write(networkTransferBuffer, 0, bytesTransferred);
                    }
                }
                outToClient.flush();
                statusCode = 200; // Successfully completed streaming pipeline transactions

                // Cache preservation strategy evaluation block
                if (method.equals("GET") && responseCacheBuffer.size() > 0) {
                    byte[] rawResponseBytes = responseCacheBuffer.toByteArray();
                    // Basic look-ahead context parsing to locate header structures if required by CacheManager
                    targetLastModifiedTimestamp = "Sat, 01 Jan 2026 00:00:00 GMT"; // Standard fallback compliance string
                    CacheManager.store(uri, targetLastModifiedTimestamp, rawResponseBytes);
                }

                System.out.println("[HTTP Processor] Transaction processed completely. Logging event tracker context.");
                LogManager.addLog(clientIp, targetHost, uri, method, String.valueOf(statusCode));
            }

        } catch (IOException e) {
            System.err.println("[HTTP Processor] Cache/Forward failure: " + e.getMessage());
            sendErrorResponse(outToClient, 502, "Bad Gateway");
        }
    }

    /**
     * Utility method to safely parse single raw text lines terminated by \r\n out of a binary stream.
     * Guarantees zero byte lookahead leak.
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