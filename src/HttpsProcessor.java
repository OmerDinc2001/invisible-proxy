import java.io.*;
import java.net.Socket;

public class HttpsProcessor {

    public static void process(InputStream inFromClient, OutputStream outToClient) throws IOException {
        // We must wrap the input stream to read binary bytes while preserving them
        // Because ConnectionHandler used a BufferedInputStream, the TLS handshake bytes 
        // are still fully waiting for us at byte 0.

        inFromClient.mark(1024 * 16); // Mark up to 16KB just in case
        byte[] handshakeBuffer = new byte[1024 * 16];

        // Read the initial chunk of the TLS Handshake
        int bytesRead = inFromClient.read(handshakeBuffer, 0, 5);
        if (bytesRead < 5) {
            return; // Not enough bytes for a valid TLS record header
        }

        // Verify Content Type is Handshake (0x16)
        if (handshakeBuffer[0] != 0x16) {
            return;
        }

        // Extract total record length from bytes 3 and 4
        int recordLength = ((handshakeBuffer[3] & 0xFF) << 8) | (handshakeBuffer[4] & 0xFF);

        // Read the rest of the TLS Record block body
        int totalBodyRead = 0;
        while (totalBodyRead < recordLength) {
            int read = inFromClient.read(handshakeBuffer, 5 + totalBodyRead, recordLength - totalBodyRead);
            if (read == -1) break;
            totalBodyRead += read;
        }

        // Reset the stream pointer back to zero so our forwarder can send the intact handshake later
        inFromClient.reset();

        // 1. Parse the SNI extension from the raw byte array
        String sniHost = extractSNI(handshakeBuffer, 5, recordLength);

        if (sniHost == null) {
            System.out.println("[HTTPS Processor] SNI Extension not found or unparseable. Defaulting to structural tunnel routing.");
            // If SNI isn't present, we can't filter it, so we just pass it along
        } else {
            System.out.println("\n[HTTPS Processor] TLS SNI Extracted: " + sniHost + "");

            // 2. Enforce Filter Block Rules
            if (FilterManager.isBanned(sniHost)) {
                System.out.println("[HTTPS Processor] ENFORCED DROP: Blocked secure host connection -> " + sniHost);
                LogManager.addLog("127.0.0.1", sniHost, "Encrypted/Hidden", "CONNECT", "403 Blocked");
                return; // Dropping the connection without completing the handshake blocks the site
            }
        }

        // 3. Establish a Blind TCP Tunnel to the Upstream Destination
        String targetHost = (sniHost != null) ? sniHost : "127.0.0.1";
        int targetPort = 443; // Secure HTTPS port

        System.out.println("[HTTPS Processor] Tunneling data streams to remote destination: " + targetHost + ":" + targetPort);

        try (Socket serverSocket = new Socket(targetHost, targetPort);
             OutputStream outToServer = serverSocket.getOutputStream();
             InputStream inFromServer = serverSocket.getInputStream()) {

            // Configure socket timeouts so lingering loops drop quickly
            serverSocket.setSoTimeout(10000);

            // Spawn an independent background sub-thread to pipe data from client to server concurrently
            Thread clientToServerWorker = new Thread(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = inFromClient.read(buffer)) != -1) {
                        outToServer.write(buffer, 0, len);
                        outToServer.flush();
                    }
                } catch (IOException ignored) {}
            });
            clientToServerWorker.start();

            // Use the main handler thread to pipe data from remote server back down to client
            byte[] serverBuffer = new byte[8192];
            int length;
            while ((length = inFromServer.read(serverBuffer)) != -1) {
                outToClient.write(serverBuffer, 0, length);
                outToClient.flush();
            }

            // Join worker thread to guarantee orderly teardown
            try { clientToServerWorker.join(); } catch (InterruptedException ignored) {}

            LogManager.addLog("127.0.0.1", targetHost, "Encrypted/Hidden", "CONNECT", "Tunnel Closed");

        } catch (IOException e) {
            System.err.println("[HTTPS Processor] Tunnel error targeting (" + targetHost + "): " + e.getMessage());
        }
    }

    /**
     * Binary helper logic parsing standard RFC 6066 TLS SNI Server Name Extensions
     */
    private static String extractSNI(byte[] data, int offset, int length) {
        try {
            int pos = offset;

            // Handshake Type must be ClientHello (1)
            if (data[pos] != 1) return null;
            pos += 4; // Skip Handshake Type & 3-byte length
            pos += 2; // Skip Version (Major/Minor)
            pos += 32; // Skip Client Random bytes

            // Skip Session ID field
            int sessionIdLen = data[pos] & 0xFF;
            pos += 1 + sessionIdLen;

            // Skip Cipher Suites field
            int cipherSuiteLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2 + cipherSuiteLen;

            // Skip Compression Methods field
            int compLen = data[pos] & 0xFF;
            pos += 1 + compLen;

            if (pos >= offset + length) return null; // No extensions included

            // Extensions Total Length
            int extTotalLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;

            int endExtPos = pos + extTotalLen;

            // Iterate through every available individual extension block
            while (pos < endExtPos) {
                int extType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                int extLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
                pos += 4;

                if (extType == 0) { // Extension Type 0 is Server Name Indication (SNI)
                    pos += 2; // Skip Server Name List length total
                    int nameType = data[pos] & 0xFF; // Type 0 is hostname string
                    pos += 1;

                    if (nameType == 0) {
                        int nameLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                        pos += 2;
                        return new String(data, pos, nameLen, "UTF-8");
                    }
                }
                pos += extLen; // Jump forward past unneeded extension payloads
            }
        } catch (Exception ignored) {}
        return null; // Extraction failed or was missing payload
    }
}