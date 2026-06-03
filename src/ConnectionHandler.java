import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ConnectionHandler implements Runnable {
    private final Socket clientSocket;

    public ConnectionHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        // Use a BufferedInputStream so we can "peek" at the data and reset the stream pointer
        try (BufferedInputStream inFromClient = new BufferedInputStream(clientSocket.getInputStream());
             OutputStream outToClient = clientSocket.getOutputStream()) {

            // Mark the stream read limit up to 512 bytes so we can safely reset it later
            inFromClient.mark(512);

            int firstByte = inFromClient.read();
            if (firstByte == -1) {
                return; // Connection closed early by client
            }

            // Reset the stream so whatever protocol parser runs next reads from byte 0
            inFromClient.reset();

            // Check if the byte matches a TLS Handshake record (0x16)
            if (firstByte == 0x16) {
                System.out.println("[ConnectionHandler] Detected -> HTTPS (TLS Handshake Record 0x16)");
                handleHttps(inFromClient, outToClient);
            } else {
                System.out.println("[ConnectionHandler] Detected -> HTTP (Plaintext/Other)");
                handleHttp(inFromClient, outToClient);
            }

        } catch (IOException e) {
            System.err.println("[ConnectionHandler] Error handling communication: " + e.getMessage());
        } finally {
            try {
                if (!clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                System.err.println("[ConnectionHandler] Final socket closure error: " + e.getMessage());
            }
        }
    }

    private void handleHttp(InputStream in, OutputStream out) throws IOException {
        System.out.println("[HTTP Processor] Initializing parsing loops...");
        // Forward the stream data into our newly created validator
        String clientIp = clientSocket.getInetAddress().getHostAddress();
        HttpProcessor.process(in, out, clientIp);
    }

    private void handleHttps(InputStream in, OutputStream out) throws IOException {
        System.out.println("[HTTPS Processor] Initializing TLS record parsing loops...");
        // Pass control over to our binary SNI tracking engine
        HttpsProcessor.process(in, out);
    }
}
