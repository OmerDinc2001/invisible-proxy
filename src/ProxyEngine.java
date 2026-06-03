import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public class ProxyEngine implements Runnable {
    private final int port;
    private ServerSocket serverSocket;
    private volatile boolean isRunning;

    public ProxyEngine(int port) {
        this.port = port;
        this.isRunning = false;
    }

    @Override
    public void run() {
        this.isRunning = true;
        try {
            // Bind to the designated proxy port (e.g., 8888 or 80)
            serverSocket = new ServerSocket(port);
            System.out.println("[ProxyEngine] Listening for transparent traffic on port " + port + "...");

            while (isRunning) {
                try {
                    // Wait for incoming intercept traffic
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("[ProxyEngine] Intercepted new connection from: " + clientSocket.getRemoteSocketAddress());

                    Thread handlerThread = new Thread(new ConnectionHandler(clientSocket));
                    handlerThread.start();

                } catch (SocketException se) {
                    // This exception is expected when serverSocket.close() is called to stop the engine
                    if (!isRunning) {
                        System.out.println("[ProxyEngine] Socket listener closed safely.");
                    } else {
                        se.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("[ProxyEngine] Critical failure starting ServerSocket on port " + port);
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    public synchronized void stop() {
        if (!isRunning) return;
        System.out.println("[ProxyEngine] Shutting down network loops...");
        isRunning = false;
        cleanup();
    }

    private void cleanup() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                System.err.println("[ProxyEngine] Error closing server socket: " + e.getMessage());
            }
        }
        System.out.println("[ProxyEngine] Offline.");
    }
}
