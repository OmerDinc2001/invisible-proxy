import java.io.*;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class CacheManager {
    private static final String CACHE_DIR = "./proxy_cache/";
    // Maps standard URLs to their Last-Modified header strings
    private static final Map<String, String> manifest = new HashMap<>();

    static {
        File dir = new File(CACHE_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    /**
     * Retrieves the stored Last-Modified timestamp metadata for a given resource URL
     */
    public static synchronized String getLastModified(String url) {
        return manifest.get(url);
    }

    /**
     * Checks if a cached copy physically exists on the disk architecture
     */
    public static synchronized boolean hasCache(String url) {
        if (!manifest.containsKey(url)) return false;
        File file = getCacheFile(url);
        return file.exists() && file.isFile();
    }

    /**
     * Saves a web asset's response body payload and metadata directly onto disk [cite: 50, 52]
     */
    public static synchronized void store(String url, String lastModified, byte[] bodyContent) {
        if (url == null || lastModified == null || bodyContent == null) return;

        manifest.put(url, lastModified);
        File targetFile = getCacheFile(url);

        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(bodyContent);
            fos.flush();
            System.out.println("[CacheManager] SUCCESSFULLY CACHED: " + url + " (Modified: " + lastModified + ") [cite: 52, 59]");
        } catch (IOException e) {
            System.err.println("[CacheManager] Write failure for asset cache: " + e.getMessage());
        }
    }

    /**
     * Streams a locally stored resource file straight back down to the client's output socket
     */
    public static synchronized void serveFromCache(String url, OutputStream outToClient) throws IOException {
        File file = getCacheFile(url);
        if (!file.exists()) return;

        System.out.println("[CacheManager] SERVING RESOURCE FROM DISK CACHE -> " + url + " ");

        // Build a standard success container header block
        String headers = "HTTP/1.1 200 OK\r\n" +
                "Content-Length: " + file.length() + "\r\n" +
                "Content-Type: text/html; charset=UTF-8\r\n" +
                "X-Proxy-Cache: HIT\r\n" + // Helper header to track cache hits during testing
                "Connection: close\r\n\r\n";

        outToClient.write(headers.getBytes("UTF-8"));

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                outToClient.write(buffer, 0, read);
            }
        }
        outToClient.flush();
    }

    private static File getCacheFile(String url) {
        try {
            // Encode the URL string into a completely safe filename structure
            String safeName = URLEncoder.encode(url, "UTF-8");
            return new File(CACHE_DIR, safeName + ".cache");
        } catch (UnsupportedEncodingException e) {
            return new File(CACHE_DIR, Math.abs(url.hashCode()) + ".cache");
        }
    }
}
