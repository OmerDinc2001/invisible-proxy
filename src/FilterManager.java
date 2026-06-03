import java.util.Collections;
import java.util.Set;
import java.util.ConcurrentModificationException;
import java.util.concurrent.ConcurrentHashMap;

public class FilterManager {
    // Thread-safe set to prevent race conditions between Web UI thread and Proxy threads
    private static final Set<String> bannedHosts = ConcurrentHashMap.newKeySet();

    static {
        // Adding a default testing host
        bannedHosts.add("banned-example.com");
    }

    public static void addHost(String host) {
        if (host != null && !host.trim().isEmpty()) {
            bannedHosts.add(host.trim().toLowerCase());
            System.out.println("[FilterManager] Added to blocklist: " + host.trim().toLowerCase());
        }
    }

    public static void removeHost(String host) {
        bannedHosts.remove(host.trim().toLowerCase());
    }

    public static boolean isBanned(String host) {
        if (host == null) return false;
        String sanitizedHost = host.trim().toLowerCase();

        // Match exact or parent wildcard domain strings
        for (String banned : bannedHosts) {
            if (sanitizedHost.equals(banned) || sanitizedHost.endsWith("." + banned)) {
                return true;
            }
        }
        return false;
    }

    public static Set<String> getBannedHosts() {
        return Collections.unmodifiableSet(bannedHosts);
    }
}
