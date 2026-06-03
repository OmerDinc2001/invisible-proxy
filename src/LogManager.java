import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class LogManager {

    // Model structure representing a single history row
    public static class LogEntry {
        public String date;
        public String clientIp;
        public String domain;
        public String path;
        public String method;
        public String statusCode;

        public LogEntry(String clientIp, String domain, String path, String method, String statusCode) {
            this.date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());
            // Sanitize IPv6 local loops to clean IPv4 strings for simple filtering matching
            this.clientIp = clientIp.replace("/", "").split(":")[0];
            if (this.clientIp.equals("127.0.0.1")) this.clientIp = "127.0.0.1";

            this.domain = domain != null ? domain : "-";
            this.path = path != null ? path : "-";
            this.method = method != null ? method : "-";
            this.statusCode = statusCode != null ? statusCode : "-";
        }

        @Override
        public String toString() {
            return String.format("%s | Client: %s | Domain: %s | Path: %s | Method: %s | Status: %s",
                    date, clientIp, domain, path, method, statusCode);
        }
    }

    private static final List<LogEntry> globalLogs = new ArrayList<>();

    // Thread-safe method to append intercept lines anywhere in the application
    public static synchronized void addLog(String clientIp, String domain, String path, String method, String statusCode) {
        globalLogs.add(new LogEntry(clientIp, domain, path, method, statusCode));
    }

    // Generates a plain-text report matching specified conditions
    public static synchronized String generateReportForIp(String targetIp) {
        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================================\n");
        sb.append("                      TRANSPARENT PROXY HISTORY LOG REPORT                       \n");
        sb.append("                      TARGET CLIENT IP: ").append(targetIp).append("\n");
        sb.append("=================================================================================\n\n");

        int matchCount = 0;
        for (LogEntry entry : globalLogs) {
            if (entry.clientIp.equalsIgnoreCase(targetIp.trim())) {
                sb.append(entry.toString()).append("\n");
                matchCount++;
            }
        }

        if (matchCount == 0) {
            sb.append("[INFO] No historical records found matching requested client connection footprint.");
        }
        return sb.toString();
    }
}
