import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.util.Set;

public class ControlServer {
    private int port;
    private HttpServer server;
    private boolean isProxyRunning = false;

    // Core Engine Integration
    private ProxyEngine proxyEngine;
    private Thread proxyThread;

    public ControlServer(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        // Map all our API endpoints
        server.createContext("/", new DashboardHandler());
        server.createContext("/checkstate", new StatusHandler());
        server.createContext("/execstart", new StartHandler());
        server.createContext("/execstop", new StopHandler());
        server.createContext("/addfilter", new AddFilterHandler());
        server.createContext("/listfilter", new ListFilterHandler());
        server.createContext("/removefilter", new RemoveFilterHandler());
        server.createContext("/generatereport", new ReportGeneratorHandler());

        server.setExecutor(null);
        server.start();

        System.out.println("=================================================");
        System.out.println("[INIT] GUI Control Server successfully launched!");
        System.out.println("[INIT] Open Chromium and go to: http://localhost:" + port);
        System.out.println("=================================================");
    }

    // --- HTML GUI GENERATOR (WITH START, STOP, REPORT, & HELP BUTTONS) ---
    private class DashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();

            // Safely ignore background icon requests without breaking the main page
            if (path.contains("favicon.ico")) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            System.out.println("[ControlServer] Serving dashboard UI to browser. Requested Path: " + path);

            String html = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "    <title>Proxy Control Panel</title>\n" +
                    "    <style>\n" +
                    "        body { font-family: sans-serif; background: #e0e0e0; margin:0; padding:0; }\n" +
                    "        .menu-bar { background: #f0f0f0; border-bottom: 1px solid #b2b2b2; padding: 5px 10px; display: flex; gap: 5px; }\n" +
                    "        .menu-item { display: inline-block; padding: 6px 12px; cursor: pointer; color: black; border: 1px solid transparent; user-select: none; }\n" +
                    "        .menu-item:hover { background: #e5e5e5; border: 1px solid #b2b2b2; }\n" +
                    "        .container { display: flex; padding: 20px; gap: 20px; }\n" +
                    "        .status-container { flex: 2; display: flex; justify-content: center; align-items: center; height: 200px; background: #ffffff; border: 1px solid #b2b2b2; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); }\n" +
                    "        .status-text { font-style: italic; font-size: 24px; font-weight: bold; color: #444; }\n" +
                    "        .filter-container { flex: 1; background: #ffffff; padding: 15px; border: 1px solid #b2b2b2; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); }\n" +
                    "        input[type='text'] { width: 70%; padding: 5px; }\n" +
                    "        button { padding: 5px 10px; cursor: pointer; }\n" +
                    "        ul { padding-left: 20px; word-wrap: break-word; }\n" +
                    "        \n" +
                    "        /* Modal Overlay Styles */\n" +
                    "        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.4); }\n" +
                    "        .modal-content { background-color: #fff; margin: 10% auto; padding: 20px; border: 1px solid #888; width: 50%; box-shadow: 0 4px 8px rgba(0,0,0,0.2); max-height: 70vh; overflow-y: auto; }\n" +
                    "        .close-btn { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }\n" +
                    "        .close-btn:hover { color: black; }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "    <div class='menu-bar'>\n" +
                    "        <div class='menu-item' onclick='sendAction(\"/execstart\")'>Start</div>\n" +
                    "        <div class='menu-item' onclick='sendAction(\"/execstop\")'>Stop</div>\n" +
                    "        <div class='menu-item' onclick='openModal(\"reportModal\")'>Report</div>\n" +
                    "        <div class='menu-item' onclick='openModal(\"helpModal\")'>Help</div>\n" +
                    "    </div>\n" +
                    "    \n" +
                    "    <div class='container'>\n" +
                    "        <div class='status-container'>\n" +
                    "            <div id='status' class='status-text'>Initializing Panel...</div>\n" +
                    "        </div>\n" +
                    "        <div class='filter-container'>\n" +
                    "            <h3>Host Filtering</h3>\n" +
                    "            <input type='text' id='hostInput' placeholder='example.com'>\n" +
                    "            <button onclick='addHost()'>Add</button>\n" +
                    "            <h4>Active Rules:</h4>\n" +
                    "            <ul id='filterList'></ul>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "    \n" +
                    "    \n" +
                    "    <div id='reportModal' class='modal'>\n" +
                    "        <div class='modal-content'>\n" +
                    "            <span class='close-btn' onclick='closeModal(\"reportModal\")'>&times;</span>\n" +
                    "            <h2>Generate History Log Report</h2>\n" +
                    "            <hr>\n" +
                    "            <p>Enter a specific client's IP address to compile and download their network transaction history details:</p>\n" +
                    "            <input type='text' id='clientIpInput' placeholder='127.0.0.1' style='width: 60%; padding: 8px;'>\n" +
                    "            <button onclick='downloadReport()' style='padding: 8px 15px;'>Download TXT Report</button>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "    \n" +
                    "    <div id='helpModal' class='modal'>\n" +
                    "        <div class='modal-content'>\n" +
                    "            <span class='close-btn' onclick='closeModal(\"helpModal\")'>&times;</span>\n" +
                    "            <h2>Information</h2>\n" +
                    "            <hr>\n" +
                    "            <h3>Developer</h3>\n" +
                    "            <p>Name: Ömer Agah DİNÇ</p>\n" +
                    "            <p>Student number: 20200702091</p>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "    \n" +
                    "    <script>\n" +
                    "        function checkStatus() {\n" +
                    "            fetch('/checkstate')\n" +
                    "                .then(r => r.text())\n" +
                    "                .then(t => { document.getElementById('status').innerText = t; })\n" +
                    "                .catch(e => console.error('Status Error:', e));\n" +
                    "        }\n" +
                    "        function sendAction(endpoint) {\n" +
                    "            console.log('Sending action:', endpoint);\n" +
                    "            fetch(endpoint, { method: 'POST' })\n" +
                    "                .then(() => checkStatus())\n" +
                    "                .catch(e => console.error('Action Error:', e));\n" +
                    "        }\n" +
                    "        function updateFilterList() {\n" +
                    "            fetch('/listfilter')\n" +
                    "                .then(r => r.json())\n" +
                    "                .then(list => {\n" +
                    "                    let ul = document.getElementById('filterList');\n" +
                    "                    ul.innerHTML = '';\n" +
                    "                    list.forEach(host => {\n" +
                    "                        let li = document.createElement('li');\n" +
                    "                        li.style.marginBottom = '5px';\n" +
                    "                        li.innerHTML = host + \" <button style='padding:2px 6px; margin-left:10px; font-size:11px; color:red;' onclick='removeHost(\\\"\" + host + \"\\\")'>X</button>\";\n" +
                    "                        ul.appendChild(li);\n" +
                    "                    });\n" +
                    "                })\n" +
                    "                .catch(e => console.error('Filter List Error:', e));\n" +
                    "        }\n" +
                    "        function addHost() {\n" +
                    "            let input = document.getElementById('hostInput');\n" +
                    "            let val = input.value.trim();\n" +
                    "            if(!val) return;\n" +
                    "            fetch('/addfilter', { method: 'POST', body: 'host=' + encodeURIComponent(val) })\n" +
                    "                .then(() => { input.value = ''; updateFilterList(); })\n" +
                    "                .catch(e => console.error('Add Filter Error:', e));\n" +
                    "        }\n" +
                    "        function removeHost(domain) {\n" +
                    "            fetch('/removefilter', {\n" +
                    "                method: 'POST',\n" +
                    "                body: 'host=' + encodeURIComponent(domain)\n" +
                    "            }).then(() => {\n" +
                    "                updateFilterList();\n" +
                    "            }).catch(e => console.error('Remove Filter Error:', e));\n" +
                    "        }\n" +
                    "        \n" +
                    "        // Download filtered client text log attachment\n" +
                    "        function downloadReport() {\n" +
                    "            let ipValue = document.getElementById('clientIpInput').value.trim();\n" +
                    "            if(!ipValue) {\n" +
                    "                alert('Please provide a valid client IP address first.');\n" +
                    "                return;\n" +
                    "            }\n" +
                    "            window.location.href = '/generatereport?ip=' + encodeURIComponent(ipValue);\n" +
                    "            closeModal('reportModal');\n" +
                    "        }\n" +
                    "        \n" +
                    "        // Modal Controls\n" +
                    "        function openModal(id) {\n" +
                    "            document.getElementById(id).style.display = 'block';\n" +
                    "        }\n" +
                    "        function closeModal(id) {\n" +
                    "            document.getElementById(id).style.display = 'none';\n" +
                    "        }\n" +
                    "        \n" +
                    "        // Close modal if user clicks outside the window box\n" +
                    "        window.onclick = function(event) {\n" +
                    "            if (event.target.className === 'modal') {\n" +
                    "                event.target.style.display = 'none';\n" +
                    "            }\n" +
                    "        }\n" +
                    "        \n" +
                    "        // Initialize\n" +
                    "        checkStatus();\n" +
                    "        updateFilterList();\n" +
                    "        setInterval(checkStatus, 2000);\n" +
                    "    </script>\n" +
                    "</body>\n" +
                    "</html>";

            byte[] response = html.getBytes("UTF-8");

            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");

            exchange.sendResponseHeaders(200, response.length);
            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        }
    }

    // --- ENGINE CONTROL API ---
    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            String response = isProxyRunning ? "Proxy Server is Running..." : "Proxy Server is Stopped";
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private class StartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                if (!isProxyRunning) {
                    System.out.println("[ControlServer] ---> 'START' COMMAND ACKNOWLEDGED <---");
                    isProxyRunning = true;
                    proxyEngine = new ProxyEngine(8888);
                    proxyThread = new Thread(proxyEngine);
                    proxyThread.start();
                }
                exchange.sendResponseHeaders(200, 0);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
            exchange.getResponseBody().close();
        }
    }

    private class StopHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                if (isProxyRunning) {
                    System.out.println("[ControlServer] ---> 'STOP' COMMAND ACKNOWLEDGED <---");
                    isProxyRunning = false;
                    if (proxyEngine != null) {
                        proxyEngine.stop();
                    }
                }
                exchange.sendResponseHeaders(200, 0);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
            exchange.getResponseBody().close();
        }
    }

    // --- FILTER CONTROL API ---
    private class AddFilterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                String body = new String(is.readAllBytes(), "UTF-8");
                if (body.startsWith("host=")) {
                    String domain = URLDecoder.decode(body.substring(5), "UTF-8");
                    FilterManager.addHost(domain);
                }
                exchange.sendResponseHeaders(200, 0);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
            exchange.getResponseBody().close();
        }
    }

    private class RemoveFilterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                String body = new String(is.readAllBytes(), "UTF-8");

                // Expecting payload format: host=domain.com
                if (body.startsWith("host=")) {
                    String domain = URLDecoder.decode(body.substring(5), "UTF-8");
                    FilterManager.removeHost(domain); // Drops rule from memory
                }
                exchange.sendResponseHeaders(200, 0);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
            exchange.getResponseBody().close();
        }
    }

    private class ListFilterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            StringBuilder json = new StringBuilder("[");
            Set<String> hosts = FilterManager.getBannedHosts();
            int count = 0;
            for (String h : hosts) {
                json.append("\"").append(h).append("\"");
                if (++count < hosts.size()) json.append(",");
            }
            json.append("]");

            byte[] response = json.toString().getBytes("UTF-8");
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(200, response.length);
            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        }
    }

    private class ReportGeneratorHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);

            String query = exchange.getRequestURI().getQuery();
            String targetIp = "127.0.0.1"; // Default fall-back target

            if (query != null && query.startsWith("ip=")) {
                targetIp = URLDecoder.decode(query.split("=")[1], "UTF-8");
            }

            System.out.println("[ControlServer] Compiling report logs targeting client IP: " + targetIp);
            String reportText = LogManager.generateReportForIp(targetIp);
            byte[] responseBytes = reportText.getBytes("UTF-8");

            // CRITICAL: Configure headers to instruct browser to trigger an immediate physical file download prompt
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"client_" + targetIp + "_report.txt\"");

            exchange.sendResponseHeaders(200, responseBytes.length);
            OutputStream os = exchange.getResponseBody();
            os.write(responseBytes);
            os.close();
        }
    }

    // Utility to prevent browser CORS blocks on local fetching
    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    }

    public static void main(String[] args) throws IOException {
        ControlServer app = new ControlServer(8080);
        app.start();
    }
}