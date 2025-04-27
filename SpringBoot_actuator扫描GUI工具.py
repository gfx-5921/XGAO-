import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
import re

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

PATHS = [
    "/api-docs", "/actuator", "/env", "/health", 
    # 可自行丰富路径
    "/v1/console/server/state?accessToken=&username="
    "/actuator",
    "/actuator/./env",
    "/actuator/auditLog",
    "/actuator/auditevents",
    "/actuator/autoconfig",
    "/actuator/beans",
    "/actuator/caches",
    "/actuator/conditions",
    "/actuator/configurationMetadata",
    "/actuator/configprops",
    "/actuator/dump",
    "/actuator/env",
    "/actuator/events",
    "/actuator/exportRegisteredServices",
    "/actuator/features",
    "/actuator/flyway",
    "/actuator/health",
    "/actuator/healthcheck",
    "/actuator/httptrace",
    "/actuator/hystrix.stream",
    "/actuator/info",
    "/actuator/integrationgraph",
    "/actuator/jolokia",
    "/actuator/logfile",
    "/actuator/loggers",
    "/actuator/loggingConfig",
    "/actuator/liquibase",
    "/actuator/metrics",
    "/actuator/mappings",
    "/actuator/scheduledtasks",
    "/actuator/swagger-ui.html",
    "/actuator/prometheus",
    "/actuator/refresh",
    "/actuator/registeredServices",
    "/actuator/releaseAttributes",
    "/actuator/resolveAttributes",
    "/actuator/sessions",
    "/actuator/springWebflow",
    "/actuator/sso",
    "/actuator/ssoSessions",
    "/actuator/statistics",
    "/actuator/status",
    "/actuator/threaddump",
    "/actuator/trace",
    "/actuator/env.css",
    "/artemis-portal/artemis/env",
    "/artemis/api",
    "/artemis/api/env",
    "/auditevents",
    "/autoconfig",
    "/api",
    "/api.html",
    "/api/actuator",
    "/api/doc",
    "/api/index.html",
    "/api/swaggerui",
    "/api/swagger-ui.html",
    "/api/swagger",
    "/api/swagger/ui",
    "/api/v2/api-docs",
    "/api/v2;%0A/api-docs",
    "/api/v2;%252Ftest/api-docs",
    "/beans",
    "/caches",
    "/cloudfoundryapplication",
    "/conditions",
    "/configprops",
    "/distv2/index.html",
    "/docs",
    "/doc.html",
    "/druid",
    "/druid/index.html",
    "/druid/login.html",
    "/druid/websession.html",
    "/dubbo-provider/distv2/index.html",
    "/dump",
    "/decision/login",
    "/entity/all",
    "/env",
    "/env.css",
    "/env/(name)",
    "/eureka",
    "/flyway",
    "/gateway/actuator",
    "/gateway/actuator/auditevents",
    "/gateway/actuator/beans",
    "/gateway/actuator/conditions",
    "/gateway/actuator/configprops",
    "/gateway/actuator/env",
    "/gateway/actuator/health",
    "/gateway/actuator/httptrace",
    "/gateway/actuator/hystrix.stream",
    "/gateway/actuator/info",
    "/gateway/actuator/jolokia",
    "/gateway/actuator/logfile",
    "/gateway/actuator/loggers",
    "/gateway/actuator/mappings",
    "/gateway/actuator/metrics",
    "/gateway/actuator/scheduledtasks",
    "/gateway/actuator/swagger-ui.html",
    "/gateway/actuator/threaddump",
    "/gateway/actuator/trace",
    "/gateway/routes",
    "/health",
    "/httptrace",
    "/hystrix",
    "/info",
    "/integrationgraph",
    "/jolokia",
    "/jolokia/list",
    "/jeecg/swagger-ui",
    "/jeecg/swagger/",
    "/libs/swaggerui",
    "/liquibase",
    "/list",
    "/logfile",
    "/loggers",
    "/metrics",
    "/mappings",
    "/monitor",
    "/nacos",
    "/prod-api/actuator",
    "/prometheus",
    "/portal/conf/config.properties",
    "/portal/env/",
    "/refresh",
    "/scheduledtasks",
    "/sessions",
    "/spring-security-oauth-resource/swagger-ui.html",
    "/spring-security-rest/api/swagger-ui.html",
    "/static/swagger.json",
    "/sw/swagger-ui.html",
    "/swagger",
    "/swagger/codes",
    "/swagger/doc.json",
    "/swagger/index.html",
    "/swagger/static/index.html",
    "/swagger/swagger-ui.html",
    "/Swagger/ui/index",
    "/swagger/ui",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger-dubbo/api-docs",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui.html;",
    "/swagger-ui/html",
    "/swagger-ui/index.html",
    "/system/druid/index.html",
    "/system/druid/webseesion.html",
    "/threaddump",
    "/template/swagger-ui.html",
    "/trace",
    "/users",
    "/user/swagger-ui.html",
    "/version",
    "/v1/api-docs/",
    "/v2/api-docs/",
    "/v3/api-docs/",
    "/v1/swagger-resources",
    "/v2/swagger-resources",
    "/v3/swagger-resources",
    "/v1.1/swagger-ui.html",
    "/v1.1;%0A/api-docs",
    "/v1.2/swagger-ui.html",
    "/v1.2;%0A/api-docs",
    "/v1.3/swagger-ui.html",
    "/v1.3;%0A/api-docs",
    "/v1.4/swagger-ui.html",
    "/v1.4;%0A/api-docs",
    "/v1.5/swagger-ui.html",
    "/v1.5;%0A/api-docs",
    "/v1.6/swagger-ui.html",
    "/v1.6;%0A/api-docs",
    "/v1.7/swagger-ui.html",
    "/v1.7;%0A/api-docs",
    "/v1.8/swagger-ui.html",
    "/v1.8;%0A/api-docs",
    "/v1.9/swagger-ui.html",
    "/v1.9;%0A/api-docs",
    "/v2.0/swagger-ui.html",
    "/v2.0;%0A/api-docs",
    "/v2.1/swagger-ui.html",
    "/v2.1;%0A/api-docs",
    "/v2.2/swagger-ui.html",
    "/v2.2;%0A/api-docs",
    "/v2.3/swagger-ui.html",
    "/v2.3;%0A/api-docs",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/v2;%0A/api-docs",
    "/v3;%0A/api-docs",
    "/v2;%252Ftest/api-docs",
    "/v3;%252Ftest/api-docs",
    "/webpage/system/druid/websession.html",
    "/webpage/system/druid/index.html",
    "/webroot/decision/login",
    "/webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js",
    "/webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js?v=2.9.2",
    "/webjars/springfox-swagger-ui/springfox.js",
    "/webjars/springfox-swagger-ui/springfox.js?v=2.9.2",
    "/webjars/springfox-swagger-ui/swagger-ui-bundle.js",
    "/webjars/springfox-swagger-ui/swagger-ui-bundle.js?v=2.9.2",
    "/%20/swagger-ui.html",
    "/v2/api-docs",
    "/heapdump",
    "/intergrationgraph",
    "/shutdown",
    "/actuator/heapdump",
    "/actuator/shutdown",
    "/gateway/actuator/heapdump",
    "/heapdump.json",
    "/hystrix.stream",
    "/v1/console/server/state?accessToken=&username=",
    "/nacos/v1/console/server/state?accessToken=&username="
]

class URLScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("SpringBoot扫描器 v0.1 - by")
        
        # 初始化所有控件
        self.progress = ttk.Progressbar(master, length=400)  # 先初始化进度条
        self.status_label = ttk.Label(master, text="就绪")    # 初始化状态标签
        
        # 创建主布局
        self.create_widgets()
        self.executor = ThreadPoolExecutor(max_workers=20)

    def create_widgets(self):
        # 创建选项卡
        self.notebook = ttk.Notebook(self.master)
        
        # 单URL扫描面板
        self.single_tab = ttk.Frame(self.notebook)
        self.create_single_tab()
        
        # 批量扫描面板
        self.batch_tab = ttk.Frame(self.notebook)
        self.create_batch_tab()
        
        # 布局主界面
        self.notebook.add(self.single_tab, text="单URL扫描")
        self.notebook.add(self.batch_tab, text="批量扫描")
        self.notebook.pack(expand=1, fill="both")
        
        # 结果区域
        self.result_area = scrolledtext.ScrolledText(self.master, height=15)
        self.result_area.pack(expand=1, fill="both", padx=5, pady=5)
        
        # 进度组件
        self.progress.pack(pady=5)
        self.status_label.pack()
        
        # 导出按钮
        self.export_btn = ttk.Button(self.master, text="导出结果", command=self.export_results)
        self.export_btn.pack(pady=5)

    def create_single_tab(self):
        frame = ttk.Frame(self.single_tab)
        ttk.Label(frame, text="目标URL:").pack(side="left", padx=5)
        
        self.single_url = tk.StringVar()
        self.url_entry = ttk.Entry(frame, textvariable=self.single_url, width=50)
        self.url_entry.pack(side="left", padx=5)
        
        self.scan_btn = ttk.Button(frame, text="开始扫描", command=self.start_single_scan)
        self.scan_btn.pack(side="left", padx=5)
        
        frame.pack(pady=10)
        # 在结果区域下方添加进度组件
        self.progress.pack(pady=5)
        self.status_label.pack()

    def create_batch_tab(self):
        frame = ttk.Frame(self.batch_tab)
        self.batch_text = scrolledtext.ScrolledText(frame, height=10, width=70)
        self.batch_text.pack(padx=5, pady=5)
        
        self.batch_btn = ttk.Button(frame, text="开始批量扫描", command=self.start_batch_scan)
        self.batch_btn.pack(pady=5)
        
        frame.pack()
        
    def start_single_scan(self):
        url = self.single_url.get().strip()
        if not url:
            messagebox.showerror("错误", "请输入URL")
            return
            
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, f"开始扫描: {url}\n")
        self.scan_url(url)
        self.total_tasks = len(PATHS)
        self.completed_tasks = 0

    def start_batch_scan(self):
        urls = self.batch_text.get(1.0, tk.END).splitlines()
        if not urls:
            messagebox.showerror("错误", "请输入至少一个URL")
            return
            
        self.result_area.delete(1.0, tk.END)
        for url in urls:
            if url.strip():
                self.executor.submit(self.scan_url, url.strip())
                
    def scan_url(self, base_url):
        base_url = base_url.rstrip('/')
        futures = []
        
        for path in PATHS:
            full_url = f"{base_url}{path}"
            futures.append(self.executor.submit(self.check_endpoint, full_url))
            
        for future in futures:
            future.add_done_callback(self.update_result)
            
    def check_endpoint(self, url):
        try:
            response = requests.get(url, 
                                  verify=False, 
                                  timeout=5,
                                  headers={'User-Agent': 'Python Scanner'})
            
            if response.status_code == 200:
                return f"[+] {url} - 200 OK (Length: {len(response.text)})\n"
        except Exception as e:
            return f"[-] {url} - 错误: {str(e)}\n"
            
    def update_result(self, future):
        result = future.result()
        if result:
            self.result_area.insert(tk.END, result)
            self.result_area.see(tk.END)
        
        # 更新进度
        self.completed_tasks += 1
        progress = self.completed_tasks / self.total_tasks * 100
        self.progress['value'] = progress
        self.status_label.config(text=f"扫描进度: {progress:.1f}%")
        
        # 完成检测
        if self.completed_tasks >= self.total_tasks:
            self.progress['value'] = 0
            self.status_label.config(text="就绪")
            messagebox.showinfo("扫描完成", "所有扫描任务已完成！")
            
    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.result_area.get(1.0, tk.END))
            messagebox.showinfo("导出成功", "结果已保存")

if __name__ == "__main__":
    root = tk.Tk()
    app = URLScannerGUI(root)
    root.mainloop()
