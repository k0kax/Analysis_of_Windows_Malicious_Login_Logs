import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import os
import time
from analyzer import process_events
from recognizer import LogAnalyzer
from datetime import timezone,datetime, timedelta
# 文件名：ui.py

class LogAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EVTX日志分析工具 v3.0")
        self.root.geometry("800x600")

        # 初始化状态
        self.is_processing = False
        self.current_stage = "等待操作"
        self.last_update = 0  # 最后更新时间戳
        self.output_dir = ""

        # 初始化UI组件
        self.create_widgets()

    def create_widgets(self):
        # 文件选择部分
        file_frame = ttk.LabelFrame(self.root, text="文件选择")
        file_frame.pack(padx=10, pady=5, fill="x")

        ttk.Button(file_frame, text="选择EVTX文件", command=self.select_evtx).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="选择配置(YAML)", command=self.select_yaml).grid(row=0, column=1, padx=5)

        self.evtx_path = tk.StringVar()
        self.yaml_path = tk.StringVar(value="config.yaml")
        ttk.Label(file_frame, text="EVTX文件:").grid(row=1, column=0, sticky="w")
        ttk.Entry(file_frame, textvariable=self.evtx_path, width=50, state='readonly').grid(row=1, column=1,
                                                                                            sticky="ew")
        ttk.Label(file_frame, text="配置文件:").grid(row=2, column=0, sticky="w")
        ttk.Entry(file_frame, textvariable=self.yaml_path, width=50, state='readonly').grid(row=2, column=1,
                                                                                            sticky="ew")

        # 进度显示
        progress_frame = ttk.LabelFrame(self.root, text="处理进度")
        progress_frame.pack(padx=10, pady=5, fill="x")

        self.progress_bar = ttk.Progressbar(progress_frame, mode="determinate")
        self.progress_bar.pack(padx=5, pady=5, fill="x")
        self.progress_label = ttk.Label(progress_frame, text=self.current_stage)
        self.progress_label.pack()

        # 日志输出
        log_frame = ttk.LabelFrame(self.root, text="处理日志")
        log_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(log_frame, height=12, wrap=tk.WORD)
        self.log_area.pack(fill="both", expand=True)

        # 操作按钮
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=5)

        self.start_btn = ttk.Button(btn_frame, text="开始分析", command=self.start_analysis)
        self.start_btn.pack(side="left", padx=5)
        ttk.Button(btn_frame, text="退出", command=self.root.quit).pack(side="right", padx=5)

    def select_evtx(self):
        path = filedialog.askopenfilename(
            title="选择EVTX文件",
            filetypes=[("EVTX 文件", "*.evtx"), ("所有文件", "*.*")]
        )
        if path:
            self.evtx_path.set(path)
            self.output_dir = os.path.join(os.path.dirname(path), "分析结果")
            self.log_message(f"[系统] 已选择EVTX文件: {os.path.basename(path)}")

    def select_yaml(self):
        path = filedialog.askopenfilename(
            title="选择配置文件",
            filetypes=[("YAML 文件", "*.yaml"), ("所有文件", "*.*")]
        )
        if path:
            self.yaml_path.set(path)
            self.log_message(f"[系统] 已选择配置文件: {os.path.basename(path)}")

    def log_message(self, message):
        # 添加当前北京时间
        beijing_time = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
        self.log_area.insert(tk.END, f"[{beijing_time}] {message}\n")
        self.log_area.see(tk.END)
        self.root.update_idletasks()
        print(message)
    def update_progress(self, data):
        current_time = time.time()
        # 限流：每秒最多更新2次，除非是最终更新
        if (current_time - self.last_update < 0.5 and
                data.get("current", 0) != data.get("total", 1)):
            return

        self.last_update = current_time

        current = data.get("current", 0)
        total = data.get("total", 1)
        message = data.get("message", "")

        if total > 0 and current <= total:
            self.progress_bar["value"] = (current / total) * 100
            self.progress_label.config(text=f"{self.current_stage} ({current}/{total})")

        if message:
            self.log_area.insert(tk.END, message + "\n")
            self.log_area.see(tk.END)

        self.root.update_idletasks()

    def start_analysis(self):
        if self.is_processing:
            return

        evtx_path = self.evtx_path.get()
        yaml_path = self.yaml_path.get()

        if not evtx_path:
            messagebox.showerror("错误", "请先选择EVTX文件")
            return
        if not os.path.exists(evtx_path):
            messagebox.showerror("错误", "EVTX文件不存在")
            return

        self.is_processing = True
        self.start_btn.config(state="disabled")
        self.log_message("\n=== 开始分析流程 ===")

        # 启动后台线程
        thread = threading.Thread(
            target=self.run_analysis_pipeline,
            args=(evtx_path, yaml_path),
            daemon=True
        )
        thread.start()

    def run_analysis_pipeline(self, evtx_path, yaml_path):
        try:
            # 阶段1: 解析EVTX
            self.current_stage = "解析EVTX文件"
            self.root.after(10, self.update_progress, {"current": 0, "total": 1})
            self.log_message(f"\n[阶段1] 正在解析 {os.path.basename(evtx_path)}...")

            def evtx_callback(data):
                self.root.after(10, self.update_progress, data)

            process_events(
                evtx_path,
                output_dir=self.output_dir,
                progress_callback=evtx_callback,
                report_interval=10  # 新增参数控制报告间隔
            )

            # 阶段2: 安全分析
            self.current_stage = "安全分析"
            self.root.after(10, self.update_progress, {"current": 0, "total": 1})
            self.log_message("\n[阶段2] 正在执行安全分析...")

            analyzer = LogAnalyzer(yaml_path)
            results = analyzer.analyze_directory(
                self.output_dir,
                output_file=os.path.join(self.output_dir, "安全检测结果.json")
            )

            # 显示结果摘要
            self.log_message(f"\n=== 分析完成 ===")
            self.log_message(f"共发现 {len(results)} 条可疑事件")
            self.log_message(f"结果文件: {os.path.join(self.output_dir, '安全检测结果.json')}")

            # 自动打开结果目录
            if os.path.exists(self.output_dir):
                os.startfile(self.output_dir) if os.name == 'nt' else os.system(f'open "{self.output_dir}"')

        except Exception as e:
            self.log_message(f"\n[错误] 处理过程中发生异常: {str(e)}")
            messagebox.showerror("错误", f"处理失败: {str(e)}")
        finally:
            self.is_processing = False
            self.root.after(10, lambda: self.start_btn.config(state="normal"))
            self.root.after(10, self.update_progress, {
                "current": 100,
                "total": 100,
                "message": "[系统] 处理流程已结束"
            })


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerUI(root)
    root.mainloop()