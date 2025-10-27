import yaml
import csv
from datetime import timezone,datetime, timedelta
import os
import json
import argparse
import ipaddress
from collections import defaultdict
from typing import Callable, Optional

# 文件名recognizer3.py
class LogAnalyzer:
    def __init__(self, config_path: str = 'config.yaml', progress_callback: Optional[Callable] = None):
        """
        初始化日志分析器
        :param config_path: 配置文件路径
        :param progress_callback: 进度回调函数 (str: message)
        """
        self.config = self._load_config(config_path)
        self.progress_callback = progress_callback
        self._prepare_ips()

    def _load_config(self, path: str) -> dict:
        """加载YAML配置文件"""
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _prepare_ips(self):
        """预处理允许的IP地址/网段"""
        self.allowed_nets = []
        for ip in self.config.get('allowed_ips', []):
            try:
                if '/' in ip:
                    self.allowed_nets.append(ipaddress.IPv4Network(ip, strict=False))
                else:
                    self.allowed_nets.append(ipaddress.IPv4Address(ip))
            except ValueError:
                continue

    def _is_ip_allowed(self, ip: str) -> bool:
        """验证IP是否在允许列表中"""
        try:
            addr = ipaddress.IPv4Address(ip)
            for net in self.allowed_nets:
                if isinstance(net, ipaddress.IPv4Network) and addr in net:
                    return True
                elif addr == net:
                    return True
        except ValueError:
            pass
        return False

    def _parse_time(self, ts_str: str) -> Optional[datetime]:
        """解析时间字符串（带时区转换）"""
        try:
            # 解析为原生datetime对象（假设ts_str已转换为北京时间字符串）
            naive_dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
            # 添加北京时间时区信息
            return naive_dt.replace(tzinfo=timezone(timedelta(hours=8)))
        except ValueError:
            return None

    def _within_working_hours(self, dt: datetime) -> bool:
        """判断时间是否在北京时间工作时段内"""
        # 确保dt是北京时间
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone(timedelta(hours=8)))
        else:
            dt = dt.astimezone(timezone(timedelta(hours=8)))

        # 提取配置中的工作时间（按北京时间配置）
        start = datetime.strptime(self.config['working_hours']['start'], "%H:%M").time()
        end = datetime.strptime(self.config['working_hours']['end'], "%H:%M").time()

        # 转换为北京时间的time对象
        beijing_time = dt.time()
        return start <= beijing_time <= end

    def _update_progress(self, message: str):
        """触发进度更新回调"""
        if self.progress_callback:
            self.progress_callback(message)

    def analyze_directory(self, input_dir: str, output_file: str = 'detections.json') -> list:
        """
        分析目录中的CSV文件
        :param input_dir: 输入目录路径
        :param output_file: 输出文件路径
        :return: 检测结果列表
        """
        self._update_progress("正在加载数据...")
        data = self._load_data(input_dir)
        results = []

        # 定义检测流程
        detection_steps = [
            ('暴力破解检测', self.detect_brute_force),
            ('横向移动检测', self.detect_lateral_movement),
            ('非工作时间登录检测', self.detect_offhours_login),
            ('非授权IP登录检测', self.detect_unauthorized_ip),
            ('特权滥用检测', self.detect_privilege_abuse)
        ]

        # 执行所有检测步骤
        for step_name, detector in detection_steps:
            self._update_progress(f"正在进行: {step_name}")
            events = data.get('4624', []) + data.get('4625', [])  # 合并相关事件
            results.extend(detector(events))

        # 保存结果
        self._update_progress("正在保存检测结果...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        self._update_progress(f"分析完成，共发现{len(results)}条异常事件")
        return results

    def _load_data(self, input_dir: str) -> dict:
        """加载CSV数据文件"""
        data = {}
        for filename in os.listdir(input_dir):
            if filename.endswith('.csv'):
                event_id = filename.split('.')[0]
                filepath = os.path.join(input_dir, filename)

                self._update_progress(f"正在加载文件: {filename}")
                with open(filepath, 'r', encoding='utf-8') as f:
                    data[event_id] = list(csv.DictReader(f))
        return data

    def detect_brute_force(self, events: list) -> list:
        """检测暴力破解攻击"""
        threshold = self.config['thresholds']['brute_force']
        window = timedelta(minutes=threshold['minutes'])
        results = []

        # 按时间排序事件
        sorted_events = sorted(
            [e for e in events if self._parse_time(e['时间戳'])],
            key=lambda x: self._parse_time(x['时间戳'])
        )

        i = 0
        while i < len(sorted_events):
            current = sorted_events[i]
            current_time = self._parse_time(current['时间戳'])
            count = 0

            # 统计时间窗口内的失败次数
            while i + count < len(sorted_events):
                event_time = self._parse_time(sorted_events[i + count]['时间戳'])
                if (event_time - current_time) <= window:
                    count += 1
                else:
                    break

            if count >= threshold['attempts']:
                results.append({
                    'type': '暴力破解',
                    'start': current['时间戳'],
                    'end': sorted_events[i + count - 1]['时间戳'],
                    'attempts': count,
                    'ip': current.get('IP地址', '未知'),
                    'user': current.get('目标用户', '未知')
                })
            i += count

        return results

    def detect_lateral_movement(self, events: list) -> list:
        """检测横向移动"""
        threshold = self.config['thresholds']['lateral_movement']
        ip_users = defaultdict(set)

        # 收集IP关联用户
        for event in events:
            ip = event.get('IP地址', '')
            if ip not in ('-', ''):
                ip_users[ip].add(event.get('目标用户', '未知'))

        return [{
            'type': '横向移动',
            'ip': ip,
            'users': list(users),
            'count': len(users)
        } for ip, users in ip_users.items() if len(users) >= threshold['users']]

    def detect_offhours_login(self, events: list) -> list:
        """检测非工作时间登录"""
        return [{
            'type': '非工作时间登录',
            'time': event['时间戳'],
            'user': event.get('目标用户', '未知'),
            'ip': event.get('IP地址', '未知')
        } for event in events
            if (dt := self._parse_time(event['时间戳']))
               and not self._within_working_hours(dt)]

    def detect_unauthorized_ip(self, events: list) -> list:
        """检测非授权IP登录"""
        return [{
            'type': '非授权IP登录',
            'time': event['时间戳'],
            'ip': event.get('IP地址', '未知'),
            'user': event.get('目标用户', '未知')
        } for event in events
            if (ip := event.get('IP地址', ''))
               and not self._is_ip_allowed(ip)]

    def detect_privilege_abuse(self, events: list) -> list:
        """检测特权账户滥用"""
        privileged = set(self.config.get('privileged_accounts', []))
        return [{
            'type': '特权滥用',
            'time': event['时间戳'],
            'user': event.get('目标用户', '未知'),
            'ip': event.get('IP地址', '未知')
        } for event in events
            if event.get('目标用户', '') in privileged]


if __name__ == '__main__':
    # 命令行接口保持兼容
    parser = argparse.ArgumentParser(description='安全日志分析工具3.0')
    parser.add_argument('--input', default='results', help='输入目录路径')
    parser.add_argument('--config', default='config.yaml', help='配置文件路径')
    parser.add_argument('--output', default='detections.json', help='输出文件路径')

    args = parser.parse_args()


    def cli_progress(message: str):
        """命令行进度显示"""
        print(f"[进度] {message}")


    analyzer = LogAnalyzer(args.config, progress_callback=cli_progress)
    analyzer.analyze_directory(args.input, args.output)
    print(f"分析结果已保存至: {args.output}")