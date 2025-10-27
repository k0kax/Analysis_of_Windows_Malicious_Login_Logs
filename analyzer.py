import argparse
import csv
import os
from datetime import datetime,timezone,timedelta
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

'''
增强版EVTX日志分析工具
更新说明：
- 完整实现所有事件类型解析
- 优化时间处理精度
- 增强字段验证
文件名:analyzer.py
'''

# 完整事件类型映射
EVENT_TYPES = {
    1102: "日志清除事件",
    4624: "登录成功",
    4625: "登录失败",
    4627: "用户账户注销",
    4634: "账户注销",
    4648: "使用显式凭证登录",
    4672: "特殊权限分配",
    4675: "SID过滤",
    4697: "服务安装",
    4698: "计划任务创建",
    4702: "安全策略更新",
    4703: "令牌权限调整",
    4719: "系统审计策略修改",
    4720: "用户账户创建",
    4726: "用户账户删除",
    4732: "安全组添加成员",
    4740: "锁定账户",
    4768: "Kerberos身份验证(TGT请求)",
    4769: "Kerberos服务票证请求",
    4776: "NTLM身份验证",
    5140: "网络共享访问",
    5145: "网络共享对象访问",
}

# 完整登录类型映射
LOGON_TYPES = {
    0: "系统启动",
    2: "交互式登录",
    3: "网络登录",
    4: "批处理登录",
    5: "服务登录",
    7: "解锁登录",
    8: "网络明文登录",
    9: "新凭据登录",
    10: "远程交互式登录",
    11: "缓存交互式登录",
    12: "远程桌面登录",
}

# 完整子状态码映射
SUBSTATUS_MAPPING = {
    "0x0": "成功",
    "0xC0000064": "用户名不存在",
    "0xC000006a": "用户名正确，密码错误",
    "0xC000006e": "密码不满足复杂性要求",
    "0xC0000070": "账户限制",
    "0xC0000234": "用户账户被锁定",
    "0xC0000072": "账户已过期",
    "0xC000006f": "用户不在允许的登录时间段",
    "0xC000006d": "登录失败: 用户名或密码不正确",
    "0xC0000133": "时钟不同步",
    "0xC0000224": "需要更改密码",
}

def parse_xml_event(xml_string):
    """完整XML事件解析（含UTC转北京时间）"""
    try:
        root = ET.fromstring(xml_string)
        namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # ===== 1. 解析系统信息 =====
        system = root.find('.//ns:System', namespaces)
        if system is None:
            return None, {}, None

        # 事件ID处理
        event_id_node = system.find('.//ns:EventID', namespaces)
        event_id = int(event_id_node.text) if event_id_node is not None else None

        # ===== 2. 时间处理核心逻辑 =====
        timestamp = None
        time_created = system.find('.//ns:TimeCreated', namespaces)
        if time_created is not None:
            sys_time = time_created.get('SystemTime', '')

            # 尝试解析带毫秒格式
            try:
                if sys_time.endswith('Z'):
                    # 处理ISO 8601格式（带Z时区标识）
                    utc_time = datetime.strptime(sys_time, '%Y-%m-%dT%H:%M:%S.%fZ')
                else:
                    # 处理不带Z的情况（假设为UTC时间）
                    utc_time = datetime.fromisoformat(sys_time.replace('Z', '+00:00'))

                # 添加UTC时区信息
                utc_time = utc_time.replace(tzinfo=timezone.utc)
                # 转换为UTC+8北京时间
                beijing_time = utc_time.astimezone(timezone(timedelta(hours=8)))
                timestamp = beijing_time

            except ValueError:
                # 处理不带毫秒的情况
                try:
                    utc_time = datetime.strptime(sys_time.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    utc_time = utc_time.replace(tzinfo=timezone.utc)
                    beijing_time = utc_time.astimezone(timezone(timedelta(hours=8)))
                    timestamp = beijing_time
                except Exception as e:
                    print(f"[时间解析警告] 非常规时间格式: {sys_time} ({str(e)})")

        # ===== 3. 解析事件数据 =====
        event_data = {}
        data_nodes = root.findall('.//ns:EventData/ns:Data', namespaces)
        for node in data_nodes:
            name = node.get('Name')
            value = node.text.strip() if node.text else ''
            # 对常见关键字段做空值处理
            if name in ['TargetUserName', 'IpAddress', 'LogonType']:
                value = value if value not in ('-', '') else '未知'
            event_data[name] = value

        # ===== 4. 返回结构化数据 =====
        return event_id, event_data, timestamp

    except ET.ParseError as e:
        print(f"[XML解析错误] 事件记录损坏: {str(e)}")
        return None, {}, None
    except Exception as e:
        print(f"[解析异常] 未处理错误: {str(e)}")
        return None, {}, None

def process_events(evtx_path, output_dir='result', progress_callback=None, report_interval=10):
    """完整事件处理流程"""
    os.makedirs(output_dir, exist_ok=True)
    results = {eid: [] for eid in EVENT_TYPES.keys()}

    try:
        # 初始化进度报告
        if progress_callback:
            progress_callback({
                'stage': 'init',
                'message': f"正在准备解析 {os.path.basename(evtx_path)}"
            })

        # 获取总记录数
        with Evtx(evtx_path) as log:
            total = sum(1 for _ in log.records())

        if progress_callback:
            progress_callback({
                'stage': 'init',
                'total': total,
                'message': f"共发现 {total} 条日志记录"
            })

        # 实际解析处理
        with Evtx(evtx_path) as log:
            processed = 0
            last_report = 0

            for record in log.records():
                event_id, data, timestamp = parse_xml_event(record.xml())
                processed += 1

                # 进度报告
                if progress_callback and (processed % report_interval == 0 or processed == total):
                    progress_callback({
                        'stage': 'processing',
                        'current': processed,
                        'total': total,
                        'message': f"解析进度: {processed}/{total} ({processed / total * 100:.1f}%)"
                    })

                if event_id not in EVENT_TYPES:
                    continue

                # 通用字段
                entry = {
                    '时间戳': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f') if timestamp else '未知',
                    '事件ID': event_id,
                    '事件类型': EVENT_TYPES.get(event_id, '未知事件'),
                }

                # 各事件类型特殊处理
                if event_id == 1102:  # 日志清除
                    entry.update({
                        '操作账户': data.get('SubjectUserName', ''),
                        '日志类型': data.get('LogType', ''),
                        '清除时间': data.get('TimeWritten', '')
                    })
                elif event_id == 4624:  # 登录成功
                    entry.update({
                        '目标用户': data.get('TargetUserName', ''),
                        '目标域': data.get('TargetDomainName', ''),
                        '登录类型': LOGON_TYPES.get(int(data.get('LogonType', 0)), '未知'),
                        'IP地址': data.get('IpAddress', ''),
                        '进程名称': data.get('ProcessName', ''),
                        '特权令牌': data.get('TokenElevationType', ''),
                        '虚拟账户': '是' if data.get('TargetUserSid', '').startswith('S-1-5-96') else '否',
                        '登录GUID': data.get('LogonGuid', '')
                    })
                elif event_id == 4625:  # 登录失败
                    entry.update({
                        '状态码': data.get('Status', ''),
                        '目标用户': data.get('TargetUserName', ''),
                        'IP地址': data.get('IpAddress', ''),
                        '子状态码': SUBSTATUS_MAPPING.get(data.get('SubStatus', ''), data.get('SubStatus', '')),
                        '登录类型': LOGON_TYPES.get(int(data.get('LogonType', 0)), '未知'),
                        '失败原因': data.get('FailureReason', ''),
                        '认证包': data.get('AuthenticationPackageName', '')
                    })
                elif event_id == 4627:  # 用户注销
                    entry.update({
                        '用户名称': data.get('TargetUserName', ''),
                        '登录ID': data.get('TargetLogonId', ''),
                        '注销类型': data.get('LogonType', '')
                    })
                elif event_id == 4634:  # 账户注销
                    entry.update({
                        '目标用户': data.get('TargetUserName', ''),
                        '目标域': data.get('TargetDomainName', ''),
                        '登录ID': data.get('TargetLogonId', ''),
                        '会话类型': data.get('SessionType', '')
                    })
                elif event_id == 4648:  # 显式凭证登录
                    entry.update({
                        '账户名': data.get('AccountName', ''),
                        '登录进程': data.get('LogonProcessName', ''),
                        '源网络地址': data.get('SourceNetworkAddress', ''),
                        '目标进程': data.get('TargetProcessName', ''),
                        '凭证类型': data.get('CredentialType', '')
                    })
                elif event_id == 4672:  # 特殊权限分配
                    entry.update({
                        '特权列表': data.get('PrivilegeList', ''),
                        '账户名': data.get('AccountName', ''),
                        '账户域': data.get('AccountDomain', ''),
                        '登录ID': data.get('LogonId', ''),
                        '安全ID': data.get('SecurityId', '')
                    })
                elif event_id == 4675:  # SID过滤
                    entry.update({
                        '源SID': data.get('SourceSid', ''),
                        '目标SID': data.get('TargetSid', ''),
                        '源账户': data.get('SourceAccountName', ''),
                        '目标账户': data.get('TargetAccountName', ''),
                        '过滤结果': data.get('FilterResult', '')
                    })
                elif event_id == 4697:  # 服务安装
                    entry.update({
                        '服务名称': data.get('ServiceName', ''),
                        '服务类型': data.get('ServiceType', ''),
                        '启动类型': data.get('StartType', ''),
                        '账户权限': data.get('AccountRight', '')
                    })
                elif event_id == 4698:  # 计划任务
                    entry.update({
                        '任务名称': data.get('TaskName', ''),
                        '创建者': data.get('CreatorSubjectName', ''),
                        '操作类型': data.get('ActionType', ''),
                        '触发条件': data.get('TriggerType', ''),
                        '执行账户': data.get('RunLevel', '')
                    })
                elif event_id == 4702:  # 安全策略更新
                    entry.update({
                        '策略类型': data.get('PolicyType', ''),
                        '修改账户': data.get('SubjectUserName', ''),
                        '策略内容': data.get('PolicyData', ''),
                        '策略GUID': data.get('PolicyId', '')
                    })
                elif event_id == 4703:  # 令牌权限调整
                    entry.update({
                        '调整权限': data.get('AdjustedPrivileges', ''),
                        '进程ID': data.get('ProcessId', ''),
                        '进程名称': data.get('ProcessName', ''),
                        '目标用户': data.get('TargetUserName', '')
                    })
                elif event_id == 4719:  # 审计策略修改
                    entry.update({
                        '策略变更类型': data.get('PolicyChangeType', ''),
                        '策略名': data.get('PolicyName', ''),
                        '旧值': data.get('OldValue', ''),
                        '新值': data.get('NewValue', ''),
                        '修改账户': data.get('SubjectUserName', '')
                    })
                elif event_id == 4720:  # 用户创建
                    entry.update({
                        '新建用户': data.get('TargetUserName', ''),
                        '操作账户': data.get('SubjectUserName', ''),
                        '用户SID': data.get('TargetSid', ''),
                        '用户组': data.get('MemberName', '')
                    })
                elif event_id == 4726:  # 用户删除
                    entry.update({
                        '删除用户': data.get('TargetUserName', ''),
                        '操作账户': data.get('SubjectUserName', ''),
                        '用户SID': data.get('TargetSid', ''),
                        '执行主机': data.get('SubjectWorkstation', '')
                    })
                elif event_id == 4732:  # 组添加成员
                    entry.update({
                        '目标组名': data.get('TargetUserName', ''),
                        '新增成员': data.get('MemberName', ''),
                        '成员类型': data.get('MemberSidType', ''),
                        '操作账户': data.get('SubjectUserName', ''),
                        '组作用域': data.get('GroupScope', '')
                    })
                elif event_id == 4740:  # 账户锁定
                    entry.update({
                        '锁定账户': data.get('TargetUserName', ''),
                        '锁定原因': data.get('Status', ''),
                        '锁定时间': data.get('CallerProcessStartTime', ''),
                        '执行主机': data.get('WorkstationName', ''),
                        '锁定次数': data.get('FailureCount', '')
                    })
                elif event_id == 4768:  # Kerberos TGT
                    entry.update({
                        '客户端名称': data.get('ClientName', ''),
                        '服务名称': data.get('ServiceName', ''),
                        '票证选项': data.get('TicketOptions', ''),
                        '错误代码': data.get('Status', '')
                    })
                elif event_id == 4769:  # Kerberos ST
                    entry.update({
                        '服务名称': data.get('ServiceName', ''),
                        '客户端地址': data.get('ClientAddress', ''),
                        '票证加密类型': data.get('TicketEncryptionType', ''),
                        '失败代码': data.get('FailureCode', ''),
                        '服务SID': data.get('ServiceSid', '')
                    })
                elif event_id == 4776:  # NTLM验证
                    entry.update({
                        '认证账户': data.get('AccountName', ''),
                        '客户端工作站': data.get('WorkstationName', ''),
                        '错误代码': data.get('ErrorCode', ''),
                        '认证包': data.get('PackageName', ''),
                        '密钥长度': data.get('KeyLength', '')
                    })
                elif event_id == 5140:  # 共享访问
                    entry.update({
                        '共享路径': data.get('ShareName', ''),
                        '访问账户': data.get('SubjectUserName', ''),
                        '源地址': data.get('SourceAddress', ''),
                        '访问权限': data.get('Accesses', ''),
                        '相对目标': data.get('RelativeTargetName', '')
                    })
                elif event_id == 5145:  # 共享对象访问
                    entry.update({
                        '共享路径': data.get('ShareName', ''),
                        '访问账户': data.get('SubjectUserName', ''),
                        '源地址': data.get('SourceAddress', ''),
                        '访问权限': data.get('Accesses', ''),
                        '文件路径': data.get('RelativeTargetName', '')
                    })

                results[event_id].append(entry)

        # 生成CSV文件
        if progress_callback:
            progress_callback({
                'stage': 'exporting',
                'message': "开始生成分析报告",
                'total': len(results)
            })

        generated_files = []
        for idx, (event_id, records) in enumerate(results.items()):
            if not records:
                continue

            filename = f"{event_id}.csv"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)

            generated_files.append(filepath)

            if progress_callback:
                progress_callback({
                    'stage': 'exporting',
                    'current': idx + 1,
                    'total': len(results),
                    'message': f"已生成 {filename}"
                })

        return generated_files

    except Exception as e:
        if progress_callback:
            progress_callback({
                'stage': 'error',
                'message': f"处理过程中断: {str(e)}"
            })
        raise


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='EVTX日志分析工具 - 3.0',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''使用示例:
  完整分析: python analyzer3.py Security1.evtx
  指定输出: python analyzer3.py Security1.evtx -o ./report
  调试模式: python analyzer3.py Security1.evtx -r 1'''
    )
    parser.add_argument('evtx_path', help='EVTX文件路径')
    parser.add_argument('-o', '--output', default='results',
                        help='输出目录 (默认: ./results)')
    parser.add_argument('-r', '--report-interval', type=int, default=10,
                        help='进度报告间隔 (默认: 10条记录)')

    args = parser.parse_args()

    def console_progress(data):
        """控制台进度显示"""
        if data.get('stage') == 'init':
            print(f"\n[{datetime.now().isoformat()}] {data['message']}")
        elif data.get('stage') == 'processing':
            print(f"\r处理进度: {data['current']}/{data['total']} | {data['current'] / data['total'] * 100:.1f}%",
                  end='')
        elif data.get('stage') == 'exporting':
            print(f"\n生成文件: {data['message']} ({data['current']}/{data['total']})")
        elif data.get('stage') == 'error':
            print(f"\n[错误] {data['message']}")

    try:
        start_time = datetime.now()
        print(f"分析开始于: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        process_events(
            args.evtx_path,
            output_dir=args.output,
            progress_callback=console_progress,
            report_interval=args.report_interval
        )

        duration = datetime.now() - start_time
        print(f"\n分析完成! 总耗时: {duration.total_seconds():.2f}秒")
        print(f"结果目录: {os.path.abspath(args.output)}")

    except FileNotFoundError:
        print(f"错误: 文件不存在 - {args.evtx_path}")
    except PermissionError:
        print(f"错误: 没有文件访问权限 - {args.evtx_path}")
    except Exception as e:
        print(f"\n发生未处理异常: {str(e)}")


if __name__ == '__main__':
    main()