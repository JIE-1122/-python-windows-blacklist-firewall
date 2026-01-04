import subprocess
import time
import threading  #多线程用于抓包的同时 对其中非法报文的IP进行建立对应的防火墙策略
from typing import Optional, List, Union, Dict, Tuple
from scapy.all import sniff, IP, TCP, UDP, ICMP

class Win10StatefulFirewall:
    def __init__(self):
        self.valid_state_rules = set()  # 记录状态检测规则名称
        self.ip_blacklist_rules = {}    # 黑名单IP与规则名映射
        self.ip_blacklist = []          # 共享黑名单
        self.blacklist_lock = threading.Lock()  # 线程安全锁 确保同一时间只有一个线程能执行该代码块 with self.blacklist_lock:语法将操作self.ip_blacklist的代码块 "锁定"
        # 记录IP的报文统计，按协议类型分别统计
        self.ip_traffic_stats: Dict[str, Dict] = {}  
        # DICT里面的DICT{src_ip: {"count": {"icmp": int, "tcp": int, "udp": int}, "last_time": float, "ports": set}} 
        # count计数器按协议类型区分，last_time记入最后发送数据包时间，ports 记录对方IP发送过数据包的端口
        self.traffic_lock = threading.Lock()  # 流量统计的线程锁
        # 配置参数
        self.FREQ_THRESHOLD = 10   # 时间窗口内超过该次数判定为非法 即超过这个次数就会将对应IP拉入黑名单
        self.FREQ_WINDOW = 10     # 频率检测时间窗口（秒）  每10秒对一个IP发送的数据包数量进行重置
        self.PORT_SCAN_THRESHOLD = 5  # 端口扫描判定阈值（短时间访问不同端口数）
        # 自定义非法端口
        self.ILLEGAL_PORTS = [] 
        # 补充XMAS(NULL扫描无标志)和常见非法标志组合
        self.INVALID_TCP_FLAGS = {'F', 'FR', 'RF', 'FPU', ''}  # 'FPU'=XMAS, ''=NULL
        self._check_firewall_status()   # 检查防火墙状态
        print("状态检测防火墙初始化成功")
    '''
    netsh 是 Windows 系统自带的网络配置命令行工具，用于配置和管理网络相关设置。
    advfirewall 是 netsh 的子命令模块，专门用于管理 Windows 高级防火墙。
    show allprofiles 是该命令的具体操作，为显示所有防火墙配置文件的状态。
    Windows 防火墙通常包含三种配置文件：Domain（域）、Private（私有网络）、Public（公共网络），分别对应不同网络环境下的防火墙策略。
    '''
    # 检查防火墙是否开启
    def _check_firewall_status(self) -> None:
        cmd = ["netsh", "advfirewall", "show", "allprofiles"]
        try:
            result = subprocess.run( #运行外部命令的函数
                cmd,
                stdout=subprocess.PIPE, #捕获命令的标准输出
                stderr=subprocess.PIPE, #捕获命令的标准错误输出
                text=True, #指定输出结果以字符串形式返回
                creationflags=subprocess.CREATE_NO_WINDOW #执行命令时不创建新的控制台窗口
            )
            profiles = ["Domain", "Private", "Public"] 
            off_profiles = []
            for profile in profiles:
                if f"{profile} Profile Settings:" in result.stdout:
                    start_idx = result.stdout.index(f"{profile} Profile Settings:") #寻找配置文件出现的位置
                    end_idx = result.stdout.find("\n\n", start_idx) #定位防火墙配置文件设置内容的结束位置
                    profile_content = result.stdout[start_idx:end_idx] #把配置文件的内容提取出来
                    if "State: Off" in profile_content: #判断防火墙关闭
                        off_profiles.append(profile)
            if off_profiles:
                print(f"高级防火墙配置文件「{','.join(off_profiles)}」已关闭，功能可能失效")
                print("请开启所有防火墙配置文件后重试")
        except Exception as e:
            print(f"检查防火墙状态失败：{e}")
    
    # 执行netsh指令 为后面添加防火墙规则的辅助函数
    def _execute_netsh_cmd(self, cmd: List[str]) -> Tuple[bool, str]:  
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,#如果外部命令执行后返回非零的退出状态码(例如语法错误、权限不足等)，subprocess.run() 会主动抛出 subprocess.CalledProcessError 异常。
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True, "操作成功" if not result.stdout else result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
            return False, f"操作失败：{error_msg}"
        except Exception as e:
            return False, f"命令执行异常：{str(e)}"

    # 添加状态检测规则
    def add_state_rule(self, rule_name: str,
                       dst_port: Optional[int] = None, #参数可以是int类型也可以是 None
                       src_ip: Optional[str] = None,
                       action: str = "allow",#默认允许
                       tcp_states: Union[str, List[str]] = ["NEW", "ESTABLISHED"]) -> Tuple[bool, str]: #默认只允许netsh中的NEW和ESTABLISHED状态
        # 检查系统中是否已存在同名规则
        check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
        check_result = subprocess.run(
            check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "规则名称:" in check_result.stdout:
            return False, f"规则「{rule_name}」已存在系统中，请勿重复添加"

        if rule_name in self.valid_state_rules:
            return False, f"规则「{rule_name}」已存在本地记录，请勿重复添加"

        action = action.lower()
        if action not in ["allow", "block"]:
            return False, "仅支持allow/block"

        # 校验TCP状态
        valid_tcp_states = ["NEW", "ESTABLISHED", "RELATED", "INVALID"]
        tcp_states_list = [tcp_states.upper()] if isinstance(tcp_states, str) else [s.upper() for s in tcp_states] #统一大写
        for state in tcp_states_list:
            if state not in valid_tcp_states:
                return False, f"无效TCP状态「{state}」，仅支持{valid_tcp_states}"

        # 构建防火墙规则命令
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",          # 入站流量
            f"action={action}",
            "protocol=TCP",     # 基于TCP协议
            f"remoteip={src_ip if src_ip else 'any'}", #src_ip无值则默认不限制IP
            f"localport={dst_port if dst_port else 'any'}"
        ]

        # 执行命令并更新规则列表
        success, msg = self._execute_netsh_cmd(cmd)
        if success:
            self.valid_state_rules.add(rule_name)
            if src_ip and action == "block":
                self.ip_blacklist_rules[src_ip] = rule_name
                #被防火墙主动block的IP直接加入黑名单，永久拦截
                with self.blacklist_lock:
                    if src_ip not in self.ip_blacklist:  
                        self.ip_blacklist.append(src_ip)
                        print(f"主动拦截IP {src_ip}，已加入黑名单")
        return success, msg

    # 删除状态检测规则
    def delete_state_rule(self, rule_name: str) -> Tuple[bool, str]:
        if rule_name not in self.valid_state_rules:
            return False, f"规则「{rule_name}」不存在本地记录"

        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
 
        success, msg = self._execute_netsh_cmd(cmd)
        if success:
            self.valid_state_rules.remove(rule_name)
            # 同步删除黑名单映射
            for ip, r_name in list(self.ip_blacklist_rules.items()):
                if r_name == rule_name:
                    del self.ip_blacklist_rules[ip]
        return success, msg

    # 列出所有规则
    def list_state_rules(self) -> Tuple[bool, str]:
        cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            "name=all"
        ]
        return self._execute_netsh_cmd(cmd)

    #动态黑名单(如果有IP发送非法报文则加入黑名单)
    def dynamic_block_blacklist(self, custom_blacklist: Optional[List[str]] = None, interval: int = 3) -> None:
        # 若传入自定义黑名单，更新本地黑名单
        if custom_blacklist:
            with self.blacklist_lock:
                for ip in custom_blacklist:
                    if ip not in self.ip_blacklist:
                        self.ip_blacklist.append(ip)
        
        print(f"\n动态黑名单监控启动")
        print(f"当前监控间隔：{interval}秒")
        print(f"初始黑名单IP：{self.ip_blacklist if self.ip_blacklist else '无'}")
        
        try:
            while True:
                print(f"{time.strftime('%H:%M:%S')}:开始本轮黑名单检查...")
                
                # 加锁读取当前黑名单
                with self.blacklist_lock:
                    current_blacklist = self.ip_blacklist.copy()
                
                for ip in current_blacklist:
                    if ip not in self.ip_blacklist_rules:#如果目标黑名单IP还没建立规则则立马建立
                        rule_name = f"Stateful_Block_{ip.replace('.', '_')}"
                        success, msg = self.add_state_rule(
                            rule_name=rule_name,
                            src_ip=ip,
                            action="block",
                            tcp_states=["NEW", "ESTABLISHED", "RELATED", "INVALID"]
                        )
                        if success:
                            print(f"成功永久拦截IP：{ip}（规则名：{rule_name}）")
                        else:
                            print(f"拦截IP {ip}失败：{msg}")

                # 移除已从黑名单中删除的IP规则
                for ip, rule_name in list(self.ip_blacklist_rules.items()):
                    if ip not in current_blacklist:
                        success, msg = self.delete_state_rule(rule_name)
                        if success:
                            print(f"解除拦截IP：{ip}（规则名：{rule_name}）")
                        else:
                            print(f"解除拦截IP {ip}失败：{msg}")

                print(f"当前活跃拦截IP：{list(self.ip_blacklist_rules.keys()) if self.ip_blacklist_rules else '无'}\n")
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n\n用户终止监控 ")
            print(f"最终活跃拦截IP：{list(self.ip_blacklist_rules.keys()) if self.ip_blacklist_rules else '无'}")
        except Exception as e:
            print(f"\n\n 动态监控异常 ")
            print(f"异常原因：{str(e)}")
            print("正在清理临时拦截规则...")
            for ip, rule_name in self.ip_blacklist_rules.items():
                self.delete_state_rule(rule_name)
            print("临时规则已清理完成")

    # 重置防火墙规则
    def reset_state_firewall(self) -> Tuple[bool, str]:
        for rule_name in list(self.valid_state_rules): #删除所有自定义状态检测规则
            self.delete_state_rule(rule_name)
        self.valid_state_rules.clear() #清空本地规则记录
        self.ip_blacklist_rules.clear() #清空黑名单与规则的映射关系
        with self.blacklist_lock: #清空黑名单列表
            self.ip_blacklist.clear()
        with self.traffic_lock: #清空流量统计数据
            self.ip_traffic_stats.clear()
        return True, "已删除所有自定义状态检测规则"
    
    # 禁止ICMP Ping报文
    def block_ping(self) -> Tuple[bool, str]:
        rule_name = "Block_ICMP_Ping"
        #防止重复
        check_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name={rule_name}"
        ]
        check_result = subprocess.run(
            check_cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "规则名称:" in check_result.stdout:
            return False, f"禁止Ping的规则「{rule_name}」已存在（系统中）"
        
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",          
            "action=block",    
            "protocol=icmpv4:8,any",  # 拦截ICMPv4类型8（Ping请求）
            "remoteip=any"     # 对所有远程IP生效
        ]
        
        success, msg = self._execute_netsh_cmd(cmd)
        if success:
            self.valid_state_rules.add(rule_name)
            print(f"已成功禁止ICMP Ping报文（规则：{rule_name}）")
        return success, msg

    # 拦截非法FIN报文专用规则
    def block_illegal_fin(self) -> Tuple[bool, str]:
        rule_name = "Block_Illegal_FIN_TCP"
        #防止重复
        check_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name={rule_name}"
        ]
        check_result = subprocess.run(
            check_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "规则名称:" in check_result.stdout:
            return False, f"禁止非法FIN的规则「{rule_name}」已存在（系统中）"
        
        # 专门拦截TCP FIN标志位报文（无ACK的非法FIN）
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",          
            "action=block",    
            "protocol=TCP",
            "remoteip=any",
            "localport=any",
            "tcpsettings=Flags:0x01"  # 0x01 = FIN标志位  如果有ACK=1 的话FLAG = 0x11
        ]
        
        success, msg = self._execute_netsh_cmd(cmd)
        if success:
            self.valid_state_rules.add(rule_name)
            print(f"已成功禁止非法FIN报文（规则：{rule_name}）")
        return success, msg

    # 更新IP流量统计 按协议类型分别计数，用bool值来判断这个IP的流量该不该加入黑名单
    def _update_traffic_stats(self, src_ip: str, proto_type: str, dst_port: Optional[int] = None) -> bool:
        # proto_type: 协议类型，可取"icmp"、"tcp"、"udp"
        current_time = time.time() #判断流量是否在 “近期” 范围内
        with self.traffic_lock:
            #首次出现的IP
            if src_ip not in self.ip_traffic_stats:
                init_ports = set() #记录该 IP 访问过的目标端口
                if dst_port is not None: #如果当前数据包包含有效的目标端口 则加入集合
                    init_ports.add(dst_port)
                # 初始化各协议计数器
                self.ip_traffic_stats[src_ip] = {
                    "count": {"icmp": 0, "tcp": 0, "udp": 0},
                    "last_time": current_time, #最后活动时间
                    "ports": init_ports  # 统一初始化为set
                }
                # 对当前协议类型计数加1
                self.ip_traffic_stats[src_ip]["count"][proto_type] = 1
                return False

            # 时间窗口外重置
            if current_time - self.ip_traffic_stats[src_ip]["last_time"] > self.FREQ_WINDOW:
                reset_ports = set()
                #如果对方有目标端口则加上端口
                if dst_port is not None:
                    reset_ports.add(dst_port)
                # 重置各协议计数器
                self.ip_traffic_stats[src_ip] = {
                    "count": {"icmp": 0, "tcp": 0, "udp": 0},
                    "last_time": current_time,
                    "ports": reset_ports
                }
                # 对当前协议类型计数加1
                self.ip_traffic_stats[src_ip]["count"][proto_type] = 1
                return False

            # 累计计数和端口跟踪
            self.ip_traffic_stats[src_ip]["count"][proto_type] += 1 #对应协议类型计数器+1
            if dst_port is not None:
                self.ip_traffic_stats[src_ip]["ports"].add(dst_port) #添加端口

            # 判定条件：超过频率阈值 或 短时间访问多个端口
            port_scan_detected = (dst_port is not None and len(self.ip_traffic_stats[src_ip]["ports"]) > self.PORT_SCAN_THRESHOLD)#判断该源 IP 是否存在 “端口扫描” 行为
            # 检查当前协议类型的计数是否超过阈值
            if self.ip_traffic_stats[src_ip]["count"][proto_type] > self.FREQ_THRESHOLD or port_scan_detected:
                return True
        return False

    #检测所有非法报文并将其对应IP加入黑名单
    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src

            # 先检查是否已在黑名单，避免重复处理
            with self.blacklist_lock:
                if src_ip in self.ip_blacklist:
                    return

            # 检测ICMP报文（Ping请求，类型8）
            if ICMP in packet:
                icmp_type = packet[ICMP].type
                if icmp_type == 8:  # ICMP类型8 = 回送请求（Ping）
                    # 频率检测，只统计ICMP类型报文
                    if self._update_traffic_stats(src_ip, "icmp"):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 发送大量ICMP Ping报文，已加入黑名单")
                    return

            # 检测非法TCP报文（含各类扫描行为）
            if TCP in packet:
                tcp_flags = packet[TCP].flags #记录对应TCP的标志位FLAG
                dst_port = packet[TCP].dport #获取 TCP 报文的目标端口号

                # 检测XMAS扫描(FPU标志)和NULL扫描(无标志)
                if tcp_flags in ['FPU', '']:#'FPU'：对应XMAS 扫描  ''（空字符串）：对应NULL 扫描
                    #先进行流量分析，因为可能是误操作而导致对方进入黑名单，如果_update_traffic_stats放回TRUE则说明是恶意扫描
                    if self._update_traffic_stats(src_ip, "tcp", dst_port): 
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        scan_type = "XMAS" if tcp_flags == 'FPU' else "NULL"
                        print(f"检测到 {src_ip} 进行TCP {scan_type}扫描，已加入黑名单")
                    return

                # 检测非法FIN报文（含F标志且无A标志）
                if 'F' in tcp_flags and 'A' not in tcp_flags:  # 无ACK的FIN = 非法
                    #先进行流量分析，因为可能是误操作而导致对方进入黑名单，如果_update_traffic_stats放回TRUE则说明是恶意扫描
                    if self._update_traffic_stats(src_ip, "tcp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 发送非法FIN报文（无ACK），已加入黑名单")
                    return

                # 检测其他无效TCP标志（FR/RF等）
                if tcp_flags in self.INVALID_TCP_FLAGS:
                    #先进行流量分析，因为可能是误操作而导致对方进入黑名单，如果_update_traffic_stats放回TRUE则说明是恶意扫描
                    if self._update_traffic_stats(src_ip, "tcp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 发送非法TCP报文（标志位：{tcp_flags}），已加入黑名单")
                    return

                #检测访问非法端口的TCP报文
                if dst_port in self.ILLEGAL_PORTS:
                    #先进行流量分析，因为可能是误操作而导致对方进入黑名单，如果_update_traffic_stats放回TRUE则说明是恶意扫描
                    if self._update_traffic_stats(src_ip, "tcp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 访问非法端口 {dst_port}，已加入黑名单")
                    return

                #检测SYN扫描
                if tcp_flags == 'S' and 'A' not in tcp_flags:
                    if self._update_traffic_stats(src_ip, "tcp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 进行TCP SYN扫描，已加入黑名单")
                    return

                # 检测TCP connect扫描(完整三次握手)
                if tcp_flags == 'SA':  # SYN-ACK回应，表明有连接尝试
                    #短时间内来自同一源 IP 的大量 SYN-ACK 报文，可作为 connect 扫描的间接特征
                    if self._update_traffic_stats(src_ip, "tcp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 进行TCP connect扫描，已加入黑名单")
                    return

            #检测非法UDP报文（访问非法端口）
            if UDP in packet:
                dst_port = packet[UDP].dport
                if dst_port in self.ILLEGAL_PORTS:
                    if self._update_traffic_stats(src_ip, "udp", dst_port):
                        with self.blacklist_lock:
                            if src_ip not in self.ip_blacklist:  # 去重
                                self.ip_blacklist.append(src_ip)
                        print(f"检测到 {src_ip} 发送UDP报文访问非法端口 {dst_port}，已加入黑名单")
                    return

    # 启动Scapy抓包线程（补充依赖提示）
    def start_sniffing(self, interface=None):
        print(f"\n网络流量监控")
        print(f"监控接口：{interface if interface else '默认接口'}")
        print("开始检测所有非法报文（ICMP/各类TCP扫描等）...")
        try:
            #主程序退出时自动结束
            #创建进程 用于抓包
            sniff_thread = threading.Thread(
                target=lambda: sniff(iface=interface, prn=self.packet_callback, store=0),
                daemon=True
            )
            #iface=interface：指定抓包接口
            #prn=self.packet_callback：设置数据包处理的回调函数 用于对抓包的数据进行处理 这里对应的是对非法报文对应IP进入黑名单
            #store=0：不缓存捕获的数据包
            #daemon=True：将线程设为守护线程，意味着当主程序退出时，该抓包线程会自动终止
            sniff_thread.start()
            return sniff_thread
        except Exception as e:
            error_msg = f"抓包启动失败：{e}"
            print(error_msg)
            return None

# 主程序
if  __name__ == "__main__":
    # 初始化状态检测防火墙
    state_firewall = Win10StatefulFirewall()

    # 优先放行已建立的TCP连接
    success, msg = state_firewall.add_state_rule(
        rule_name="Allow_Established_TCP",
        action="allow",
        tcp_states="ESTABLISHED"
    )
    print(f"放行TCP已建立连接：{'成功' if success else '失败'}，信息：{msg}")

    # 禁止Ping报文
    print("禁止Ping报文 ")
    success, msg = state_firewall.block_ping()
    print(f"禁止Ping报文：{'成功' if success else '失败'}，信息：{msg}")

    # 仅允许80端口的TCP新连接
    success, msg = state_firewall.add_state_rule(
        rule_name="Allow_80_TCP_New",
        dst_port=80,
        action="allow",
        tcp_states="NEW"
    )
    print(f"允许80端口TCP新连接：{'成功' if success else '失败'}，信息：{msg}")

    # 拦截所有无效TCP连接
    success, msg = state_firewall.add_state_rule(
        rule_name="Block_Invalid_TCP",
        action="block",
        tcp_states="INVALID"
    )
    print(f"拦截TCP无效连接：{'成功' if success else '失败'}，信息：{msg}")

    # 查看状态检测规则（验证规则生效）
    print("查看所有状态检测规则")
    success, rules = state_firewall.list_state_rules()

    if success:
        print("状态检测规则列表（前25行）：")
        for line in [l for l in rules.split('\n') if l.strip()][:25]:
            print(line)
    else:
        print(f"查看规则失败：{rules}")

    # 启动抓包线程
    sniff_thread = state_firewall.start_sniffing()
    if sniff_thread:
        print("抓包线程启动成功")
    else:
        print("抓包线程启动失败")

    # 动态黑名单 + 状态检测
    print("\n启动动态黑名单监控")
    ip_blacklist = []
    # 传入自定义黑名单和监控间隔
    state_firewall.dynamic_block_blacklist(custom_blacklist=ip_blacklist, interval=5)

    # 重置防火墙（若用户终止监控，会执行到此处）
    success, msg = state_firewall.reset_state_firewall()
    print(f"\n重置状态检测防火墙：{'成功' if success else '失败'}，信息：{msg}")