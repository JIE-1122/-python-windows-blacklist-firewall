from scapy.all import IP, TCP, send
import time

# 目标IP
target_ip = "192.168.9.128"
# 发送数量（超过防火墙的FREQ_THRESHOLD=10）
send_count = 20
# 发送间隔（控制在10秒内完成，确保落在时间窗口内）
interval = 0.5  # 每0.5秒发一个，20个共10秒

# 构造非法FIN报文（仅含F标志，无A标志）
ip = IP(dst=target_ip)
tcp = TCP(sport=59247, dport=80, flags='F')  # 关键：flags='F'（无ACK）

print(f"开始发送{send_count}个非法FIN报文（间隔{interval}秒）...")
for i in range(send_count):
    send(ip/tcp, verbose=0)  # verbose=0关闭冗余输出
    print(f"已发送第{i+1}/{send_count}个")
    time.sleep(interval)

print("发送完成")