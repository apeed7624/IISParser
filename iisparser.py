import os
import argparse
import re


def read_iis_logs(directory_path, default=False, ip_list_path=None, parsers=None, output_file=None):
    # 如果提供了 IP 地址列表的檔案路徑，將其讀取為列表
    known_ips = set()
    if ip_list_path:
        with open(ip_list_path, 'r') as ip_file:
            known_ips.update(line.strip() for line in ip_file)

    # 列出指定路徑下的所有檔案
    files = os.listdir(directory_path)

    # 過濾出所有的 IIS log 檔案
    iis_logs = [file for file in files if file.endswith(".log")]

    # 逐一處理每個 IIS log 檔案
    for log_file in iis_logs:
        file_path = os.path.join(directory_path, log_file)

        # 資料處理邏輯
        process_iis_log(file_path, known_ips, default, parsers, output_file)


def process_iis_log(file_path, known_ips=None, default=False, parsers=None, output_file=None):
    # 資料處理邏輯

    with open(file_path, 'rb') as file:
        # 在這裡加入檔案內容的處理邏輯
        content = file.readlines()

        # 初始化用於存放匹配到的 IP 的列表
        matching_ips = {}

        # 初始化用於存放匹配到特定字串的列表
        matching_parser_lines = {parser: [] for parser in (parsers or [])}

        # 初始化用於存放 POST + 200 的列表
        post_records = []

        # 初始化用於存放特定字串的列表
        command_records = []

        # 逐行檢查是否為 POST 請求且狀態碼為 200，或包含特定字串，或匹配到已知 IP
        for line_bytes in content:
            # 解碼字節序列，這裡使用 'utf-8' 編碼，根據實際情況更改
            line = line_bytes.decode('utf-8', errors='replace')

            # 使用正則表達式找出 log 中的 IP 地址
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                ip = ip_match.group()
                if known_ips and ip in known_ips:
                    matching_ips[ip] = line.strip()

            # 檢查是否為 POST + 200
            if "POST" in line and " 200 " in line:
                post_records.append(line)

            # 檢查是否包含特定字串
            for parser in (parsers or []):
                if parser in line:
                    matching_parser_lines[parser].append(line)

            # 檢查是否包含特定字串（保留原有功能）
            if any(keyword in line for keyword in ["xp_cmdshell", "cmd.exe", "whoami", "net use", "sqlcmd"]):
                command_records.append(line)

        # 如果有匹配到的 IP，將其寫入 attack.txt
        if matching_ips and not default and not output_file:
            with open('attack.txt', 'a') as attack_file:
                for ip, line in matching_ips.items():
                    attack_file.write(f"Matching IP {ip} in {file_path}: {line}\n")
                attack_file.write('\n')

        # 如果有匹配到的 POST + 200，將其寫入 post.txt
        if post_records and not parsers and not output_file and (default or not parsers):
            with open('post.txt', 'a') as post_file:
                post_file.write(f"POST + 200 records in {file_path}:\n")
                post_file.writelines(post_records)
                post_file.write('\n\n')

        # 如果有匹配到的特定字串（保留原有功能），將整行寫入 command.txt
        if command_records and not parsers and not output_file and (default or not parsers):
            with open('command.txt', 'a', encoding='utf-8') as command_file:
                command_file.write(f"Command matches in {file_path}:\n")
                command_file.writelines(command_records)
                command_file.write('\n\n')

        # 如果有匹配到的特定字串，將整行寫入指定文件
        for parser, lines in matching_parser_lines.items():
            if lines and output_file and not default:
                with open(output_file, 'a', encoding='utf-8') as parser_output_file:
                    parser_output_file.write(f"{parser} matches in {file_path}:\n")
                    parser_output_file.writelines(lines)
                    parser_output_file.write('\n\n')

# 建立解析器
parser = argparse.ArgumentParser(description='Parse IIS logs.')
parser.add_argument('directory_path', type=str, help='Path to the directory containing IIS logs')
parser.add_argument('-default', action='store_true', help='Run default functionality')
parser.add_argument('-ip', '--ip-list', type=str, help='Path to a file containing a list of known IPs')
parser.add_argument('-parsers', nargs='+', help='List of parsers to match in logs')
parser.add_argument('-output', type=str, help='Path to the output file for matching parser strings')

# 解析命令列參數
args = parser.parse_args()

# 判斷是否指定了 -default 參數，只執行預設功能
if args.default:
    read_iis_logs(args.directory_path, default=True, ip_list_path=args.ip_list, parsers=args.parsers)
elif args.ip_list:
    # 如果指定了 -ip 參數，執行比對 IP 的功能
    read_iis_logs(args.directory_path, ip_list_path=args.ip_list, output_file=args.output)
elif args.parsers:
    # 如果指定了 -parsers 參數，執行比對特定字串的功能
    read_iis_logs(args.directory_path, parsers=args.parsers, output_file=args.output)
else:
    print("Invalid command. Please provide valid parameters.")
