import re
import os
import csv
import logging
from datetime import datetime

SERIAL_NUMBER_LIST = []

TEXT_FILE_EXTENSION = [".txt", ".log"]
OUTPUT_FOLDER = "output"
LOG_FILE_NAME = f"{OUTPUT_FOLDER}/switch_capture.log"
NXOS_SWITCH_FILE_NAME = f"{OUTPUT_FOLDER}/2_NXOS_report.txt"
IOS_SWITCH_FILE_NAME = f"{OUTPUT_FOLDER}/1_IOS_report.txt"
NXOS_SWITCH_CSV_FILE_NAME = f"{OUTPUT_FOLDER}/2_NXOS_report.csv"
IOS_SWITCH_CSV_FILE_NAME = f"{OUTPUT_FOLDER}/1_IOS_report.csv"
CISCO_WLC_FILE_NAME = f"{OUTPUT_FOLDER}/3_WLC_report.txt"
CISCO_WLC_AP_FILE_NAME = f"{OUTPUT_FOLDER}/ALL_WLC_AP_report.csv"

EXPORT_CSV_DICT = {
    "File Name": "N/A",
    "IP Address": "N/A",
    "Hostname": "N/A",
    "Model Number": "N/A",
    "Serial Number": "N/A",
    "Uptime": "N/A",
    "Software Version": "N/A",
    "Boot Mode": "N/A",
    "Total Memory": "N/A",
    "Used Memory": "N/A",
    "Memory Percent Used": "N/A",
    "Total Disk": "N/A",
    "Used Disk": "N/A",
    "Disk Percent Used": "N/A",
    "5-minute CPU Average": "N/A",
    "1-minute CPU Average": "N/A",
    "5-second CPU Average": "N/A",
    "Cisco Timestamp": "N/A",
    "Putty Timestamp": "N/A",
    "NTP Status": "N/A",
    "Inventory Information": "N/A"
}

WLC_INFO_DICT = {
    "File Name": "N/A",
    "IP Address": "N/A",
    "Hostname": "N/A",
    "Model Number": "N/A",
    "Serial Number": "N/A",
    "Uptime": "N/A",
    "Software Version": "N/A",
    "Total Memory": "N/A",
    "Used Memory": "N/A",
    "Memory Percent Used": "N/A",
    "Total Disk": "N/A",
    "Used Disk": "N/A",
    "Disk Percent Used": "N/A",
    "CPU Average": "N/A",
    "Cisco Timestamp": "N/A",
    "Putty Timestamp": "N/A",
}

AP_INFO_DICT = {
    "Model": "N/A",
    "IP Address": "N/A",
    "Serial Number": "N/A",
    "Uptime": "N/A",
    "AP Name": "N/A",
}

class Nexus_Switch:
    def __init__(self, data):
        # All regular expressions here
        show_tech_match = re.search(r"#\s+sh(?:ow)? tech", data)
        putty_timestamp_pattern = re.compile(r"(?:PuTTY|MobaXterm) log (\d{4}\.\d{2}.\d{2} \d{2}:\d{2}:\d{2})")
        running_config_pattern = re.compile(r"\#\sshow run(.+?)\#", re.DOTALL)
        show_version_pattern = re.compile(r"\#\sshow ver(.+?)\#", re.DOTALL)
        show_sysresources_pattern = re.compile(r"#\s?sh(?:ow)?\s?sys(?:tem)?\sres(?:ource|ources)?(.+?)\#", re.DOTALL)
        show_processcpu_pattern = re.compile(r"\#\sshow process cpu\s\n+PID(.+?)\#", re.DOTALL)
        show_inventory_pattern = re.compile(r"\#\sshow inv(.+?)\#", re.DOTALL)
        directory_pattern = re.compile(r"\#\sdir(.+?)\#", re.DOTALL)

        logging.info(f"NXOS Switch : {file} (show tech)" if show_tech_match else f"NXOS Switch : {file}")
        
        running_config = self.extract_info(running_config_pattern, data, "No `show running config` command")
        show_processcpu = self.extract_info(show_processcpu_pattern, data, "No `show process cpu` command")
        show_version = self.extract_info(show_version_pattern, data, "No `show version` command")
        show_sysresources = self.extract_info(show_sysresources_pattern, data, "No `show system resources` command")
        putty_timestamp = self.extract_info(putty_timestamp_pattern, data, "No `PuTTY log timestamp` in file")
        show_inventory = self.extract_info(show_inventory_pattern, data, "No `show inventory` command")
        dir_info = self.extract_info(directory_pattern, data, "No `dir` command")

        hostname = self.get_hostname(running_config)
        ip_address_info, ip_address = self.extract_ip_address_info(running_config, hostname)
        model_number, serial_number, uptime, software_version = self.extract_version_info(show_version)
        
        total_memory, used_memory = self.extract_memory_info(show_sysresources)
        total_memory_mb = round(total_memory/1024, 2) if total_memory != "N/A" else "N/A"
        used_memory_mb = round(used_memory/1024, 2) if used_memory != "N/A" else "N/A"
        memory_usage_percent = "N/A" if total_memory == "N/A" else f"{round(used_memory/total_memory*100, 2)}%"

        total_disk, used_disk = self.extract_disk_info(dir_info)
        total_disk_mb = round(total_disk/(1024**2), 2) if total_disk != "N/A" else "N/A"
        used_disk_mb = round(used_disk/(1024**2), 2) if used_disk != "N/A" else "N/A"
        disk_usage_percent = "N/A" if total_disk == "N/A" else f"{round(used_disk/total_disk*100, 2)}%"

        cisco_datetime, putty_datetime = self.compare_clocks(running_config, putty_timestamp)
        cpu_5min, cpu_1min, cpu_5sec, cpu_utlization = self.extract_cpu_info(show_processcpu)
        inventory_info, inventory_dict_list = self.extract_inventory_info(show_inventory)
        
        
        report_format = f"""=~=~=~=~=~=~=~=~=~=~=~==~=~=~=~=~=~=~=~=~=~=~=
Report for File : {file}
~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=
IP Address       : {ip_address_info}
Hostname         : {hostname}
Model Number     : {model_number}
Serial Number    : {serial_number}
Uptime           : {uptime}
Software Version : {software_version}

Memory Usage:
Total Memory : {total_memory} K, {total_memory_mb} MiB
Used Memory  : {used_memory} K, {used_memory_mb} MiB
Percent Used : {memory_usage_percent}

Disk Usage:
Total Disk      : {total_disk} bytes, {total_disk_mb} MiB
Used Disk       : {used_disk} bytes, {used_disk_mb} MiB
Percent Used    : {disk_usage_percent}

CPU Usage:
5-minute Average: {cpu_5min}
1-minute Average: {cpu_1min}
5-second Average: {cpu_5sec}
Cpu Utlization  : {cpu_utlization}%

Timestamps:
Cisco Timestamp: {cisco_datetime}
Putty Timestamp: {putty_datetime}

Inventory Information:
{inventory_info}
---

"""
        self.export_report(report_format)

        CSV_DICT = EXPORT_CSV_DICT.copy()
        CSV_DICT["File Name"] = file
        CSV_DICT["Hostname"] = hostname
        CSV_DICT["Model Number"] = model_number
        CSV_DICT["Serial Number"] = serial_number
        CSV_DICT["IP Address"] = ip_address
        CSV_DICT["Uptime"] = uptime
        CSV_DICT["Software Version"] = software_version
        CSV_DICT["Total Memory"] = total_memory
        CSV_DICT["Used Memory"] = used_memory
        CSV_DICT["Memory Percent Used"] = memory_usage_percent
        CSV_DICT["Total Disk"] = total_disk
        CSV_DICT["Used Disk"] = used_disk
        CSV_DICT["Disk Percent Used"] = disk_usage_percent
        CSV_DICT["5-minute CPU Average"] = cpu_5min if cpu_utlization != "N/A" else cpu_utlization
        CSV_DICT["1-minute CPU Average"] = cpu_1min
        CSV_DICT["5-second CPU Average"] = cpu_5sec
        CSV_DICT["Cisco Timestamp"] = cisco_datetime
        CSV_DICT["Putty Timestamp"] = putty_datetime
        CSV_DICT["Inventory Information"] = inventory_dict_list
        self.export_dict_to_csv(CSV_DICT)

    def get_hostname(self, running_config):
        if running_config is None: return "N/A"

        hostname_pattern = re.compile(r"(?:hostname|switchname)\s+(.+?)\n")

        try:
            hostname = hostname_pattern.search(running_config).group(1)
        except AttributeError:
            hostname = "N/A"
            logging.warning(f"MISSING HOSTNAME IN CONFIG")
        
        return hostname
    
    def compare_clocks(self, running_config, putty_timestamp):
        if putty_timestamp is None or running_config is None: return "N/A", "N/A"
        putty_timestamp = putty_timestamp.split("\n")[0] # For condition where two PuTTy timestamp is capture
        putty_datetime = datetime.strptime(putty_timestamp, '%Y.%m.%d %H:%M:%S')

        cicso_time_pattern = re.compile(r"!Time:\s(.+?)\n")
        cisco_timezone_pattern = re.compile(r"clock timezone\s(\w{1,3})(.+?)\n")
        cisco_format = f'%a %b %d %H:%M:%S %Y'

        cisco_time_match = cicso_time_pattern.search(running_config)
        if not cisco_time_match:
            logging.warning(f"MISSING CISCO TIMESTAMP IN CONFIG")
            return "N/A", putty_datetime

        cisco_time_str = cisco_time_match.group(1).replace("  ", " ")
        try:
            cisco_tz_match = cisco_timezone_pattern.search(running_config)
            cisco_tz = cisco_tz_match.group(1) if cisco_tz_match else "N/A"
            cisco_datetime = f"{datetime.strptime(cisco_time_str, cisco_format)} {cisco_tz}"

            return cisco_datetime, putty_datetime
        except ValueError:
            logging.warning(f"MISSING TIMEZONE IN CONFIG")
            return "N/A", putty_datetime
    
    def extract_version_info(self, show_version_output):
        if show_version_output is None: return "N/A", "N/A", "N/A", "N/A"
        model_number, serial_number, uptime, software_version = "N/A", "N/A", "N/A", "N/A"
        show_version_pattern = re.compile(r"""
                     (?:Processor\sBoard\sID (?P<serial_number>.*)|
                     Kernel\suptime\sis(?P<uptime>.*)|
                     NXOS:\s(?P<software_version>.*)|
                     Hardware\n(?P<model_number>.*))""",re.VERBOSE)
        
        show_version_matches = show_version_pattern.search(show_version_output)

        if show_version_matches:
            show_version_matches = show_version_pattern.finditer(show_version_output)
            for match in show_version_matches:
                model_number = match.group("model_number") or model_number
                serial_number = match.group("serial_number") or serial_number
                uptime = match.group("uptime") or uptime
                software_version = match.group("software_version") or software_version
        
        uptime = uptime.strip() if uptime != "N/A" else "N/A"
        software_version = software_version.strip() if software_version != "N/A" else "N/A"
        model_number = model_number.strip() if model_number != "N/A" else "N/A"
        serial_number = serial_number.strip() if serial_number != "N/A" else "N/A"

        if model_number == "N/A":
            logging.warning(f"MISSING MODEL NUMBER IN `show version`")
        if uptime == "N/A":
            logging.warning(f"MISSING UPTIME IN `show version`")
        if software_version == "N/A":
            logging.warning(f"MISSING SOFTWARE VERSION IN `show version`")
        SERIAL_NUMBER_LIST.append(serial_number) if serial_number != "N/A" else logging.warning(
            f"MISSING SERIAL NUMBER IN `show version`")


        return model_number, serial_number, uptime, software_version

    def extract_memory_info(self, show_sysresources):
        if show_sysresources is None: return "N/A", "N/A"
        
        memory_usage_pattern = re.compile(r"Memory usage:\s+(\d+)[Kk] total,\s+(\d+)[Kk] used,\s+(\d+)[Kk] free\n")
        try:
            memory_usage_match = memory_usage_pattern.search(show_sysresources)

            total_memory = int(memory_usage_match[1])
            used_memory = int(memory_usage_match[2])
            # free_memory = int(memory_usage_match[3])
        except AttributeError:
            logging.warning(f"MISSING MEMORY INFO")
            total_memory = used_memory = "N/A"
        except TypeError:
            logging.warning(f"MEMORY INFO FOUND, BUT NOT INTEGER TYPE")
            total_memory = used_memory = "N/A"

        return total_memory, used_memory

    def extract_disk_info(self, dir_info):
        if dir_info is None: return "N/A", "N/A"

        disk_usage_pattern = re.compile(r"(\d+)\sbytes\sused\n\s*(\d+)\sbytes\sfree\n\s*(\d+)\sbytes\stotal")
        try:
            disk_usage_match = disk_usage_pattern.search(dir_info)

            total_memory = int(disk_usage_match[3])
            used_memory = int(disk_usage_match[1])
            # free_memory = int(disk_usage_match[2])
        except AttributeError:
            logging.warning(f"MISSING DISK INFO")
            total_memory = used_memory = "N/A"
        except TypeError:
            logging.warning(f"DISK INFO FOUND, BUT NOT INTEGER TYPE")
            total_memory = used_memory = "N/A"
            

        return total_memory, used_memory
    
    def extract_cpu_info(self, show_sysresources):
        if show_sysresources is None: return "N/A", "N/A", "N/A", "N/A"
        cpu_5min, cpu_1min, cpu_5sec, cpu_utlization = "N/A", "N/A", "N/A", "N/A"

        cpu_usage_pattern = re.compile(
            r"""
            (?:
                five\ seconds:\s(?P<five_sec>\d+%/\d+%);\s
                one\sminute:\s(?P<one_min>\d+%);\s
                five\sminutes:\s(?P<five_min>\d+%)
            |
                (?P<cputil_user>\d+.\d+)%\ user,\s+
                (?P<cputil_kernel>\d+.\d+)%\ kernel,\s+
                (?P<cputil_idle>\d+.\d+)%\ idle
            )
            """, re.VERBOSE)

        cpu_usage_matches = cpu_usage_pattern.search(show_sysresources)

        if cpu_usage_matches:
            cpu_usage_matches = cpu_usage_pattern.finditer(show_sysresources)
            for cpu_usage in cpu_usage_matches:
                fivesec_1 = cpu_usage.group("five_sec")
                onemin_1 = cpu_usage.group("one_min")
                fivemin_1 = cpu_usage.group("five_min")
                cputil_percent = cpu_usage.group("cputil_idle")

                cpu_1min = onemin_1 or cpu_1min  # Assign if non-empty
                cpu_5sec = fivesec_1 or cpu_5sec
                cpu_5min = fivemin_1 or cpu_5min
                cpu_utlization = cputil_percent or cpu_utlization
        
        cpu_utlization = round(100 - float(cpu_utlization), 2)
        
        if cpu_5min and cpu_1min and cpu_5sec == "N/A":
             logging.warning(f"MISSING CPU 5min, 1min, 5sec")

        if cpu_utlization == "N/A":
            logging.warning(f"MISSING CPU UTILIZATION INFO")

        return cpu_5min, cpu_1min, cpu_5sec, cpu_utlization

    def extract_inventory_info(self, show_inventory):
        if show_inventory is None: return "N/A" , "N/A"

        inventory_dict = {
            "Name": "N/A",
            "PID": "N/A",
            "SN": "N/A"
        }
        inventory_list = []
        inventory_dict_list = []
        
        inventory_pattern = re.compile(r"NAME:\s+\"(.+?)\",\s+(.+?)\nPID:\s+(.+?),(.+?)SN:\s+(.+?)\n")
        try:
            inventory_matches = inventory_pattern.findall(show_inventory)
            inventory_matches = list(dict.fromkeys(inventory_matches)) # remove duplicates
        except AttributeError:
            logging.warning(f"MISSING INVENTORY INFO")
            return "N/A", "N/A"

        for inventory in inventory_matches:
            for item in inventory:
                if item == "Chassis":
                    SERIAL_NUMBER_LIST.append(inventory[4].strip())
                    inventory_dict = inventory_dict.copy()
                    inventory_dict["Name"] = inventory[0]
                    inventory_dict["PID"] = inventory[2].strip()
                    inventory_dict["SN"] = inventory[4].strip()

                    inventory_dict_list.append(inventory_dict)
                    inventory_list.append(f"Name: {inventory[0]}, PID: {inventory[2].strip()}, SN: {inventory[4].strip()}")
        inventory_str = "\n".join(inventory_list)

        if inventory_str == "":
            logging.warning(f"INVENTORY INFO FOUND, BUT NO MATCHING INFO")
            inventory_str = "N/A, show inventory found but no matching inventory info"

            return inventory_str, "N/A"
        
        return inventory_str, inventory_dict_list
    
    def extract_ip_address_info(self, running_config, hostname):
        ip_address_pattern_file = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        authentication_info_pattern = re.compile(r"(aaa group server (?:tacacs\+|radius|tacacs) (\w+)\s+\n)(\s+.*?\n)+")

        # remove hostname from file name
        filename = file.replace(f"{hostname}", "")        
        ip_address = ip_address_pattern_file.search(filename)
        
        if ip_address:
            return f"{ip_address.group(1)} (from file name)", ip_address.group(1)
        else:
            try:
                authentication_info = authentication_info_pattern.search(running_config).group(0)
                return f"\nNO IP ADDRESS, SHOW AUTHENTICATION INFO:\n{'-.'*16}\n{authentication_info}{'-.'*16}"
            except (AttributeError, TypeError):
                logging.warning(f"MISSING IP ADDRESS IN FILE NAME AND CONFIG")
                return "N/A", "N/A"
            
    def extract_info(self, pattern, file_data, error_message):
        try:
            info = pattern.findall(file_data)
            if info and len(info) > 1: # Condition for multiple matches
                info = "\n".join(info)
            else:
                info = info[0]
        except (AttributeError, IndexError):
            info = None
            logging.error(f"{error_message} IN FILE")

            # for debugging
            # traceback.print_exc()
        return info

    def export_report(self, report):
        with open(f"{NXOS_SWITCH_FILE_NAME}", 'a') as f:
            f.write(report)
    
    def export_dict_to_csv(self, csv_dict):
        # Create a copy to for standalone and first switch in the stack
        # else csv_dict data type will get alter after saving to row
        first_csv_dict = csv_dict.copy()  

        with open(f"{NXOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
            writer = csv.writer(csv_file)

            if csv_dict["Inventory Information"] != "N/A":  # stack switch
                if len(csv_dict["Inventory Information"]) > 1:  # if more than 1 switch in stack
                    first_inventory_dict = csv_dict["Inventory Information"][0]
                    
                    first_csv_dict["Model Number"] = first_inventory_dict['PID']
                    first_csv_dict["Serial Number"] = first_inventory_dict['SN']
                    first_csv_dict['Inventory Information'] = f"Name: {first_inventory_dict['Name']}, PID: {first_inventory_dict['PID']}, SN: {first_inventory_dict['SN']}"
                    writer.writerow(list(first_csv_dict.values()))

                    for inventory_dict in csv_dict["Inventory Information"][1:]:  # skip first row
                        # Set values for each switch in the stack
                        csv_dict["Serial Number"] = inventory_dict["SN"]
                        csv_dict["Model Number"] = inventory_dict["PID"]

                        # Set other values to "N/A"
                        csv_dict.update({
                            "Total Memory": "N/A",
                            "Used Memory": "N/A",
                            "Memory Percent Used": "N/A",
                            "Total Disk": "N/A",
                            "Used Disk": "N/A",
                            "Disk Percent Used": "N/A",
                            "5-minute CPU Average": "N/A",
                            "1-minute CPU Average": "N/A",
                            "5-second CPU Average": "N/A",
                            "Inventory Information": f"Name: {inventory_dict['Name']}, PID: {inventory_dict['PID']}, SN: {inventory_dict['SN']}"
                        })

                        # Write values to the CSV file
                        writer.writerow(list(csv_dict.values()))
                else:
                    first_csv_dict['Inventory Information'] = "Standalone Switch"
                    writer.writerow(list(first_csv_dict.values()))
            else:  # standalone switch
                first_csv_dict['Inventory Information'] = "Standalone Switch"
                writer.writerow(list(first_csv_dict.values()))


class Catalyst_Switch:
    def __init__(self, data):

        # All regular expressions here
        show_tech_match = re.search(r"#sh(?:ow)? tech", data)
        putty_timestamp_pattern = re.compile(r"(?:PuTTY|MobaXterm) log (\d{4}\.\d{2}.\d{2} \d{2}:\d{2}:\d{2})")
        directory_pattern = re.compile(r"\#dir(.+?)\#", re.DOTALL)
        ntp_status_pattern = re.compile(r"#sh(?:ow)? ntp sta(?:tus|tu)?(.+?)#", re.DOTALL)
        boot_mode_pattern = re.compile(r"#sh(?:ow)? boot(.+?)#", re.DOTALL)

        if show_tech_match:
            # require show tech to be run
            show_version_pattern = re.compile(r"-\sshow version(.+?)\n\n\n\-{4,}", re.DOTALL)
            running_config_pattern = re.compile(r"-\sshow running-config(.+?)\n\-{4,}", re.DOTALL)
            cisco_timestamp_pattern = re.compile(r"-\sshow clock(.+?)\n\-{4,}", re.DOTALL)
            cpu_usage_pattern = re.compile(r"-\sshow process cpu(.+?)\n\n\-{4,}", re.DOTALL)
            memory_usage_pattern = re.compile(r"-\sshow process memory(.+?)\n\-{4,}", re.DOTALL)
            file_systems_pattern = re.compile(r"-\sshow file systems(.+?)\n\n\-{4,}", re.DOTALL)
            pnp_stack_pattern = re.compile(r"-\sshow inventory(.+?)\n\n\-{4,}", re.DOTALL)
        else:
            show_version_pattern = re.compile(r"#sh(?:ow)? ver(?:sion)?(.+?)#", re.DOTALL)
            running_config_pattern = re.compile(r"#sh(?:ow)? run(?:ning)?(.+?)#", re.DOTALL)
            cisco_timestamp_pattern = re.compile(r"#sh(?:ow)? clock(.+?)#", re.DOTALL)
            cpu_usage_pattern = re.compile(r"#sh(?:ow)? process cpu(.+?)#", re.DOTALL)
            memory_usage_pattern = re.compile(r"#sh(?:ow)? process memory(.+?)#", re.DOTALL)
            file_systems_pattern = re.compile(r"#sh(?:ow)? file system(?:s)?(.+?)#", re.DOTALL)
            pnp_stack_pattern = re.compile(r"#sh(?:ow)? inv(?:entory)?(.+?)#", re.DOTALL)
        
        logging.info(f" IOS Switch : {file} (show tech)" if show_tech_match else f" IOS Switch : {file}")

        # Extract information from the file
        running_config = self.extract_info(running_config_pattern, data, "No `show running config` command")
        show_version_info = self.extract_info(show_version_pattern, data, "No `show version` command")
        cpu_usage_info = self.extract_info(cpu_usage_pattern, data, "No `show process cpu` command")
        memory_usage_info = self.extract_info(memory_usage_pattern, data, "No `show process memory` command")
        disk_usage_info = self.extract_info(file_systems_pattern, data, "No `show file systems` command")
        if disk_usage_info is None:
            dir_info = self.extract_info(directory_pattern, data, "No `dir` command")
        cisco_datatime_info = self.extract_info(cisco_timestamp_pattern, data, "No `show clock` commadn")
        putty_datetime_info = self.extract_info(putty_timestamp_pattern, data, "No `PuTTY log timestamp` in file")
        pnp_stack_info = self.extract_info(pnp_stack_pattern, data, "No `show inventory` command")
        ntp_status_info = self.extract_info(ntp_status_pattern, data, "No `show ntp status` command")
        boot_mode_info = self.extract_info(boot_mode_pattern, data, "No `show boot` command")

        hostname = self.get_hostname(running_config)
        ip_address_info, ip_address = self.extract_ip_address_info(running_config, hostname)
        model_number, serial_number, uptime, software_version, boot_mode = self.extract_version_info(show_version_info, boot_mode_info)
        
        total_memory, used_memory = self.extract_memory_info(memory_usage_info)
        total_memory_mb = round(total_memory/(1024**2), 2) if total_memory != "N/A" else "N/A"
        used_memory_mb = round(used_memory/(1024**2), 2) if used_memory != "N/A" else "N/A"
        memory_usage_percent = "N/A" if total_memory == "N/A" else f"{round(used_memory/total_memory*100, 2)}%"

        total_disk, used_disk, disk_type = self.extract_disk_info(disk_usage_info) if disk_usage_info else self.extract_dir_info(dir_info)
        total_disk_mb = round(total_disk/1024**2, 2) if total_disk != "N/A" else "N/A"
        used_disk_mb = round(used_disk/1024**2, 2) if used_disk != "N/A" else "N/A"
        disk_usage_percent = "N/A" if total_disk == "N/A" else f"{round(used_disk/total_disk*100, 2)}%"

        cpu_5min, cpu_1min, cpu_5sec = self.extract_cpu_info(cpu_usage_info)
        cisco_datetime, putty_datetime, ntp_status = self.compare_clocks(putty_datetime_info, cisco_datatime_info, ntp_status_info)
        inventory_info, inventory_dict_list = self.extract_inventory_info(pnp_stack_info)

        # Generate report format
        report_format = f"""=~=~=~=~=~=~=~=~=~=~=~==~=~=~=~=~=~=~=~=~=~=~=
Report for File : {file}
~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=
IP Address       : {ip_address_info}
Hostname         : {hostname}
Model Number     : {model_number}
Serial Number    : {serial_number}
Uptime           : {uptime}
Software Version : {software_version} ({boot_mode})

Memory Usage:
Total Memory : {total_memory} bytes, {total_memory_mb} MiB
Used Memory  : {used_memory} bytes, {used_memory_mb} MiB
Percent Used : {memory_usage_percent}

Disk Usage: ({disk_type})
Total Disk      : {total_disk} bytes, {total_disk_mb} MiB
Used Disk       : {used_disk} bytes, {used_disk_mb} MiB
Percent Used    : {disk_usage_percent}

CPU Usage:
5-minute Average: {cpu_5min}
1-minute Average: {cpu_1min}
5-second Average: {cpu_5sec}

Timestamps:
Cisco Timestamp: {cisco_datetime}
Putty Timestamp: {putty_datetime}
NTP Status     : {ntp_status}

Inventory Information:
{inventory_info}
---

"""
    
        self.export_report(report_format)
        
        CSV_DICT = EXPORT_CSV_DICT.copy()
        CSV_DICT["File Name"] = file
        CSV_DICT["Hostname"] = hostname
        CSV_DICT["Model Number"] = model_number
        CSV_DICT["Serial Number"] = serial_number
        CSV_DICT["IP Address"] = ip_address
        CSV_DICT["Uptime"] = uptime
        CSV_DICT["Software Version"] = software_version
        CSV_DICT["Total Memory"] = total_memory
        CSV_DICT["Used Memory"] = used_memory
        CSV_DICT["Memory Percent Used"] = memory_usage_percent
        CSV_DICT["Total Disk"] = total_disk
        CSV_DICT["Used Disk"] = used_disk
        CSV_DICT["Disk Percent Used"] = disk_usage_percent
        CSV_DICT["5-minute CPU Average"] = cpu_5min
        CSV_DICT["1-minute CPU Average"] = cpu_1min
        CSV_DICT["5-second CPU Average"] = cpu_5sec
        CSV_DICT["Cisco Timestamp"] = cisco_datetime
        CSV_DICT["Putty Timestamp"] = putty_datetime
        CSV_DICT["NTP Status"] = ntp_status
        CSV_DICT["Boot Mode"] = boot_mode
        CSV_DICT["Inventory Information"] = inventory_dict_list
        self.export_dict_to_csv(CSV_DICT)
    
    def get_hostname(self, running_config):
        if running_config is None: return "N/A"

        hostname_pattern = re.compile(r"hostname\s+(.+?)\n")
        
        try:
            hostname = hostname_pattern.search(running_config).group(1)
        except AttributeError:
            hostname = "N/A"
            logging.warning(f"MISSING HOSTNAME IN CONFIG")

        return hostname
        
    def compare_clocks(self, putty_timestamp, cisco_timestamp, ntp_status):
        if putty_timestamp is None or cisco_timestamp is None: return "N/A", "N/A"

        # Extract PuTTy timestamp
        putty_timestamp = putty_timestamp.split("\n")[0] # For condition where two PuTTy timestamp is capture
        putty_datetime = datetime.strptime(putty_timestamp, '%Y.%m.%d %H:%M:%S')

        # Compile regex patterns here
        cisco_time_pattern = re.compile(r"(\d{2}:\d{2}:\d{2}.\d{3} (\w{2,3}) \w{3} \w{3} \d{1,2} \d{4})")
        ntp_status_pattern = re.compile(r"Clock is synchronized, stratum (.+?), reference is (.+?)\n")

        # Search for Cisco timestamp
        cisco_time_match = cisco_time_pattern.search(ntp_status) if ntp_status else cisco_time_pattern.search(cisco_timestamp)
        if not cisco_time_match:
            logging.warning(f"MISSING CISCO TIMESTAMP IN CONFIG")
            return "N/A", putty_datetime

        cisco_time_str, cisco_tz = cisco_time_match.group(1), cisco_time_match.group(2)
        if not cisco_tz:
            cisco_tz = ""
            logging.warning(f"CISCO TIMESTAMP WITHOUT TIMEZONE")
        
        # Search for NTP status
        ntp_status_match = ntp_status_pattern.search(ntp_status) if ntp_status else None
        if ntp_status_match:
            ntp_status_stratum = ntp_status_match.group(1)
            ntp_status_reference = ntp_status_match.group(2).strip()
            ntp_status_msg  = f"SYNC({ntp_status_stratum}/16), REF: {ntp_status_reference}"
        else:
            ntp_status_msg = "NOT SYNC" if ntp_status else "NOT FOUND"
        
        # Format Cisco timestamp    
        cisco_format = f'%H:%M:%S.%f {cisco_tz} %a %b %d %Y'
        cisco_datetime = datetime.strptime(cisco_time_str, cisco_format)
        cisco_datetime = datetime.strftime(cisco_datetime, '%Y-%m-%d %H:%M:%S')

        cisco_datetime = f"{cisco_datetime} {cisco_tz}"

        return cisco_datetime, putty_datetime, ntp_status_msg

    def extract_version_info(self, show_version_output, boot_mode_output):
        if show_version_output is None: return "N/A", "N/A", "N/A", "N/A", "N/A"

        # Initialize variables/compile regex patterns here
        model_number_pattern = re.compile(r"""
                    (?:
                    Model [Nn]umber\s+:\s+(?P<model_type_1>.+?)\n|
                    cisco\s(?P<model_type_2>.*?)\s|
                    License\sInformation\sfor\s\'(?P<model_coreswitch>.*?)\'\n|
                    Cisco\s(?P<model_type_3>.*?)\s                      
                    )""",re.VERBOSE)
        serial_number_pattern = re.compile(r"System [Ss]erial [Nn]umber\s+:\s+(.+)")
        uptime_pattern = re.compile(r"uptime is\s+(.+?)\n")
        software_version_pattern = re.compile(r"Version (.+?),")
        boot_mode_pattern = re.compile(r"\:(.+(.conf|.bin))")
        serial_number = uptime = software_version = boot_mode = "N/A"

        model_number_match = model_number_pattern.search(show_version_output)
        serial_number = serial_number_pattern.search(show_version_output)
        uptime = uptime_pattern.search(show_version_output)
        software_version = software_version_pattern.search(show_version_output)
        boot_mode_match = boot_mode_pattern.search(boot_mode_output)
        
        if model_number_match:
            model_number_match = model_number_pattern.finditer(show_version_output)
            for match in model_number_match:
                model_number = match.group("model_type_1") or match.group("model_coreswitch") or match.group("model_type_2") or match.group("model_type_3")
        else:
            model_number = "N/A"
            logging.warning(f"MISSING MODEL NUMBER IN `show version`")
            
        if not serial_number: # Core Switch
            serial_number_pattern = re.compile(r"Processor\s[Bb]oard\sID\s(.*?)\n")
            serial_number = serial_number_pattern.search(show_version_output)
            logging.warning(f"MISSING SERIAL NUMBER IN `show version`") if not serial_number else None

        if serial_number:
            serial_number = serial_number.group(1)
            SERIAL_NUMBER_LIST.append(serial_number)
        else:
            logging.warning(f"MISSING SERIAL NUMBER IN `show version`")

        if uptime:
            uptime = uptime.group(1)
        else:
            logging.warning(f"MISSING UPTIME IN `show version`")

        if not software_version: # Core Switch
            software_version_pattern = re.compile(r"ROM:\s(.*?)\n")
            software_version = software_version_pattern.search(show_version_output)
            logging.warning(f"MISSING SOFTWARE VERSION IN `show version`") if not software_version else None

        if software_version:
            software_version = software_version.group(1)
        else:
            logging.warning(f"MISSING SOFTWARE VERSION IN `show version`")
        
        if boot_mode_match:
            boot_type = boot_mode_match.group(2)
            boot_mode = "Install Mode" if ".conf" in boot_type else "Bundle Mode"
        else:
            logging.warning(f"MISSING BOOT MODE IN `show boot`")

        return model_number, serial_number, uptime, software_version, boot_mode
    
    def extract_memory_info(self, memory_usage):
        if memory_usage is None: return "N/A", "N/A"

        # Initialize variables/compile regex patterns here
        memory_usage_pattern = re.compile(r"(?:Processor Pool Total:|Total:)\s+(\d+)\,? Used:\s+(\d+)\,? Free:\s+(\d+)|System memory\s+:\s+(\d+)K\stotal,\s(\d+)K\sused,\s(\d+)K")
                
        try:
            memory_usage_match = memory_usage_pattern.search(memory_usage)

            total_memory = int(memory_usage_match[1])
            used_memory = int(memory_usage_match[2])
            # free_memory = int(memory_usage_match[3])
        except AttributeError:
            logging.warning(f"MISSING MEMORY INFO")
            total_memory = used_memory = "N/A"
        except TypeError:
            # Possible is Core Switch, use second pattern
            try:
                total_memory = int(memory_usage_match[4])*1000
                used_memory = int(memory_usage_match[5])*1000
                # free_memory = int(memory_usage_match[6])*1000
            except TypeError:
                total_memory = used_memory = "N/A"
                logging.warning(f"MISSING MEMORY INFO")

      
        return total_memory, used_memory
    
    def extract_disk_info(self, disk_usage):
        if disk_usage is None: return "N/A", "N/A", 'N/A'
        
        disk_usage_pattern = re.compile(r"\*\s+(\d+)\s+(\d+)\s+(\w+)")

        try:
            disk_usage_match = disk_usage_pattern.search(disk_usage)

            total_memory = int(disk_usage_match[1])
            used_memory = int(disk_usage_match[2])
            disk_type = disk_usage_match[3]
        except (TypeError, AttributeError):
            logging.warning(f"MISSING DISK INFO")
            total_memory = used_memory = disk_type = "N/A"
        
        return total_memory, used_memory, disk_type

    def extract_dir_info(self, dir_info):
        if dir_info is None: return "N/A", "N/A", "N/A"
        disk_usage_pattern = re.compile(r"(\d+)\sb(?:ytes|yte)\stotal\s\((\d+)\sb(?:ytes|yte)\sfree\)")

        try:
            disk_usage_match = disk_usage_pattern.search(dir_info)

            total_memory = int(disk_usage_match[1])
            used_memory = int(disk_usage_match[2])
        except (TypeError, AttributeError):
            logging.warning(f"MISSING DISK INFO")
            total_memory = used_memory = "N/A"

        return total_memory, used_memory, "N/A"

    def extract_cpu_info(self, cpu_usage):
        if cpu_usage is None: return "N/A", "N/A", "N/A"

        # Initialize variables/compile regex patterns here
        cpu_5min_pattern = re.compile(r"five minutes: (.+?)\n")
        cpu_1min_pattern = re.compile(r"one minute: (.+?);")
        cpu_5sec_pattern = re.compile(r"five seconds: (.+?);")

        try:
            cpu_5min = cpu_5min_pattern.search(cpu_usage).group(1)
            cpu_1min = cpu_1min_pattern.search(cpu_usage).group(1)
            cpu_5sec = cpu_5sec_pattern.search(cpu_usage).group(1)
        except AttributeError:
            cpu_5min = cpu_1min = cpu_5sec = "N/A"
            logging.warning(f"MISSING CPU USAGE INFO")

        return cpu_5min, cpu_1min, cpu_5sec

    def extract_inventory_info(self, show_inventory):
        if show_inventory is None: return "N/A", "N/A"

        inventory_dict = {
            "Name": "N/A",
            "PID": "N/A",
            "SN": "N/A"
        }

        inventory_list = []
        inventory_dict_list = []

        inventory_pattern = re.compile(r"NAME:\s+(.+?),\s+(.+?)\nPID:\s+(.+?),(.+?)SN:\s(.+?)\n")
        switch_keyworad_pattern = re.compile(r"\"(?:\d{1,2}|Switch\s+\d{1,2}|Switch\d{0,2}\s+System|Switch\s\d{1,2}\s+Chassis|Chassis|Chassis \d{1,2})\"")
        
        try:
            inventory_matches = inventory_pattern.findall(show_inventory)
            inventory_matches = list(dict.fromkeys(inventory_matches)) # remove duplicates
        except AttributeError:
            logging.warning(f"MISSING INVENTORY INFO")
            return "N/A", "N/A"

        for inventory in inventory_matches:
            for item in inventory:
                switch = switch_keyworad_pattern.search(item)
                if switch:
                    # if no serial number, 
                    # means it is provisioned switch, so will just exclude it
                    if inventory[4].strip() != "": 
                        SERIAL_NUMBER_LIST.append(inventory[4].strip())
                        inventory_dict = inventory_dict.copy()
                        inventory_dict["Name"] = inventory[0].replace('"', '')
                        inventory_dict["PID"] = inventory[2].strip()
                        inventory_dict["SN"] = inventory[4].strip()
                        
                        
                        inventory_dict_list.append(inventory_dict)
                        inventory_list.append(f"Name: {inventory[0].replace('"', '')}, PID: {inventory[2].strip()}, SN: {inventory[4].strip()}")
        inventory_str = "\n".join(inventory_list)

        if inventory_str == "":
            # the condition that no inventory info match, but show inventory found
            logging.warning(f"INVENTORY INFO FOUND, BUT NO MATCHING INFO")
            inventory_str = "N/A, show inventory found but no matching inventory info"

            return inventory_str, "N/A"
        
        return inventory_str, inventory_dict_list

    def extract_ip_address_info(self, running_config, hostname):
        """
        Step to extract IP address information

        1. Try to get IP address from the file name.
        2. Else, Get VLAN interface that handles SSH.
        3. Then, Get IP address of the VLAN interface.
        4. Else, get all matching IP addresses in the running config.
        """

        # Initialize variables/compile regex patterns here
        ip_address_pattern = re.compile(r"ip address (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")
        ip_address_pattern_file = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        ssh_source_interface_pattern = re.compile(r"ip (?:ssh|tacacs|radius) source-interface [vV]lan(\d+)")

        source_interface_vlan = ""

        # Step 1
        filename = file.replace(f"{hostname}", "")
        ip_address = ip_address_pattern_file.search(filename)
        
        if ip_address:
            return f"{ip_address.group(1)} (from file name)", ip_address.group(1)
        elif running_config is not None:
            try:
                # Step 2
                source_interface_vlan = ssh_source_interface_pattern.search(running_config).group(1)
                
                # Step 3
                vlan_interface_match = re.search(r"\!\ninterface Vlan" + source_interface_vlan + r"\n(.+?)\!\n", running_config, re.DOTALL).group(1)
                ip_address = re.search(ip_address_pattern, vlan_interface_match).group(1)
                return f"{ip_address} (from VLAN {source_interface_vlan})", re.search(ip_address_pattern_file, vlan_interface_match).group(1)
            except AttributeError:
                # Step 4
                ip_address_info = "\n".join(ip_address_pattern.findall(running_config))
                return f"\nNO SSH SOURCE INTERFACE, SHOW ALL MATCH:\n{'-.'*16}\n{ip_address_info}\n{'-.'*16}\n", 'N/A'
        else:
            return "N/A", "N/A"

    def extract_info(self, pattern, file_data, error_message):
        try:
            info = pattern.findall(file_data)
            if info and len(info) > 1:
                info = "\n".join(info)
            else:
                info = info[0]
        except (AttributeError, IndexError):
            info = None
            logging.error(f"{error_message} IN FILE")

            # for debugging
            # traceback.print_exc()
        return info

    def export_report(self, report):
        with open(f"{IOS_SWITCH_FILE_NAME}", 'a') as f:
            f.write(report)

    def export_dict_to_csv(self, csv_dict):
        # Create a copy to for standalone and first switch in the stack
        # else csv_dict data type will get alter after saving to row
        first_csv_dict = csv_dict.copy()  
        
        with open(f"{IOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
            writer = csv.writer(csv_file)

            if csv_dict["Inventory Information"] != "N/A":  # stack switch
                if len(csv_dict["Inventory Information"]) > 1:  # if more than 1 switch in stack
                    first_inventory_dict = csv_dict["Inventory Information"][0]
                    
                    first_csv_dict["Model Number"] = first_inventory_dict['PID']
                    first_csv_dict["Serial Number"] = first_inventory_dict['SN']
                    first_csv_dict['Inventory Information'] = f"Name: {first_inventory_dict['Name']}, PID: {first_inventory_dict['PID']}, SN: {first_inventory_dict['SN']}"
                    writer.writerow(list(first_csv_dict.values()))

                    for inventory_dict in csv_dict["Inventory Information"][1:]:  # skip first row
                        # Set values for each switch in the stack
                        csv_dict["Serial Number"] = inventory_dict["SN"]
                        csv_dict["Model Number"] = inventory_dict["PID"]

                        # Set other values to "N/A"
                        csv_dict.update({
                            "Total Memory": "N/A",
                            "Used Memory": "N/A",
                            "Memory Percent Used": "N/A",
                            "Total Disk": "N/A",
                            "Used Disk": "N/A",
                            "Disk Percent Used": "N/A",
                            "5-minute CPU Average": "N/A",
                            "1-minute CPU Average": "N/A",
                            "5-second CPU Average": "N/A",
                            "Inventory Information": f"Name: {inventory_dict['Name']}, PID: {inventory_dict['PID']}, SN: {inventory_dict['SN']}"
                        })

                        # Write values to the CSV file
                        writer.writerow(list(csv_dict.values()))
                else:
                    first_csv_dict['Inventory Information'] = "Standalone Switch"
                    writer.writerow(list(first_csv_dict.values()))
            else:  # standalone switch
                first_csv_dict['Inventory Information'] = "Standalone Switch"
                writer.writerow(list(first_csv_dict.values()))


class Cisco_WLC:
    def __init__(self, data, controller_name):
        logging.info(f" WLC Cisco  : {file} [{controller_name}]")
        ap_info_dict_list = [] # a list of dict for all ap info of a wlc

        # show_run_pattern = re.compile(r"\(.*?\) \>sh(?:ow) run(?:ning)(.+?)\(.+?\) \>", re.DOTALL)
        show_run_pattern = re.compile(rf"\({controller_name}\) \>sh(?:ow) run(?:ning)?(?:-config)?(.+?)\)\s>", re.DOTALL)
        wlc_ap_pattern = re.compile(rf"\({controller_name}\) \>show ap sum(?:mary)?(.+?)\)\s>", re.DOTALL)
        wlc_ap_uptime_pattern = re.compile(rf"\({controller_name}\) \>show ap uptime(.+?)\)\s>", re.DOTALL)
        wlc_ap_inventory_pattern = re.compile(rf"\({controller_name}\) \>show ap inv(?:entory)?\s+all(.+?)\)\s>", re.DOTALL)
        wlc_cpu_pattern = re.compile(rf"\({controller_name}\) \>show cpu(.+?)\)\s>", re.DOTALL)
        wlc_memory_pattern = re.compile(rf"\({controller_name}\) \>show memory(.+?)\)\s>", re.DOTALL)
        wlc_disk_pattern = re.compile(rf"\({controller_name}\) \>test system disk-usage(.+?)\)\s>", re.DOTALL)
        putty_timestamp_pattern = re.compile(r"(?:PuTTY|MobaXterm) log (\d{4}\.\d{2}.\d{2} \d{2}:\d{2}:\d{2})")

        wlc_show_run = self.extract_info(show_run_pattern, data, "No `show running config` command")
        putty_timestamp = self.extract_info(putty_timestamp_pattern, data, "No `PuTTY log timestamp` in file")
        wlc_cpu_info = self.extract_info(wlc_cpu_pattern, data, "No `show cpu usage` command")
        wlc_memory_info = self.extract_info(wlc_memory_pattern, data, "No `show memory summary ` command")
        wlc_ap_summary = self.extract_info(wlc_ap_pattern, data, "No `show ap summary` command")
        wlc_ap_uptime = self.extract_info(wlc_ap_uptime_pattern, data, "No `show ap uptime` command")
        wlc_ap_inventory = self.extract_info(wlc_ap_inventory_pattern, data, "No `show ap inventory all` command")
        wlc_disk_pattern = self.extract_info(wlc_disk_pattern, data, "No `test system disk-usage` command")
        
        wlc_dict = WLC_INFO_DICT.copy()
        wlc_dict["File Name"] = file
        wlc_dict["Putty Timestamp"] = datetime.strptime(putty_timestamp, "%Y.%m.%d %H:%M:%S")
        wlc_dict = self.extract_wlc_showrun(wlc_show_run, wlc_dict)
        wlc_dict = self.extract_wlc_cpu(wlc_cpu_info, wlc_dict)
        wlc_dict = self.extract_wlc_memory(wlc_memory_info, wlc_dict)
        wlc_dict = self.extract_disk_usage(wlc_disk_pattern, wlc_dict)
        
        ap_info_dict_list = self.extract_ap_summary(wlc_ap_summary, ap_info_dict_list)
        ap_info_dict_list = self.extract_ap_uptime(wlc_ap_uptime, ap_info_dict_list)
        ap_info_dict_list = self.extract_ap_inventory(wlc_ap_inventory, ap_info_dict_list)

        self.export_report(wlc_dict, ap_info_dict_list)

    def extract_wlc_showrun(self, data, wlc_dict):
        if data is None: return wlc_dict

        wlc_model_sn_pattern = re.compile(r"\DESCR:\s\"(.+?)\"\n+PID:\s(.+?),.+\SN:\s(.+?)\n")
        wlc_version_pattern = re.compile(r"Product Version\.+\s(.+?)\n")
        wlc_uptime_pattern = re.compile(r"Up Time\.+\s(.+?)\n")
        wlc_hostname_pattern = re.compile(r"System Name\.+\s(.+?)\n")
        wlc_ipaddress_pattern = re.compile(r"IP Address\.+\s(.+?)\n")
        wlc_time_pattern = re.compile(r"Information:\n+Time\.+\s(.+?)\s\n")

        #wlc_model_sn_pattern.findall(data)
        wlc_model_sn_info = wlc_model_sn_pattern.search(data)
        wlc_version_info = wlc_version_pattern.search(data)
        wlc_uptime_info = wlc_uptime_pattern.search(data)
        wlc_hostname_info = wlc_hostname_pattern.search(data)
        wlc_ipaddress_info = wlc_ipaddress_pattern.search(data)
        wlc_time_info = wlc_time_pattern.search(data)
        
        if wlc_model_sn_info:
            wlc_dict["Model Number"] = f'{wlc_model_sn_info.group(2)} ({wlc_model_sn_info.group(1)})'
            wlc_dict["Serial Number"] = wlc_model_sn_info.group(3)
        else:
            logging.warning(f"MISSING MODEL NUMBER OR SERIAL NUMBER IN FILE")
            wlc_dict["Model Number"] = "N/A"
            wlc_dict["Serial Number"] = "N/A"
        
        if wlc_version_info:
            wlc_dict["Software Version"] = wlc_version_info.group(1)
        else:
            logging.warning(f"MISSING SOFTWARE VERSION IN FILE")
            wlc_dict["Software Version"] = "N/A"
        
        if wlc_uptime_info:
            wlc_dict["Uptime"] = wlc_uptime_info.group(1)
        else:
            logging.warning(f"MISSING UPTIME IN FILE")
            wlc_dict["Uptime"] = "N/A"
        
        if wlc_hostname_info:
            wlc_dict["Hostname"] = wlc_hostname_info.group(1)
        else:
            logging.warning(f"MISSING HOSTNAME IN FILE")
            wlc_dict["Hostname"] = "N/A"
        
        if wlc_ipaddress_info:
            wlc_dict["IP Address"] = wlc_ipaddress_info.group(1)
        else:
            logging.warning(f"MISSING IP ADDRESS IN FILE")
            wlc_dict["IP Address"] = "N/A"
        if wlc_time_info:
            wlc_dict["Cisco Timestamp"] = wlc_time_info.group(1)
            wlc_dict["Cisco Timestamp"] = datetime.strptime(wlc_dict["Cisco Timestamp"], "%a %b %d %H:%M:%S %Y")
        else:
            logging.warning(f"MISSING CISCO TIMESTAMP IN FILE")
            wlc_dict["Cisco Timestamp"] = "N/A"

        return wlc_dict
    
    def extract_disk_usage(self, data, wlc_dict):
        if data is None: return wlc_dict

        disk_usage_pattern = re.compile(r"(\d+\.\d+|\d+)(?:M|k| )\s+(\d+\.\d+|\d+)(?:M|k| )\s+(\d+\.\d+|\d+)(?:M|k| )\s+(\d{1,2})%\s+.*\/run\n")
        disk_usage_info = disk_usage_pattern.search(data)

        try:
            total_disk = float(disk_usage_info.group(1))
            used_disk = float(disk_usage_info.group(1)) - float(disk_usage_info.group(3))

            wlc_dict["Total Disk"] = round(total_disk,2)
            wlc_dict["Used Disk"] = round(used_disk,2)
            wlc_dict["Disk Percent Used"] = round(used_disk / total_disk * 100, 2)
        except AttributeError:
            wlc_dict["Total Disk"] = "N/A"
            wlc_dict["Used Disk"] = "N/A"
            wlc_dict["Disk Percent Used"] = "N/A"
            logging.warning(f"MISSING DISK USAGE INFO IN FILE")
        
        return wlc_dict

    def extract_wlc_cpu(self, data, wlc_dict):
        if data is None: return wlc_dict

        cpu_load_pattern = re.compile(r"Current\sCPU\(s\)\sload:\s(\d+)%")
        cpu_load_info = cpu_load_pattern.search(data)

        try:
            wlc_dict["CPU Average"] = cpu_load_info.group(1)
        except AttributeError:
            wlc_dict["CPU Average"] = "N/A"
            logging.warning(f"MISSING CPU USAGE INFO IN FILE")

        return wlc_dict

    def extract_wlc_memory(self, data, wlc_dict):
        if data is None: return wlc_dict

        total_memory_pattern = re.compile(r"Total System Memory\.+ \((\d+)\s+KB\) (\d+) MB")
        free_memory_pattern = re.compile(r"Total System Free Memory\.+ \((\d+)\s+KB\) (\d+) MB")

        try:
            total_memory_mb = int(total_memory_pattern.search(data).group(2))
            free_memory_mb = int(free_memory_pattern.search(data).group(2))
            used_memory_mb = total_memory_mb - free_memory_mb

            wlc_dict["Total Memory"] = total_memory_mb
            wlc_dict["Used Memory"] = used_memory_mb
            wlc_dict["Memory Percent Used"] = round(used_memory_mb / total_memory_mb * 100, 2)
        except (AttributeError, ValueError):
            wlc_dict["Total Memory"] = "N/A"
            wlc_dict["Used Memory"] = "N/A"
            wlc_dict["Memory Percent Used"] = "N/A"
            logging.warning(f"MISSING MEMORY USAGE INFO IN FILE")

        return wlc_dict

    def extract_ap_summary(self, data, ap_list):
        if data is None: return ap_list

        wlc_ap_info_pattern = re.compile(r"-\n(.+?)\n\n", re.DOTALL)
        wlc_ap_info = wlc_ap_info_pattern.search(data) # capture all ap info section
        if wlc_ap_info:
            wlc_ap_info = wlc_ap_info.group(1).split("\n")
            wlc_ap_info = [ap for ap in wlc_ap_info if ap != ''] # remove empty string
            
            for ap in wlc_ap_info:
                ap_dict = AP_INFO_DICT.copy()

                ap_info = re.split(r'\s\s+', ap)

                ap_dict["AP Name"] = ap_info[0]
                ap_dict["Model"] = ap_info[2]
                ap_dict["IP Address"] = ap_info[6]

                ap_list.append(ap_dict)
        else:
            logging.warning(f"MISSING AP SUMMARY IN FILE")
            
        return ap_list        
    
    def extract_ap_uptime(self, data, ap_list):
        if data is None: return ap_list

        ap_uptime_pattern = re.compile(r"-\n(.+?)\n\n", re.DOTALL)
        wlc_ap_list = ap_uptime_pattern.search(data)
        
        if wlc_ap_list:
            wlc_ap_list = wlc_ap_list.group(1).split("\n")
            wlc_ap_list = [ap for ap in wlc_ap_list if ap != ''] # remove empty string

            for ap in wlc_ap_list:
                uptime_info = re.split(r'\s\s+', ap)  # Split each line using one or more spaces as the delimiter 
                for ap_info in ap_list:

                    if ap_info["AP Name"] == uptime_info[0]:
                        ap_info["Uptime"] = uptime_info[2]
        else:
            logging.warning(f"MISSING AP UPTIME IN FILE")
            
        return ap_list
    
    def extract_ap_inventory(self, data, ap_list):  
        if data is None: return ap_list

        ap_inventory_pattern = re.compile(r"Inventory for (.*?)\n+NAME:\s\"(.*?)\"\s+,\s+DESCR:\s+\"(.*?)\"\n+PID:\s+(.*?),\s+VID:\s+(.*?),\s+SN:\s(.*?)\n\n")
        wlc_ap_list = ap_inventory_pattern.findall(data)
        if wlc_ap_list:
            for ap in wlc_ap_list:
                for ap_info in ap_list:
                    if ap_info["AP Name"] == ap[0]:
                        ap_info["Serial Number"] = ap[5]
        else:
            logging.warning(f"MISSING AP INVENTORY IN FILE")
        
        return ap_list

    def export_report(self, wlc_dict, ap_list):
        # export in two report, one for wlc txt, one for ap csv
        report_format = f"""=~=~=~=~=~=~=~=~=~=~=~==~=~=~=~=~=~=~=~=~=~=~=
Report for File : {file}
~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=
IP Address       : {wlc_dict['IP Address']}
Hostname         : {wlc_dict['Hostname']}
Model Number     : {wlc_dict['Model Number']}
Serial Number    : {wlc_dict['Serial Number']}
Uptime           : {wlc_dict['Uptime']}
Software Version : {wlc_dict['Software Version']}

Memory Usage:
Total Memory : {wlc_dict["Total Memory"]} MB
Used Memory  : {wlc_dict["Used Memory"]} MB
Percent Used : {wlc_dict["Memory Percent Used"]}%

Disk Usage:
Total Disk      : {wlc_dict["Total Disk"]} MB
Used Disk       : {wlc_dict["Used Disk"]} MB
Percent Used    : {wlc_dict["Disk Percent Used"]}%

CPU Usage:
Cpu Utlization  : {wlc_dict["CPU Average"]}%

Timestamps:
Cisco Timestamp: {wlc_dict["Cisco Timestamp"]}
Putty Timestamp: {wlc_dict["Putty Timestamp"]}
---

"""
        
        with open(f"{CISCO_WLC_FILE_NAME}", "a") as f:
            f.write(report_format)

        with open(f"{CISCO_WLC_AP_FILE_NAME}", "a", newline='') as f:
            f.write(f"{file}\n")
            writer = csv.DictWriter(f, fieldnames=AP_INFO_DICT.keys())
            writer.writeheader()
            writer.writerows(ap_list)

    def extract_info(self, pattern, file_data, error_message):
        try:
            info = pattern.findall(file_data)
            if info and len(info) > 1:
                info = "".join(info)
            else:
                info = info[0]
        except (AttributeError, IndexError):
            info = None
            logging.error(f"{error_message} IN FILE") 
            # for debugging
            # traceback.print_exc()
        return info


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.ERROR:
            self._style = logging.PercentStyle('    %(levelname)s: %(message)s')
        elif record.levelno == logging.WARNING:
            self._style = logging.PercentStyle('    %(levelname)s: %(message)s')
        else:
            self._style = logging.PercentStyle('%(message)s')
        return super().format(record)

def logging_init():
    # Create a file handler with the custom formatter
    file_handler = logging.FileHandler(LOG_FILE_NAME, mode='w')
    file_handler.setLevel(logging.DEBUG)  # Set the level as needed
    file_handler.setFormatter(CustomFormatter())

    # Configure logging to output to console
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)  # Set the level as needed
    console.setFormatter(CustomFormatter())

    # Add handlers to the root logger
    logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console])
    logging.getLogger('').addHandler(console)

if __name__ == "__main__":
    # create output folder if not exist
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    # get current path
    files = os.listdir()
    try:
        os.remove(f"{IOS_SWITCH_FILE_NAME}") if os.path.exists(f"{IOS_SWITCH_FILE_NAME}") else None
        os.remove(f"{NXOS_SWITCH_FILE_NAME}") if os.path.exists(f"{NXOS_SWITCH_FILE_NAME}") else None
        os.remove(f"{IOS_SWITCH_CSV_FILE_NAME}") if os.path.exists(f"{IOS_SWITCH_CSV_FILE_NAME}") else None
        os.remove(f"{NXOS_SWITCH_CSV_FILE_NAME}") if os.path.exists(f"{NXOS_SWITCH_CSV_FILE_NAME}") else None
        os.remove(f"{CISCO_WLC_FILE_NAME}") if os.path.exists(f"{CISCO_WLC_FILE_NAME}") else None
        os.remove(f"{CISCO_WLC_AP_FILE_NAME}") if os.path.exists(f"{CISCO_WLC_AP_FILE_NAME}") else None
    except PermissionError:
        input(f"Please close the following files:\n{IOS_SWITCH_FILE_NAME}\n{NXOS_SWITCH_FILE_NAME}\n{IOS_SWITCH_CSV_FILE_NAME}\n{NXOS_SWITCH_CSV_FILE_NAME}\n\nPress Enter to continue...")

    files = [file for file in os.listdir() if os.path.splitext(file)[1] in TEXT_FILE_EXTENSION]
    files.sort(key=lambda x: [int(c) if c.isdigit() else c.lower() for c in re.split('([0-9]+)', x)]) # Natural Sort Function

    # create csv file header
    with open(f"{IOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(EXPORT_CSV_DICT.keys())

    with open(f"{NXOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(EXPORT_CSV_DICT.keys())

    unknown_file = []
    processed_file = []
    export_csv_dict_list = []
    total_file = len(files)
    nxos_switch_pattern = re.compile(r"!Command:")
    ios_switch_pattern = re.compile(r"[Cc]isco IOS")
    cisco_wlc_pattern = re.compile(r"\((.*?)\)\s>")
    unicode_escape_pattern = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
    
    logging_init()

    for file in files:
        # create export csv dictionary for each file
        try:
            with open(file, "r") as f:
                data = f.read()
                data = re.sub(unicode_escape_pattern, '', data)
                if nxos_switch_pattern.search(data):
                    nexus_switch = Nexus_Switch(data)
                    processed_file.append(file)
                elif ios_switch_pattern.search(data):
                    catalyst_switch = Catalyst_Switch(data)
                    processed_file.append(file)
                elif cisco_wlc_pattern.search(data):
                    controller_name = cisco_wlc_pattern.search(data).group(1)
                    Cisco_WLC(data, controller_name)
                    processed_file.append(file)
                else:
                    unknown_file.append(file)
        except UnicodeDecodeError:
            logging.error(f"UNICODE DECODE ERROR IN FILE [{file}]")
            unknown_file.append(file)
        except FileNotFoundError:
            logging.error(f"FILE NOT FOUND [{file}], CHECK PATH LENGTH LIMIT")
            unknown_file.append(file)
        
    logging.debug("\n"+"-"*50)
    for file in unknown_file:
        logging.debug(f"Unknown Switch or File [{file}]")
    logging.debug("-"*50) if len(unknown_file) != 0 else None
    logging.debug(f"Total file: {total_file}, Processed file: {len(processed_file)}, Unknown file: {len(unknown_file)}\n")
    logging.shutdown()

    # SERIAL_NUMBER_LIST = list(dict.fromkeys(SERIAL_NUMBER_LIST))
    # for serial_number in SERIAL_NUMBER_LIST:
    #     print(serial_number)
    input("Press Enter to exit...")

