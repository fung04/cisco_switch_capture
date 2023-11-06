import re
import os
import csv
from datetime import datetime

TEXT_FILE_EXTENSION = [".txt", ".log"]
NXOS_SWITCH_FILE_NAME = "2_NXOS_report.txt"
IOS_SWITCH_FILE_NAME = "1_IOS_report.txt"
NXOS_SWITCH_CSV_FILE_NAME = "2_NXOS_report.csv"
IOS_SWITCH_CSV_FILE_NAME = "1_IOS_report.csv"

EXPORT_CSV_DICT = {
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
    "Disk Percentage Used": "N/A",
    "5-minute CPU Average": "N/A",
    "1-minute CPU Average": "N/A",
    "5-second CPU Average": "N/A",
    "Cisco Timestamp": "N/A",
    "Putty Timestamp": "N/A",
    "Inventory Information": "{}"
}

class Nexus_Switch:
    def __init__(self, data):
        print(f"NXOS Switch : {file}")
        # All regular expressions here
        putty_timestamp_pattern = re.compile(r"(?:PuTTY|MobaXterm) log (\d{4}\.\d{2}.\d{2} \d{2}:\d{2}:\d{2})")
        running_config_pattern = re.compile(r"\#\sshow run(.+?)\#", re.DOTALL)
        show_version_pattern = re.compile(r"\#\sshow ver(.+?)\#", re.DOTALL)
        show_sysresources_pattern = re.compile(r"#\s?sh(?:ow)?\s?sys(?:tem)?\sres(?:ource|ources)?\s\n+Load(.+?)\#", re.DOTALL)
        show_processcpu_pattern = re.compile(r"\#\sshow process cpu\s\n+PID(.+?)\#", re.DOTALL)
        show_inventory_pattern = re.compile(r"\#\sshow inv(.+?)\#", re.DOTALL)
        directory_pattern = re.compile(r"\#\sdir(.+?)\#", re.DOTALL)

        running_config = self.extract_info(running_config_pattern, data, "NO `show running config` COMMAND")
        show_processcpu = self.extract_info(show_processcpu_pattern, data, "NO `show process cpu` COMMAND")
        show_version = self.extract_info(show_version_pattern, data, "NO `show version` COMMAND")
        show_sysresources = self.extract_info(show_sysresources_pattern, data, "NO `show system resources` COMMAND")
        putty_timestamp = self.extract_info(putty_timestamp_pattern, data, "NO `PuTTY log timestamp` in file")
        show_inventory = self.extract_info(show_inventory_pattern, data, "NO `show inventory` COMMAND")
        dir_info = self.extract_info(directory_pattern, data, "NO `dir` COMMAND")

        hostname = self.get_hostname(running_config)
        ip_address_info = self.extract_ip_address_info(running_config, hostname)
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
        inventory_info = self.extract_inventory_info(show_inventory)
        
        
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
Percentage Used : {disk_usage_percent}

CPU Usage:
5-minute Average: {cpu_5min}
1-minute Average: {cpu_1min}
5-second Average: {cpu_5sec}
cpu utlization  : {cpu_utlization}%

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
        CSV_DICT["IP Address"] = ip_address_info
        CSV_DICT["Hostname"] = hostname
        CSV_DICT["Model Number"] = model_number
        CSV_DICT["Serial Number"] = serial_number
        CSV_DICT["Uptime"] = uptime
        CSV_DICT["Software Version"] = software_version
        CSV_DICT["Total Memory"] = total_memory
        CSV_DICT["Used Memory"] = used_memory
        CSV_DICT["Memory Percent Used"] = memory_usage_percent
        CSV_DICT["Total Disk"] = total_disk
        CSV_DICT["Used Disk"] = used_disk
        CSV_DICT["Disk Percentage Used"] = disk_usage_percent
        CSV_DICT["5-minute CPU Average"] = cpu_5min if cpu_utlization != "N/A" else cpu_utlization
        CSV_DICT["1-minute CPU Average"] = cpu_1min
        CSV_DICT["5-second CPU Average"] = cpu_5sec
        CSV_DICT["Cisco Timestamp"] = cisco_datetime
        CSV_DICT["Putty Timestamp"] = putty_datetime
        CSV_DICT["Inventory Information"] = inventory_info
        self.export_dict_to_csv(CSV_DICT)


    def get_hostname(self, running_config):
        if running_config is None: return "N/A"

        hostname_pattern = re.compile(r"(?:hostname|switchname)\s+(.+?)\n")
        match = hostname_pattern.search(running_config)

        if match:
            hostname = match.group(1)
        else:
            hostname = "N/A"
            print(f"    WARN: MISSING HOSTNAME IN CONFIG")

        return hostname
    
    def compare_clocks(self, running_config, putty_timestamp):
        if putty_timestamp is None or running_config is None: return "N/A", "N/A"
        
        cicso_time_pattern = re.compile(r"!Time:\s(.+?)\n")
        cisco_timezone_pattern = re.compile(r"clock timezone\s(\w{1,3})(.+?)\n")
        cisco_format = f'%a %b %d %H:%M:%S %Y'
        
        cisco_time_str = cicso_time_pattern.search(running_config).group(1).replace("  ", " ")
        
        try:
            cisco_tz = cisco_timezone_pattern.search(running_config).group(1)
        except AttributeError:
            cisco_tz = "N/A"
        finally:  
                # Convert Cisco timestamp and Putty timestamp to datetime objects
                putty_datetime = datetime.strptime(putty_timestamp, '%Y.%m.%d %H:%M:%S')
                cisco_datetime = f"{datetime.strptime(cisco_time_str, cisco_format)} {cisco_tz}"

                return cisco_datetime, putty_datetime
    
    def extract_version_info(self, show_version_output):
        if show_version_output is None: return "N/A", "N/A", "N/A", "N/A"

        # Initialize variables/compile regex patterns here
        model_number_pattern = re.compile(r"Hardware\n(.+?)\n")
        serial_number_pattern = re.compile(r"\s?Processor Board ID\s(.+?)\n")
        uptime_pattern = re.compile(r"Kernel uptime is\s(.+?)\n")
        software_version_pattern = re.compile(r"\s?NXOS:\s(.+?)\n")
        model_number = serial_number = uptime = software_version = "N/A"

        try:
            model_number_match = model_number_pattern.search(show_version_output)
            serial_number_match = serial_number_pattern.search(show_version_output)
            uptime_match = uptime_pattern.search(show_version_output)
            software_version_match = software_version_pattern.search(show_version_output)
        except AttributeError:
            print(f"    WARN: NOT ALL VERSION INFO FOR FILE [{file}]")

        if model_number_match:
            model_number = model_number_match.group(1).strip()
        if serial_number_match:
            serial_number = serial_number_match.group(1)
        if uptime_match:
            uptime = uptime_match.group(1)
        if software_version_match:
            software_version = software_version_match.group(1)

        return model_number, serial_number, uptime, software_version

    def extract_memory_info(self, show_sysresources):
        # print(f'show_sysresources: {show_sysresources}')
        if show_sysresources is None: return "N/A", "N/A"
        # Initialize variables/compile regex patterns here
        memory_usage_pattern = re.compile(r"Memory usage:\s+(\d+)[Kk] total,\s+(\d+)[Kk] used,\s+(\d+)[Kk] free\n")
        memory_usage_match = memory_usage_pattern.search(show_sysresources)
        try:
            memory_usage_match = memory_usage_pattern.search(show_sysresources)

            total_memory = int(memory_usage_match[1])
            used_memory = int(memory_usage_match[2])
            free_memory = int(memory_usage_match[3])
        except TypeError or AttributeError:
            print(f"    WARN: MISSING MEMORY INFO")
            total_memory = used_memory = "N/A"

        return total_memory, used_memory

    def extract_disk_info(self, dir_info):
        if dir_info is None: return "N/A", "N/A"

        disk_usage_pattern = re.compile(r"(\d+)\sbytes\sused\n(\d+)\sbytes\sfree\n(\d+)\sbytes\stotal")

        try:
            disk_usage_match = disk_usage_pattern.search(dir_info)

            total_memory = int(disk_usage_match[3])
            used_memory = int(disk_usage_match[1])
        except TypeError or AttributeError:
            print(f"    WARN: MISSING DISK INFO")
            total_memory = used_memory = "N/A"

        return total_memory, used_memory
    
    def extract_cpu_info(self, show_sysresources):
        if show_sysresources is None: return "N/A", "N/A", "N/A", "N/A"
        

        # Initialize variables/compile regex patterns here
        cpu_5min_pattern = re.compile(r"five minutes: (.+?)\n")
        cpu_1min_pattern = re.compile(r"one minute: (.+?);")
        cpu_5sec_pattern = re.compile(r"five seconds: (.+?);")
        cpu_utlization_pattern = re.compile(r"(\d+.\d+)% user,\s+(\d+.\d+)% kernel,\s+(\d+.\d+)% idle")

        try:
            cpu_5min = cpu_5min_pattern.search(show_sysresources).group(1)
            cpu_1min = cpu_1min_pattern.search(show_sysresources).group(1)
            cpu_5sec = cpu_5sec_pattern.search(show_sysresources).group(1)
        except:
            cpu_5min = cpu_1min = cpu_5sec = cpu_utlization = "N/A"
            print(f"    WARN: MISSING CPU USAGE")

        try:
            cpu_utlization = cpu_utlization_pattern.search(show_sysresources).group(3)
            cpu_utlization = round(100 - float(cpu_utlization), 2)
        except:
            cpu_utlization = "N/A"
            print(f"    WARN: MISSING CPU UILIZATION")

        return cpu_5min, cpu_1min, cpu_5sec, cpu_utlization

    def extract_inventory_info(self, show_inventory):
        if show_inventory is None: return "N/A"

        inventory_list = []
        inventory_pattern = re.compile(r"NAME:\s+\"(.+?)\",\s+(.+?)\nPID:\s+(.+?),(.+?)SN:\s+(.+?)\n")
        try:
            inventory_matches = inventory_pattern.findall(show_inventory)
        except AttributeError:
            print(f"    WARN: MISSING INVENTORY INFO")
            return "N/A"

        for inventory in inventory_matches:
            for item in inventory:
                if item == "Chassis":
                    inventory_list.append(f"Name: {inventory[0]}, PID: {inventory[2].strip()}, SN: {inventory[4].strip()}")
        inventory_list = "\n".join(inventory_list)
        
        return inventory_list
    
    def extract_ip_address_info(self, running_config, hostname):
        ip_address_pattern_file = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        authentication_info_pattern = re.compile(r"(aaa group server (?:tacacs\+|radius|tacacs) (\w+)\s+\n)(\s+.*?\n)+")

        # remove hostname from file name
        filename = file.replace(f"{hostname}", "")        
        ip_address = ip_address_pattern_file.search(filename)
        
        if ip_address:
            return f"{ip_address.group(1)} (from file name)"
        else:
            try:
                authentication_info = authentication_info_pattern.search(running_config).group(0)
                return f"\nNO IP ADDRESS, SHOW AUTHENTICATION INFO:\n{'-.'*16}\n{authentication_info}{'-.'*16}"
            except AttributeError:
                print(f"    WARN: MISSING IP ADDRESS")
                return "N/A"

    def extract_info(self, pattern, file_data, error_message):
        try:
            info = pattern.search(file_data).group(1)
        except AttributeError:
            info = None
            print(f"    ERROR: {error_message} IN FILE")

            # for debugging
            # traceback.print_exc()
        return info

    def export_report(self, report):
        with open(f"{NXOS_SWITCH_FILE_NAME}", 'a') as f:
            f.write(report)
    
    def export_dict_to_csv(self, csv_dict):
        # Extract the keys and values from the dictionary
        keys = EXPORT_CSV_DICT.keys()
        values = csv_dict.values()

        # Write the data to a CSV file
        with open(f"{NXOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
            writer = csv.writer(csv_file)
                        
            writer.writerow(values)


class Catalyst_Switch:
    def __init__(self, data):
        print(f"IOS Switch: {file}")
        # All regular expressions here
        putty_timestamp_pattern = re.compile(r"(?:PuTTY|MobaXterm) log (\d{4}\.\d{2}.\d{2} \d{2}:\d{2}:\d{2})")
        # require show tech to be run
        show_version_pattern = re.compile(r"-\sshow version(.+?)\n\n\n\-{4,}", re.DOTALL)
        running_config_pattern = re.compile(r"-\sshow running-config(.+?)\n\-{4,}", re.DOTALL)
        cisco_timestamp_pattern = re.compile(r"-\sshow clock(.+?)\n\-{4,}", re.DOTALL)
        cpu_usage_pattern = re.compile(r"-\sshow process cpu(.+?)\n\n\-{4,}", re.DOTALL)
        memory_usage_pattern = re.compile(r"-\sshow process memory(.+?)\n\-{4,}", re.DOTALL)
        file_systems_pattern = re.compile(r"-\sshow file systems(.+?)\n\n\-{4,}", re.DOTALL)
        pnp_stack_pattern = re.compile(r"-\sshow inventory(.+?)\n\n\-{4,}", re.DOTALL)

        # Extract information from the file
        running_config = self.extract_info(running_config_pattern, data, "No `show running config` command")
        show_version_info = self.extract_info(show_version_pattern, data, "No `show version` command")
        cpu_usage_info = self.extract_info(cpu_usage_pattern, data, "No `show process cpu` command")
        memory_usage_info = self.extract_info(memory_usage_pattern, data, "No `show process memory` command")
        disk_usage_info = self.extract_info(file_systems_pattern, data, "No `show file systems` command") #find at dir command if fail
        cisco_datatime_info = self.extract_info(cisco_timestamp_pattern, data, "No `show clock` commadn")
        putty_datetime_info = self.extract_info(putty_timestamp_pattern, data, "No `PuTTY log timestamp` in file")
        pnp_stack_info = self.extract_info(pnp_stack_pattern, data, "No `show inventory` command")

        hostname = self.get_hostname(running_config)
        ip_address_info = self.extract_ip_address_info(running_config, hostname) if running_config else "     ERROR: MISSING running config"
        model_number, serial_number, uptime, software_version = self.extract_version_info(show_version_info)
        
        total_memory, used_memory = self.extract_memory_info(memory_usage_info)
        total_memory_mb = round(total_memory/(1024**2), 2) if total_memory != "N/A" else "N/A"
        used_memory_mb = round(used_memory/(1024**2), 2) if used_memory != "N/A" else "N/A"
        memory_usage_percent = "N/A" if total_memory == "N/A" else f"{round(used_memory/total_memory*100, 2)}%"

        total_disk, used_disk, disk_type = self.extract_disk_info(disk_usage_info)
        total_disk_mb = round(total_disk/1024**2, 2) if total_disk != "N/A" else "N/A"
        used_disk_mb = round(used_disk/1024**2, 2) if used_disk != "N/A" else "N/A"
        disk_usage_percent = "N/A" if total_disk == "N/A" else f"{round(used_disk/total_disk*100, 2)}%"

        cpu_5min, cpu_1min, cpu_5sec = self.extract_cpu_info(cpu_usage_info)
        cisco_datetime, putty_datetime = self.compare_clocks(putty_datetime_info, cisco_datatime_info)
        inventory_info, inventory_info_list = self.extract_inventory_info(pnp_stack_info)

        # Generate report format
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
Total Memory : {total_memory} bytes, {total_memory_mb} MiB
Used Memory  : {used_memory} bytes, {used_memory_mb} MiB
Percent Used : {memory_usage_percent}

Disk Usage:({disk_type})
Total Disk      : {total_disk} bytes, {total_disk_mb} MiB
Used Disk       : {used_disk} bytes, {used_disk_mb} MiB
Percentage Used : {disk_usage_percent}

CPU Usage:
5-minute Average: {cpu_5min}
1-minute Average: {cpu_1min}
5-second Average: {cpu_5sec}

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
        CSV_DICT["IP Address"] = ip_address_info
        CSV_DICT["Hostname"] = hostname
        CSV_DICT["Model Number"] = model_number
        CSV_DICT["Serial Number"] = serial_number
        CSV_DICT["Uptime"] = uptime
        CSV_DICT["Software Version"] = software_version
        CSV_DICT["Total Memory"] = total_memory
        CSV_DICT["Used Memory"] = used_memory
        CSV_DICT["Memory Percent Used"] = memory_usage_percent
        CSV_DICT["Total Disk"] = total_disk
        CSV_DICT["Used Disk"] = used_disk
        CSV_DICT["Disk Percentage Used"] = disk_usage_percent
        CSV_DICT["5-minute CPU Average"] = cpu_5min
        CSV_DICT["1-minute CPU Average"] = cpu_1min
        CSV_DICT["5-second CPU Average"] = cpu_5sec
        CSV_DICT["Cisco Timestamp"] = cisco_datetime
        CSV_DICT["Putty Timestamp"] = putty_datetime
        CSV_DICT["Inventory Information"] = inventory_info_list
        self.export_dict_to_csv(CSV_DICT)
    
    def get_hostname(self, running_config):
        if running_config is None: return "N/A"

        hostname_pattern = re.compile(r"hostname\s+(.+?)\n")
        
        try:
            hostname = hostname_pattern.search(running_config).group(1)
        except AttributeError:
            hostname = "N/A"
            print(f"    WARN: MISSING HOSTNAME")

        return hostname

    def compare_clocks(self, putty_timestamp, cisco_timestamp):
        if putty_timestamp is None or cisco_timestamp is None: return "N/A", "N/A"

        # Initialize variables/compile regex patterns here
        cisco_pattern = re.compile(r"(\d{2}:\d{2}:\d{2}.\d{3} (\w{3}) \w{3} \w{3} \d{1,2} \d{4})")
        
        cisco_time_str = cisco_pattern.search(cisco_timestamp)
        cisco_tz = cisco_time_str.group(2)
        cisco_format = f'%H:%M:%S.%f {cisco_tz} %a %b %d %Y'
        
        # Convert Cisco timestamp and Putty timestamp to datetime objects
        cisco_datetime = f"{datetime.strptime(cisco_time_str.group(1), cisco_format)} {cisco_tz}"
        putty_datetime = datetime.strptime(putty_timestamp, '%Y.%m.%d %H:%M:%S')

        return cisco_datetime, putty_datetime

    def extract_version_info(self, show_version_output):
        if show_version_output is None: return "N/A", "N/A", "N/A", "N/A"
        # TODO: Add support for Core Switches

        # Initialize variables/compile regex patterns here
        model_number_pattern = re.compile(r"Model [Nn]umber\s+:\s+(.+?)\n")
        serial_number_pattern = re.compile(r"System [Ss]erial [Nn]umber\s+:\s+(.+)")
        uptime_pattern = re.compile(r"uptime is\s+(.+?)\n")
        software_version_pattern = re.compile(r"Version (.+?),")
        model_number = serial_number = uptime = software_version = "N/A"

        try:
            model_number_match = model_number_pattern.search(show_version_output)
            serial_number_match = serial_number_pattern.search(show_version_output)
            uptime_match = uptime_pattern.search(show_version_output)
            software_version_match = software_version_pattern.search(show_version_output)
        except AttributeError:
            print(f"    WARN: NOT ALL VERSION IN FILE [{file}]")

        if model_number_match:
            model_number = model_number_match.group(1)
        elif model_number_match == None:
            model_number_pattern = re.compile(r"License\sInformation\sfor\s\'(.*?)\'\n")
            model_number = model_number_pattern.search(show_version_output).group(1)
        else:
            print(f"    WARN: MISSING MODEL NUMBER IN FILE [{file}]")

        if serial_number_match:
            serial_number = serial_number_match.group(1)
        elif serial_number_match == None:
            serial_number_pattern = re.compile(r"Processor\s[Bb]oard\sID\s(.*?)\n")
            serial_number = serial_number_pattern.search(show_version_output).group(1)
        else:
            print(f"    WARN: MISSING SERIAL NUMBER IN FILE [{file}]")

        if uptime_match:
            uptime = uptime_match.group(1)
        
        if software_version_match:
            software_version = software_version_match.group(1)
        elif software_version_match == None:
            software_version_pattern = re.compile(r"ROM:\s(.*?)\n")
            software_version = software_version_pattern.search(show_version_output).group(1)
        else:
            print(f"    WARN: MISSING SOFTWARE VERSION IN FILE [{file}]")

        return model_number, serial_number, uptime, software_version
    
    def extract_memory_info(self, memory_usage):
        if memory_usage is None: return "N/A", "N/A"
        # TODO: Add support for Core Switches

        # Initialize variables/compile regex patterns here
        memory_usage_pattern = re.compile(r"Processor Pool Total:\s+(\d+) Used:\s+(\d+) Free:\s+(\d+)|System memory\s+:\s+(\d+)K\stotal,\s(\d+)K\sused,\s(\d+)K")
                
        try:
            memory_usage_match = memory_usage_pattern.search(memory_usage)

            total_memory = int(memory_usage_match[1])
            used_memory = int(memory_usage_match[2])
            free_memory = int(memory_usage_match[3])
        except AttributeError:
            print(f"    WARN: MISSING MEMORY INFO")
            total_memory = used_memory = "N/A"
        except TypeError:
            if memory_usage_match[4] is not None:
                total_memory = int(memory_usage_match[4])*1000
                used_memory = int(memory_usage_match[5])*1000
                free_memory = int(memory_usage_match[6])*1000
            else:
                total_memory = used_memory = "N/A"
                print(f"    WARN: MISSING MEMORY INFO")

      
        return total_memory, used_memory
    
    def extract_disk_info(self, disk_usage):
        if disk_usage is None: return "N/A", "N/A", 'N/A'

        # Initialize variables/compile regex patterns here
        disk_usage_pattern = re.compile(r"\*\s+(\d+)\s+(\d+)\s+(\w+)")

        try:
            disk_usage_match = disk_usage_pattern.search(disk_usage)

            total_memory = int(disk_usage_match[1])
            used_memory = int(disk_usage_match[2])
            disk_type = disk_usage_match[3]

        except TypeError or AttributeError:
            print(f"    WARN: MISSING DISK INFO")
            total_memory = used_memory = disk_type = "N/A"
        
        return total_memory, used_memory, disk_type

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
            print(f"    WARN: MISSING CPU USAGE INFO")

        return cpu_5min, cpu_1min, cpu_5sec

    def extract_inventory_info(self, show_inventory):
        if show_inventory is None: return "N/A", "N/A"

        inventory_list = []
        inventory_pattern = re.compile(r"NAME:\s+(.+?),\s+(.+?)\nPID:\s+(.+?),(.+?)SN:\s+(.+?)\n")
        switch_keyworad_pattern = re.compile(r"\"(?:\d{1,2}|Switch\s+\d{1,2}|Switch\d{1,2}\s+System)\"")
        
        try:
            inventory_matches = inventory_pattern.findall(show_inventory)
        except AttributeError:
            print(f"    WARN: MISSING INVENTORY INFO")
            return "N/A"

        for inventory in inventory_matches:
            for item in inventory:
                switch = switch_keyworad_pattern.search(item)
                if switch:
                    inventory_list.append(f"Name: {inventory[0]}, PID: {inventory[2].strip()}, SN: {inventory[4].strip()}")
        inventory_list_str = "\n".join(inventory_list)

        if inventory_list_str == "":
            inventory_list_str = "N/A, show inventory found but no matching inventory info"
            inventory_list = ["N/A, show inventory found but no matching inventory info"]

        return inventory_list_str, inventory_list

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
            return f"{ip_address.group(1)} (from file name)"
        else:
            try:
                # Step 2
                source_interface_vlan = ssh_source_interface_pattern.search(running_config).group(1)
                
                # Step 3
                vlan_interface_match = re.search(r"\!\ninterface Vlan" + source_interface_vlan + r"\n(.+?)\!\n", running_config, re.DOTALL).group(1)
                ip_address = re.search(ip_address_pattern, vlan_interface_match).group(1)
                return f"{ip_address} (from VLAN {source_interface_vlan})"
            except AttributeError:
                # Step 4
                ip_address_info = "\n".join(ip_address_pattern.findall(running_config))
                return f"\nNO SSH SOURCE INTERFACE, SHOW ALL MATCH:\n{'-.'*16}\n{ip_address_info}\n{'-.'*16}\n"

    def extract_info(self, pattern, file_data, error_message):
        try:
            info = pattern.search(file_data).group(1)
        except AttributeError:
            info = None
            print(f"    ERROR: {error_message} IN FILE")

            # for debugging
            # traceback.print_exc()
        return info

    def export_report(self, report):
        with open(f"{IOS_SWITCH_FILE_NAME}", 'a') as f:
            f.write(report)

    def export_dict_to_csv(self, csv_dict):

        # Extract the keys and values from the dictionary
        keys = EXPORT_CSV_DICT.keys()
        values = csv_dict.values()

        # Write the data to a CSV file
        with open(f"{IOS_SWITCH_CSV_FILE_NAME}", 'a', newline='') as csv_file:
            writer = csv.writer(csv_file)
                        
            writer.writerow(values)


if __name__ == "__main__":
    # get current path
    files = os.listdir()
    os.remove(f"{IOS_SWITCH_FILE_NAME}") if os.path.exists(f"{IOS_SWITCH_FILE_NAME}") else None
    os.remove(f"{NXOS_SWITCH_FILE_NAME}") if os.path.exists(f"{NXOS_SWITCH_FILE_NAME}") else None
    os.remove(f"{IOS_SWITCH_CSV_FILE_NAME}") if os.path.exists(f"{IOS_SWITCH_CSV_FILE_NAME}") else None
    os.remove(f"{NXOS_SWITCH_CSV_FILE_NAME}") if os.path.exists(f"{NXOS_SWITCH_CSV_FILE_NAME}") else None

    files = [file for file in os.listdir() if os.path.splitext(file)[1] in TEXT_FILE_EXTENSION]

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
    unicode_escape_pattern = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'


    for file in files:
        # create export csv dictionary for each file

        with open(file, "r") as f:
            data = f.read()
            data = re.sub(unicode_escape_pattern, '', data)
            if nxos_switch_pattern.search(data):
                nexus_switch = Nexus_Switch(data)
                processed_file.append(file)
            elif ios_switch_pattern.search(data):
                catalyst_switch = Catalyst_Switch(data)
                processed_file.append(file)
            else:
                unknown_file.append(file)


    print("\n"+"-"*50)
    for file in unknown_file:
        print(f"ERROR: Unknown switch type in file [{file}]")
    print("-"*50+"")
    print(f"Total file: {total_file}, Processed file: {len(processed_file)}, Unknown file: {len(unknown_file)}\n")
    input("Press Enter to exit...")