import re

class LogParser:
    def __init__(self):
        # This regex captures the basic structure of Syslog/Auth.log
        # Group 1: Timestamp, Group 2: Hostname, Group 3: Servicio, Group 4: PID (opcional), Group 5: Mensaje
        self.ssh_regex = r'(?P<timestamp>\w{3}\s+\d+\s\d+:\d+:\d+)\s(?P<hostname>\S+)\s(?P<service>[\w\-\/]+)(\[(?P<pid>\d+)\])?:\s(?P<message>.*)'

        # Regex for Web
        self.web_regex = r'(?P<src_ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3})'

    def parse_line(self, line):
        # Clean tabs, spaces, \n...
        line = line.strip()

        # If the ssh_regex matches the log line creates a MATCH
        ssh_match = re.search(self.ssh_regex, line)
        if ssh_match:
            return self._parse_ssh(ssh_match) 
        
        # If the ssh fails then we try web
        web_match = re.search(self.web_regex, line)
        if web_match:
            return self._parse_web(web_match)

        return None
    
    def _parse_ssh(self, match):
        # Extracts the basic fields to a dictionary
        log_data = match.groupdict()

        # Extracts the message to check it from the log
        message = log_data.get('message', '')

        # Checks the message
        if "Failed password" in message or "Invalid user" in message:
            log_data['event_type'] = 'failed_login'
        elif "Accepted password" in message:
            log_data['event_type'] = 'successful_login'
            
        if 'event_type' in log_data:
            # Looks for user and ip
            ssh_pattern = r'(for|user) (?P<user>\S+) from (?P<ip>\S+)'
            ssh_match = re.search(ssh_pattern, message)

            # Verifies if the second regex found something
            if ssh_match:
                # Extracts the new fields: user, ip
                extra_data = ssh_match.groupdict()
                log_data['user'] = extra_data.get('user')
                log_data['src_ip'] = extra_data.get('ip') 

        return log_data
    
    def _parse_web(self, match):
        data = match.groupdict()
        data['service'] = 'web'
        # If status is 404 -> not found
        if data['status'] == '404':
            data['event_type'] = 'web_not_found'
        return data
    
if __name__ == "__main__":
    parser = LogParser()
    sample = "Oct 15 14:20:01 server1 sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2"
    print(parser.parse_line(sample))