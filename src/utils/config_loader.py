class ConfigLoader:
    @staticmethod
    def load_process_whitelist():
        try:
            whitelist = []
            with open('data/process_whitelist.txt', 'r') as f:
                for line in f:
                    process = line.strip()
                    if process:
                        whitelist.append(process)
            return whitelist
        except FileNotFoundError:
            return ["chrome.exe", "code.exe", "python.exe", "explorer.exe"]

    @staticmethod
    def load_resource_limits():
        try:
            with open('data/resource_limits.txt', 'r') as f:
                limits = {}
                for line in f:
                    resource, limit = line.strip().split(',')
                    limits[resource] = float(limit)
                return limits
        except FileNotFoundError:
            return {'cpu': 50, 'memory': 70}