import psutil

# -------------------------------
# Get Process Info
# -------------------------------
def get_processes():
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info']):
        try:
            connections = proc.connections(kind='inet')

            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "user": proc.info['username'],
                "memory": proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                "connections": connections
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes


# -------------------------------
# Suspicious Detection Logic
# -------------------------------
def analyze_process(p):
    reasons = []

    if p["memory"] > 150 * 1024 * 1024:
        reasons.append("High Memory Usage")

    if not p["user"]:
        reasons.append("Unknown User")

    if len(p["connections"]) > 8:
        reasons.append("Many Network Connections")

    return reasons