import ipaddress
from typing import List, Dict, Any, Optional
from database.models import FirewallRule

# Map common service object names to port numbers so risk scoring works
# even when the XML parser stores "svc-rdp" instead of "3389".
SERVICE_TO_PORT: Dict[str, int] = {
    "svc-ftp-ctrl": 21, "svc-ftp-data": 20, "ftp": 21, "ftp-ctrl": 21,
    "svc-ssh": 22, "ssh": 22, "svc-sftp": 22,
    "svc-telnet": 23, "telnet": 23,
    "svc-smtp": 25, "smtp": 25, "svc-smtp-submission": 587,
    "svc-dns-udp": 53, "svc-dns-tcp": 53, "dns": 53,
    "svc-tftp": 69, "tftp": 69,
    "svc-http": 80, "http": 80, "web-browsing": 80,
    "svc-kerberos": 88, "kerberos": 88,
    "svc-msrpc": 135, "msrpc": 135,
    "svc-netbios-ns": 137, "svc-netbios-ssn": 139, "netbios-ssn": 139,
    "svc-imap": 143, "svc-imaps": 993,
    "svc-snmp": 161, "snmp": 161, "svc-snmp-trap": 162,
    "svc-ldap": 389, "ldap": 389, "svc-ldaps": 636, "ldaps": 636,
    "svc-https": 443, "https": 443, "ssl": 443,
    "svc-smb": 445, "smb": 445,
    "svc-smtps": 465,
    "svc-syslog": 514, "syslog": 514,
    "svc-modbus": 502, "modbus": 502,
    "svc-ftps": 990,
    "svc-mssql": 1433, "mssql": 1433, "svc-mssql-browser": 1434,
    "svc-oracle": 1521, "oracle": 1521,
    "svc-pptp": 1723,
    "svc-nfs": 2049,
    "svc-mysql": 3306, "mysql": 3306,
    "svc-rdp": 3389, "ms-rdp": 3389, "msrdp": 3389,
    "svc-postgres": 5432, "postgresql": 5432,
    "svc-vnc": 5900, "vnc": 5900,
    "svc-winrm-http": 5985, "svc-winrm-https": 5986,
    "svc-redis": 6379, "redis": 6379,
    "svc-http-alt": 8080, "http-alt": 8080, "svc-https-alt": 8443,
    "svc-elasticsearch": 9200, "elasticsearch": 9200,
    "svc-elasticsearch-cluster": 9300,
    "svc-memcached": 11211, "memcached": 11211,
    "svc-mongodb": 27017, "mongodb": 27017,
    "svc-docker": 2375, "svc-docker-tls": 2376,
    "svc-kubernetes": 6443,
    "svc-metasploit": 4444, "svc-cobalt-strike": 50050,
    "svc-s7comm": 102, "s7comm": 102,
    "svc-kafka": 9092, "svc-zookeeper": 2181, "svc-etcd": 2379,
    "svc-cassandra": 9042, "svc-couchdb": 5984,
    "svc-ntp": 123, "ntp": 123,
    "svc-openvpn": 1194, "svc-ipsec-isakmp": 500, "svc-ipsec-nat-t": 4500,
}

def resolve_port(dest_port: str) -> Optional[int]:
    """Resolve a dest_port value (number, service name, or range) to a single port."""
    if not dest_port or dest_port.lower() in ("any", "application-default", "1-65535"):
        return None
    try:
        return int(dest_port)
    except (ValueError, TypeError):
        pass
    # Try service name lookup (case-insensitive)
    return SERVICE_TO_PORT.get(dest_port.lower().strip())

def ip_in_network(ip_str: str, network_str: str) -> bool:
    """
    Checks if an IP address or network is contained within another network.
    """
    if network_str.lower() == 'any' or network_str == '0.0.0.0/0':
        return True
    if ip_str.lower() == 'any' or ip_str == '0.0.0.0/0':
        return network_str.lower() == 'any' or network_str == '0.0.0.0/0'
    
    try:
        # Normalize to CIDR
        if '/' not in ip_str:
            ip_str += '/32'
        if '/' not in network_str:
            network_str += '/32'
            
        ip_net = ipaddress.ip_network(ip_str, strict=False)
        target_net = ipaddress.ip_network(network_str, strict=False)
        
        return target_net.supernet_of(ip_net)
    except ValueError:
        return False

def port_in_range(port_str: str, range_str: str) -> bool:
    """
    Checks if a port or port range is contained within another port range.
    """
    if range_str.lower() == 'any' or range_str == '1-65535':
        return True
    if port_str.lower() == 'any' or port_str == '1-65535':
        return range_str.lower() == 'any' or range_str == '1-65535'
        
    try:
        def parse_range(p_str):
            if '-' in p_str:
                start, end = map(int, p_str.split('-'))
                return start, end
            else:
                p = int(p_str)
                return p, p
                
        p_start, p_end = parse_range(port_str)
        r_start, r_end = parse_range(range_str)
        
        return r_start <= p_start and r_end >= p_end
    except (ValueError, TypeError):
        return False

def check_if_shadowed(current_rule: FirewallRule, all_rules: List[FirewallRule]) -> bool:
    """
    A rule is shadowed if a higher priority rule (lower position) matches 
    all traffic that the current rule would match.
    """
    for rule in all_rules:
        # Only check rules with higher priority (lower position) on the same device
        if rule.device_name == current_rule.device_name and rule.rule_position < current_rule.rule_position:
            
            # Check Protocol
            proto_match = (rule.protocol.lower() == 'any' or 
                           rule.protocol.lower() == current_rule.protocol.lower())
            
            if not proto_match:
                continue
                
            # Check Source IP
            src_match = ip_in_network(current_rule.source_ip, rule.source_ip)
            if not src_match:
                continue
                
            # Check Destination IP
            dst_match = ip_in_network(current_rule.dest_ip, rule.dest_ip)
            if not dst_match:
                continue
                
            # Check Destination Port
            port_match = port_in_range(current_rule.dest_port, rule.dest_port)
            if not port_match:
                continue
                
            # If we reach here, all traffic for current_rule is covered by 'rule'
            return True
            
    return False

def calculate_rule_risk(rule: FirewallRule, all_rules: List[FirewallRule], vulnerable_ports: Dict[int, Dict[str, str]]) -> Dict[str, Any]:
    """
    Calculates risk score and reasons based on the scoring algorithm.
    Category is chosen by the *highest-severity* matching condition, not last.
    """
    risk_score = 0.0
    reasons = []
    # Track all matching categories with their severity weight
    matched_categories: List[tuple] = []  # (weight, category_name)

    src_any = rule.source_ip.lower() in ('any', '0.0.0.0/0')
    dst_any = rule.dest_ip.lower() in ('any', '0.0.0.0/0')
    port_any = rule.dest_port.lower() in ('any', '1-65535', 'application-default') if rule.dest_port else True

    # 1. Source Wildcard Check (max +2 points)
    if src_any:
        risk_score += 2
        reasons.append("Source allows ANY IP address")

    # 2. Destination Wildcard Check (max +2 points)
    if dst_any:
        risk_score += 2
        reasons.append("Destination allows ANY IP address")

    # 3. Port Range Size (max +1.5 points)
    if port_any:
        risk_score += 1.5
        reasons.append("Allows all ports")
    elif '-' in rule.dest_port:
        try:
            start, end = map(int, rule.dest_port.split('-'))
            if (end - start) > 100:
                risk_score += 1.0
                reasons.append(f"Wide port range: {rule.dest_port}")
        except ValueError:
            pass

    # Overly permissive: src=any AND dst=any AND port=any AND action=allow
    if src_any and dst_any and port_any and rule.action.lower() == 'allow':
        matched_categories.append((4, "overly_permissive"))

    # 4. Insecure Service Check (max +3 points)
    insecure_ports = [21, 23, 445, 3389, 1433, 3306, 5432]
    if rule.action.lower() == 'allow':
        port_num = resolve_port(rule.dest_port)
        if port_num is not None and port_num in insecure_ports:
            risk_score += 3
            svc_info = vulnerable_ports.get(port_num)
            service = svc_info['service'] if svc_info else str(port_num)
            reasons.append(f"Allows vulnerable service: {service} on port {port_num}")
            matched_categories.append((3, "insecure_service"))
        elif '-' in (rule.dest_port or ''):
            try:
                start, end = map(int, rule.dest_port.split('-'))
                matched_insecure = [p for p in insecure_ports if start <= p <= end]
                if matched_insecure:
                    risk_score += 3
                    services = [vulnerable_ports.get(p, {}).get('service', str(p)) for p in matched_insecure]
                    reasons.append(f"Allows insecure services in range: {', '.join(services)}")
                    matched_categories.append((3, "insecure_service"))
            except ValueError:
                pass

    # 5. Unused Rule Check (max +1 point)
    if rule.hit_count == 0 or rule.last_hit is None:
        risk_score += 1
        reasons.append("Rule never used (unused)")
        matched_categories.append((1, "unused"))

    # 6. Shadowed Rule Check (max +2 points)
    shadowed = check_if_shadowed(rule, all_rules)
    if shadowed:
        risk_score += 2
        reasons.append("Shadowed by higher priority rule")
        matched_categories.append((2, "shadowed"))

    # Pick category by highest severity weight
    if matched_categories:
        matched_categories.sort(key=lambda x: x[0], reverse=True)
        category = matched_categories[0][1]
    else:
        category = "overly_permissive" if rule.action.lower() == 'allow' else "unused"

    # Cap at 10
    risk_score = min(risk_score, 10.0)

    # Determine Level and Color
    if risk_score >= 9.0:
        level = "critical"
        color = "red"
    elif risk_score >= 6.0:
        level = "high"
        color = "orange"
    elif risk_score >= 3.0:
        level = "medium"
        color = "yellow"
    else:
        level = "low"
        color = "green"

    return {
        "rule_id": rule.id,
        "risk_score": risk_score,
        "risk_level": level,
        "risk_category": category,
        "reason": "; ".join(reasons),
        "cvss_color": color,
        "recommendation": generate_recommendation(category, level, reasons)
    }

def generate_recommendation(category: str, level: str, reasons: List[str]) -> str:
    """
    Generates a basic recommendation based on findings.
    """
    if category == "shadowed":
        return "Delete this rule as it is covered by a higher priority rule, or move it above the shadowing rule if intended."
    if category == "unused":
        return "Review if this rule is still needed. If not, disable or delete it to reduce attack surface."
    if category == "insecure_service":
        return "Replace insecure protocol with a secure alternative (e.g., SSH instead of Telnet, SFTP instead of FTP)."
    if category == "overly_permissive":
        return "Restrict source/destination to specific IP addresses or subnets instead of 'any'."
    
    return "Apply principle of least privilege to this rule."
