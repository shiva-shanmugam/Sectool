#!/bin/bash

if [ ${UID} -ne 0 ]
then
    echo "Run the script as Administrator"
    echo "" > system_report.txt
    exit 1
fi

REPORT_FILE="system_report.txt"

get_hostname() {
    hostname
}

get_kernel_version() {
    uname -r
}

get_distribution_details() {
    if [ -x "$(command -v lsb_release)" ]; then
        lsb_release -a
    elif [ -f /etc/os-release ]; then
        cat /etc/os-release
    else
        echo "Unable to determine distribution details"
    fi
}

list_users() {
    cut -d : -f1 /etc/passwd
}

list_groups() {
    cut -d : -f1 /etc/group
}


list_installed_packages() {
    if [ -x "$(command -v dpkg)" ]; then
        dpkg -l
    elif [ -x "$(command -v rpm)" ]; then
        rpm -qa
    else
        echo "Unable to list installed packages"
    fi
}

get_network_interfaces() {
    ip addr show
}

list_firewall_rules() {
    if [ -x "$(command -v iptables)" ]; then
        iptables -L
    elif [ -x "$(command -v firewall-cmd)" ]; then
        firewall-cmd --list-all
    else
        echo "Unable to list firewall rules"
    fi
}

list_listening_ports() {
    netstat -tuln
}

list_mounted_filesystems() {
    mount
}

get_disk_usage() {
    df -h
}

print_separator() {
    echo "-----------------------------------------" >> "$REPORT_FILE"
}

check_package_integrity() {
    if [ -x "$(command -v debsums)" ]; then
        debsums -c
    elif [ -x "$(command -v rpm)" ]; then
        rpm -Va
    else
        echo "Unable to check package management integrity"
    fi
}

check_cve_vulnerabilities() {
    if [ -x "$(command -v apt-get)" ]; then
        apt-get changelog $(dpkg -l | grep '^ii' | awk '{print $2}') | grep -i 'CVE'
    elif [ -x "$(command -v yum)" ]; then
        yum list-security --security
    else
        echo "Unable to perform vulnerability checks"
    fi
}

check_file_permissions() {
    echo "File Permissions and Ownership:"
    echo "-----------------------------------------"
    echo "Home Directory Permissions:"
    ls -ld /home/*
    echo "Root Directory Permissions:"
    ls -ld /
    echo "User Directory Ownership:"
    ls -ld /home/*/ | awk '{print $3}'
}

check_security_configurations() {
    echo "Security Configurations:"
    echo "-----------------------------------------"
    if [ -x "$(command -v sestatus)" ]; then
        echo "SELinux Status:"
        sestatus
    elif [ -x "$(command -v apparmor_status)" ]; then
        echo "AppArmor Status:"
        apparmor_status
    else
        echo "Security configuration tools not found"
    fi
}

check_system_logs() {
    echo "System Logs:"
    echo "-----------------------------------------"
    echo "Last 10 lines of syslog:"
    tail -n 10 /var/log/syslog
    echo "Last 10 lines of auth.log:"
    tail -n 10 /var/log/auth.log
}

check_security_monitoring_tools() {
    echo "Security Monitoring Tools:"
    echo "-----------------------------------------"
    if [ -x "$(command -v chkrootkit)" ]; then
        echo "chkrootkit:"
        chkrootkit
    fi
    if [ -x "$(command -v rkhunter)" ]; then
        echo "rkhunter:"
        rkhunter --check
    fi
}

list_active_network_connections() {
    echo "Active Network Connections:"
    echo "-----------------------------------------"
    netstat -tuln
}

main() {
    echo "Generating system report..." > "$REPORT_FILE"
    print_separator
    echo "Hostname: $(get_hostname)" >> "$REPORT_FILE"
    print_separator
    echo "Kernel Version: $(get_kernel_version)" >> "$REPORT_FILE"
    print_separator
    echo "Distribution Details:" >> "$REPORT_FILE"
    print_separator
    get_distribution_details >> "$REPORT_FILE"
    print_separator
    echo "Installed Packages:" >> "$REPORT_FILE"
    print_separator
    # list_installed_packages >> "$REPORT_FILE"
    print_separator
    echo "User and Group Settings:" >> "$REPORT_FILE"
    print_separator
    echo "Users:" >> "$REPORT_FILE"
    print_separator
    list_users >> "$REPORT_FILE"
    print_separator
    echo "Groups:" >> "$REPORT_FILE"
    print_separator
    list_groups >> "$REPORT_FILE"
    print_separator
    echo "Filesystem and Storage Information:" >> "$REPORT_FILE"
    print_separator
    # echo "Mounted Filesystems:" >> "$REPORT_FILE"
    # print_separator
    # list_mounted_filesystems >> "$REPORT_FILE"
    print_separator
    echo "Disk Usage:" >> "$REPORT_FILE"
    print_separator
    get_disk_usage >> "$REPORT_FILE"
    print_separator
    echo "Network Configuration:" >> "$REPORT_FILE"
    print_separator
    echo "Network Interfaces:" >> "$REPORT_FILE"
    print_separator
    get_network_interfaces >> "$REPORT_FILE"
    print_separator
    echo "Firewall Rules:" >> "$REPORT_FILE"
    print_separator
    list_firewall_rules >> "$REPORT_FILE"
    print_separator
    echo "Listening Network Services and Ports:" >> "$REPORT_FILE"
    print_separator
    list_listening_ports >> "$REPORT_FILE"
    # print_separator
    # echo "Package Management Integrity:" >> "$REPORT_FILE"
    # print_separator
    # check_package_integrity >> "$REPORT_FILE"
    # print_separator
    # echo "Vulnerability Checks (CVEs):" >> "$REPORT_FILE"
    # print_separator
    # check_cve_vulnerabilities >> "$REPORT_FILE"
    print_separator
    echo "System Security Settings:" >> "$REPORT_FILE"
    check_file_permissions >> "$REPORT_FILE"
    print_separator
    check_security_configurations >> "$REPORT_FILE"
    print_separator
    # echo "Check Last 10 Logs:" >> "$REPORT_FILE"
    # print_separator
    # check_system_logs >> "$REPORT_FILE"
    print_separator
    check_security_monitoring_tools >> "$REPORT_FILE"
    echo "System report saved to $REPORT_FILE"
}

main
