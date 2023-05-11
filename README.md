# Port Scanner Project
## Contributors: Sophie Song, Sylvia Tan


### Requirements:

• port_scanner.py file is required <br />
• logging, socket, scapy, datetime, argparse, random modules are required

### To run the project:

• Download the port_scanner folder
• Open a terminal / command line
• Go to the directory of the folder by typing cd port_scanner
• Type the following line to execute:
    • Python3 port_scanner.py [-mode] MODE [-order] ORDER [-ports] PORTS target_ip
    * Options for MODE:
        • normal (TCP Connect Scan)
        • syn (TCP SYN Scan)
        • fin (TCP FIN Scan)
    * Options for ORDER:
        • order (in ascending order of 0,1,2,...)
        • random (in random order)
    * Options for PORTS:
        • all (scan for all the ports, ranging from 0 to 65535)
        • known (scan for known ports only, ranging from 0 to 1023)
    * target_ip: type the IP adress of the target host for the port scan

### Reflections:

One major challenge we faced while working on the port scanner project was that the scanning took a long time. We were first confused because we couldn't get any result in the command line for about 3 minutes even for scanning 50ish ports. Later when we noticed that it does work, we tried putting timeouts of 0.5 sec on each scans, which allowed us to scan each ports a lot faster. Given that all 65535 ports should be scanned, it will take about 9 hours, which is a lot faster than how much we expect to take if we didn't have timeout calls. This also significantly reduced our time on coding because we constantly looked at the results while coding, and the results were computed a lot quicker.

### Contributions:

Sophie: 
• syn_scan, norm_scan functions
• argparse
• results printing
• comments
• README 
Sylvia:
• general structure of the codes
• fin_scan, norm_scan, port_scan functions
• argparse
• conditions for order, ports
• results printing
