# Port Scanner Project
## Contributors: Sophie Song, Sylvia Tan


### Requirements:

- `port_scanner.py` file is required <br />
- `logging`, `socket`, `scapy`, `datetime`, `argparse`, `random` modules are required

### To run the project:

- Download the port_scanner folder <br />
- Open a terminal / command line <br />
- Go to the directory of the folder by typing `cd port_scanner` <br />
- Type the following line to execute: <br />
    <br />
    * `Python3 port_scanner.py [-mode] MODE [-order] ORDER [-ports] PORTS target_ip` <br />
    <br />
    - Options for MODE:<br />
     * `normal` (TCP Connect Scan)<br />
     * `syn` (TCP SYN Scan)<br />
     * `fin` (TCP FIN Scan)<br />
    - Options for ORDER:<br />
     * `order` (in ascending order of 0,1,2,...)<br />
     * `random` (in random order)<br />
    - Options for PORTS:<br />
     * `all` (scan for all the ports, ranging from 0 to 65535)<br />
     * `known` (scan for known ports only, ranging from 0 to 1023)<br />
    - `target_ip`: type the IP adress of the target host for the port scan<br />

### Reflections:

One major challenge we faced while working on the port scanner project was that the scanning took a long time. We were first confused because we couldn't get any result in the command line for about 3 minutes even for scanning 50ish ports. Later when we noticed that it does work, we tried putting timeouts of 0.5 sec on each scans, which allowed us to scan each ports a lot faster. Given that all 65535 ports should be scanned, it will take about 9 hours, which is a lot faster than how much we expect to take if we didn't have timeout calls. This also significantly reduced our time on coding because we constantly looked at the results while coding, and the results were computed a lot quicker.

### Contributions:

Sophie: <br />
• syn_scan, norm_scan functions<br />
• argparse<br />
• results printing<br />
• comments<br />
• README <br />
Sylvia:<br />
• general structure of the codes<br />
• fin_scan, norm_scan, port_scan functions<br />
• argparse<br />
• conditions for order, ports<br />
• results printing<br />
