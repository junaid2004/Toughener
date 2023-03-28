import socket
import ssl
import argparse
import os
import openai
import PyPDF2
from fpdf import FPDF

company = "Demo Company"

# Define a list of vulnerable ports and their associated vulnerabilities
vulnerable_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC"
}

# Define a dictionary of known vulnerabilities
known_vulnerabilities = {
    "FTP": ["Anonymous Login", "Weak Passwords"],
    "SSH": ["Weak Passwords", "OpenSSH 4.3p2 Backdoor"],
    "Telnet": ["Weak Passwords"],
    "SMTP": ["Open Relay"],
    "DNS": ["DNS Spoofing"],
    "HTTP": ["SQL Injection", "Cross-Site Scripting", "Directory Traversal"],
    "POP3": ["Weak Passwords"],
    "IMAP": ["Weak Passwords"],
    "HTTPS": ["Heartbleed Bug"],
    "MySQL": ["Weak Passwords"],
    "RDP": ["Weak Passwords"],
    "PostgreSQL": ["Weak Passwords"],
    "VNC": ["Weak Passwords"]
}

# Define a function to scan a port for vulnerabilities
def scan_port(target_host, port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout to prevent the scanner from hanging
        sock.settimeout(1)

        # Connect to the port
        sock.connect((target_host, port))

        # If the connection succeeds, the port is open
        if port in vulnerable_ports:
            # If the port is vulnerable, print the associated vulnerability
            vulnerability = vulnerable_ports[port]
            open_ports.append(port)

            # If the vulnerability is known, print the associated details
            if vulnerability in known_vulnerabilities:
                for v in known_vulnerabilities[vulnerability]:
                    pass

        else:
            # If the port is not vulnerable, add it to the list of open ports
            open_ports.append(port)

        # Close the connection
        sock.close()

    except:
        # If the connection fails, the port is closed
        pass

# Define the main function
def main():
    global open_ports

    # Parse the command-line arguments
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("host", help="The target host to scan")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS encryption")
    args = parser.parse_args()

    # Determine the target port range
    if args.ssl:
        target_ports = range(1, 443)
    else:
        target_ports = range(1, 65536)

    # Scan each port in the target range
    open_ports = []
    for port in target_ports:
        scan_port(args.host, port)

    # Print the vulnerable ports
    for port, vulnerability in vulnerable_ports.items():
        if port in open_ports:
            pass

    # Print all the open ports in one line
    open_ports_str = ", ".join(str(p) for p in open_ports)

    #code for reccomendation

    openai.api_key = "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"

    response = openai.Completion.create(
      model="text-davinci-003",
      #prompt= "just write test",
      prompt=f"write 15 security recommendation for a Windows-based system where PORTS {open_ports_str} are open each recommendation 35 words or more in size ",
      temperature=0.7,
      max_tokens=1000,
      top_p=1,
      frequency_penalty=0,
      presence_penalty=0
    )

    output_text = response.choices[0].text
    #print(output_text)
    #code for reprot 

    # Set up the PDF object
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', size=12)

    # Add the text to the PDF
    pdf.multi_cell(0, 10, output_text)

    # Save the PDF file
    pdf.output("recommendations.pdf", "F")


    #code for CVSS score 
    #print(f"Number of open ports: {len(open_ports)}")

    NumberOfPorts = len(open_ports)
    #print(NumberOfPorts)
    Formula = NumberOfPorts * 2
    #print(Formula)
    CVss_score = 100 - Formula
    #print(CVss_score)

    # Create a Audit certificate 
    class Certificate(FPDF):
        def __init__(self, companyname, OS, cvssscore):
            super().__init__('L', 'mm', 'A4')
            self.companyname = companyname
            self.OS = OS
            self.cvssscore = cvssscore

        def create_certificate(self):
            # Add a new page
            self.add_page()

            # Set the background color
            self.set_fill_color(200, 200, 200)
            self.rect(0, 0, 297, 210, 'F')

            # Add a border
            self.set_line_width(1)
            self.set_draw_color(0, 0, 0)
            self.rect(5.0, 5.0, 287.0, 200.0)

            # Set the font and size
            self.set_font('Arial', 'B', 24)

            # Add the title
            self.cell(0, 40, 'Security Audit Certificate', 0, 1, 'C')

            # Set the font and size for the name
            self.set_font('Arial', '', 18)

            # Add the name
            self.cell(0, 40, f'This is to certify that {self.companyname}', 0, 1, 'C')

            # Add the course name
            self.cell(0, 40, f'has successfully completed the security Audit for {self.OS}', 0, 1, 'C')

            # Add the CVSS score
            self.cell(0, 40, f'CVSS score: {self.cvssscore}', 0, 1, 'C')
    cert = Certificate(company, "20202020", CVss_score)
    cert.create_certificate()
    cert.output('Audit_cert.pdf', 'F')

# Call the main function
if __name__ == "__main__":
    main()
