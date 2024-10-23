# ADSetupFull

### An Automated PowerShell Script for Active Directory Domain Configuration

Welcome to **ADSetupFull**, a comprehensive PowerShell script designed to automate the entire setup process of an Active Directory (AD) environment. From setting up the domain controller and configuring DNS, to managing domain users, password policies, and network configurations, this script ensures a seamless AD deployment experience. Perfect for setting up test labs, enterprise environments, or automating domain management!

## Features

- **Dynamic Configuration**: Prompt-based input for all key configurations such as IP addresses, domain names, NetBIOS names, and administrator credentials.
- **Automated AD Setup**: Installs and configures Active Directory Domain Services (AD DS) and DNS, creating a fully functional domain environment.
- **Network Configuration**: Ensures static IP settings, DNS configurations, and primary DNS suffixes match domain requirements.
- **Remote Desktop Configuration**: Easily enables and configures Remote Desktop on the domain controller for remote administration.
- **Firewall Management**: Automatically sets up firewall rules necessary for Active Directory, DNS, and file sharing services.
- **Domain User and Group Management**: Automates the creation of users and groups, ensuring proper permissions and password policies are enforced.
- **File Share Setup**: Configures file shares that are accessible to all domain users, providing shared storage resources.
- **Domain Health Checks**: Runs a comprehensive health check on the domain controller to ensure everything is functioning properly.
- **Client Domain Join**: Seamlessly joins Windows 10 clients to the domain using the script, ensuring consistent network and DNS settings.
- **Custom Domain Account Propagation**: Creates and propagates domain accounts across the network with user-defined configurations.

## Installation and Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/ADSetupFull.git
