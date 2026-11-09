control 'SV-260527' do
  title 'Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.'
  desc 'check', %q(Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive by using the following command:  
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs sudo grep -iH 'clientalivecountmax' 
     /etc/ssh/sshd_config:ClientAliveCountMax 1 
 
If "ClientAliveCountMax" is not set to "1", conflicting results are returned, or it is commented out or missing, this is a finding.)
  desc 'fix', 'Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive. 
 
Note: This setting must be applied in conjunction with UBTU-22-255040 to function correctly. 
 
Add or modify the following line in the "/etc/ssh/sshd_config" file: 

ClientAliveCountMax 1 
  
Restart SSH for the changes to take effect: 

$ sudo systemctl restart ssh'
  impact 0.5
  tag check_id: 'C-64256r1208679_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag gid: 'V-260527'
  tag rid: 'SV-260527r1208681_rule'
  tag stig_id: 'UBTU-22-255030'
  tag fix_id: 'F-64164r1208680_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host'
  tag 'container-conditional'

  only_if('SSH is not installed on the system this requirement is Not Applicable', impact: 0.0) {
    service('sshd').enabled? || package('openssh-server').installed?
  }

  client_alive_count = input('sshd_client_alive_count_max')

  if virtualization.container_system?
    impact 0.0
    describe 'skip' do
      skip 'SSH configuration does not apply inside containers. This control is Not Applicable.'
    end
  else
    describe 'SSH ClientAliveCountMax configuration' do
      it "should be set to #{client_alive_count}" do
        expect(sshd_active_config.ClientAliveCountMax).to(cmp(client_alive_count), "SSH ClientAliveCountMax is commented out or not set to the expected value (#{client_alive_count})")
      end
    end
  end
end
