control 'SV-274861' do
  title 'The operating system must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify the operating system restricts privilege elevation to authorized personnel with the following command:

     $ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Configure the operating system to restrict privilege elevation to authorized personnel.

Remove the following entries from the /etc/sudoers file or any configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-274861'
  tag rid: 'SV-274861r1101704_rule'
  tag stig_id: 'UBTU-22-654224'
  tag fix_id: 'F-78867r1101703_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  describe command("sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'") do
    its('stdout') { should_not match(/ALL\s+ALL=\(ALL\)\s+ALL/) }
    its('stdout') { should_not match(/ALL\s+ALL=\(ALL:ALL\)\s+ALL/) }
  end
end
