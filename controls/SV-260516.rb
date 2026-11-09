control 'SV-260516' do
  title 'Ubuntu 22.04 LTS must have an application firewall enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the ufw is enabled on the system with the following command: 
 
    $ sudo ufw status
    Status: active
 
If the above command returns the status as "inactive" or any type of error, this is a finding. 

If the ufw is not installed, ask the system administrator if another application firewall is installed. If a different firewall is active on the system, this is not a finding.'
  desc 'fix', 'Enable the ufw by using the following command: 
 
    $ sudo ufw enable

Note: Enabling the firewall will potentially disrupt ssh sessions.'
  impact 0.5
  tag check_id: 'C-64245r1184059_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag gid: 'V-260516'
  tag rid: 'SV-260516r1184061_rule'
  tag stig_id: 'UBTU-22-251020'
  tag fix_id: 'F-64153r1184060_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  expected_firewall_package = input('expected_firewall_package')

  describe package(expected_firewall_package) do
    it { should be_installed }
  end

  if expected_firewall_package == 'ufw'
    describe 'ufw service active state' do
      subject { command('systemctl is-active ufw.service').stdout.strip }
      it { should cmp 'active' }
    end
  else
    describe service(expected_firewall_package) do
      it { should be_enabled }
      it { should be_running }
    end
  end
end
