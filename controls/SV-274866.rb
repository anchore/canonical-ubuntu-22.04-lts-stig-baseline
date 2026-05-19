control 'SV-274866' do
  title 'Ubuntu 22.04 LTS must use the "SSSD" package for multifactor authentication services.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.'
  desc 'check', 'Verify the "sssd.service" is enabled and active with the following commands:

     $ sudo systemctl is-enabled sssd
     enabled

     $ sudo systemctl is-active sssd
     active

If "sssd.service" is not active or enabled, this is a finding.'
  desc 'fix', 'Enable the "sssd.service" to start automatically on reboot with the following command:

     $ sudo systemctl enable sssd.service

Ensure the "sssd" service is running:

     $ sudo systemctl start sssd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-274866'
  tag rid: 'SV-274866r1101739_rule'
  tag stig_id: 'UBTU-22-254015'
  tag fix_id: 'F-78872r1101738_fix'
  tag cci: ['CCI-004046', 'CCI-004047', 'CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('sssd') do
    it { should be_enabled }
    it { should be_running }
  end
end
