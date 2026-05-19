control 'SV-274864' do
  title 'Ubuntu 22.04 LTS must have the "SSSD" package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the packages required for multifactor authentication installed with the following command:

     $ dpkg -l | grep sssd

If the "sssd" package is not installed, this is a finding.'
  desc 'fix', 'Install the sssd package and the required pam packages with the following commands:

     $ sudo apt install sssd

     $ sudo apt install libpam-sss

     $ sudo apt install libnss-sss'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-274864'
  tag rid: 'SV-274864r1155209_rule'
  tag stig_id: 'UBTU-22-254010'
  tag fix_id: 'F-78870r1101727_fix'
  tag cci: ['CCI-004046', 'CCI-004047', 'CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe package('sssd') do
      it { should be_installed }
    end
  end
end
