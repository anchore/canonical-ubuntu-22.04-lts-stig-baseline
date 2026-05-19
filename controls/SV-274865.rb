control 'SV-274865' do
  title 'Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command:

     $ grep -i ldap_user_certificate /etc/sssd/sssd.conf
     ldap_user_certificate=userCertificate;binary

If the "ldap_user_certificate" option is not set to "userCertificate;binary", this is a finding.'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

     ldap_user_certificate=userCertificate;binary'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-274865'
  tag rid: 'SV-274865r1101731_rule'
  tag stig_id: 'UBTU-22-254030'
  tag fix_id: 'F-78871r1101730_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe file('/etc/sssd/sssd.conf') do
      it { should exist }
      its('content') { should match(/ldap_user_certificate\s*=\s*userCertificate;binary/) }
    end
  end
end
