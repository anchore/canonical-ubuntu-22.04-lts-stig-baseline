control 'SV-274867' do
  title 'Ubuntu 22.04 LTS must ensure SSSD performs certificate path validation, including revocation checking, against a trusted anchor for PKI-based authentication.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.'
  desc 'check', "Verify Ubuntu 22.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.

Verify the pam service is listed under [sssd] with the following command:

     $ sudo grep -A 1 '^\\[sssd\\]' /etc/sssd/sssd.conf
     [sssd]
     services = nss,pam,ssh

If \"pam\" is not listed in services, this is a finding.

Verify the pam service is set to use pam for smart card authentication in the [pam] section of /etc/sssd/sssd.conf with the following command:

     $ sudo grep -A 1 '^\\[pam]' /etc/sssd/sssd.conf
     [pam]
     pam_cert_auth = True

If \"pam_cert_auth = True\" is not returned, this is a finding."
  desc 'fix', 'Configure Ubuntu 22.04 LTS, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor.

Add or update the /etc/sssd/sssd.conf so that the following entries are in the correct sections of the file:

[sssd]
services = nss,pam,ssh
config_file_version = 2

[pam]
pam_cert_auth = True'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-274867'
  tag rid: 'SV-274867r1107270_rule'
  tag stig_id: 'UBTU-22-254020'
  tag fix_id: 'F-78873r1101741_fix'
  tag cci: ['CCI-000185', 'CCI-004909']
  tag nist: ['IA-5 (2) (a)', 'IA-5 (2) (b) (1)', 'IA-5 (2) (d)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command("sudo grep -A 1 '^\\[sssd\\]' /etc/sssd/sssd.conf") do
      its('stdout') { should match(/services.*=.*pam/) }
    end

    describe command("sudo grep -A 1 '^\\[pam\\]' /etc/sssd/sssd.conf") do
      its('stdout') { should match(/pam_cert_auth\s*=\s*True/) }
    end
  end
end
