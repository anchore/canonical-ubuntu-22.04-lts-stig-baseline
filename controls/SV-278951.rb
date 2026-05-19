control 'SV-278951' do
  title 'Ubuntu 22.04 LTS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

The support status of the OS depends on its subscription status.

End of life dates for Ubuntu 22.04 releases are as follows:
Standard Support: April 2027
Extended Security Maintenance (ESM): April 2032'
  desc 'check', 'Verify the version of Ubuntu 22.04 LTS is vendor supported with the following command:

     $ grep DISTRIB_DESCRIPTION /etc/lsb-release
     DISTRIB_DESCRIPTION="Ubuntu 22.04.1 LTS"

Check the subscription status of the system with the following command:
     $ pro status

If the installed version of Ubuntu 22.04 LTS is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of Ubuntu 22.04 LTS.'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-278951'
  tag rid: 'SV-278951r1155215_rule'
  tag stig_id: 'UBTU-22-211000'
  tag fix_id: 'F-83390r1135402_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/lsb-release') do
    its('DISTRIB_ID') { should cmp 'Ubuntu' }
    its('DISTRIB_RELEASE') { should cmp '22.04' }
  end
end
