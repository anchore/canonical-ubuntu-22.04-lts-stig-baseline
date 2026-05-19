control 'SV-279937' do
  title 'Ubuntu 22.04 LTS must not have the nfs-kernel-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', "Verify that Ubuntu 22.04 LTS does not have nfs packages installed.

Check if packages are installed:
     $ sudo dpkg -l | grep -E 'nfs-common|nfs-kernel-server'

If the nfs-common or nfs-kernel-server packages are installed, this is a finding."
  desc 'fix', 'Configure the Ubuntu operating system to disable nonessential capabilities by removing the nfs-common and nfs-kernel-server packages from the system with the following commands:

     $ sudo apt purge --yes nfs-common nfs-kernel-server

     $ sudo apt autoremove --yes'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-279937'
  tag rid: 'SV-279937r1156364_rule'
  tag stig_id: 'UBTU-22-215040'
  tag fix_id: 'F-84402r1156363_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('nfs-kernel-server') do
    it { should_not be_installed }
  end

  describe package('nfs-common') do
    it { should_not be_installed }
  end
end
