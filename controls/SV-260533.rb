control 'SV-260533' do
  title 'Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', %q(Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms'
     /etc/ssh/sshd_config:KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the SSH server for changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-64262r953410_chk'
  tag severity: 'medium'
  tag gid: 'V-260533'
  tag rid: 'SV-260533r958408_rule'
  tag stig_id: 'UBTU-22-255060'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-64170r953411_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  # Not applicable in containers when OpenSSH server is not installed
  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !virtualization.container_system? || package('openssh-server').installed?
  }

  expected_kex = input('expected_kex')
  # DISA: a finding unless KexAlgorithms contains only the approved algorithms in exact order.
  meets_rule = ->(value) { value.split(',') == expected_kex }

  # DISA greps every file sshd reads (sshd -dd), Include targets too. `sshd -T -dd` lists them even in
  # images where sshd -T cannot finish; fall back to the default files if it lists none. Comment lines are skipped.
  config_files = command("/usr/sbin/sshd -T -dd 2>&1 | awk '/load_server_config: filename/ {print $NF}'").stdout.split
  config_files = ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/*.conf'] if config_files.empty?
  kex_lines = command("grep -iHs -E '^[[:space:]]*kexalgorithms([[:space:]]|=)' #{config_files.join(' ')}").stdout.lines.map(&:strip)
  # Drop the "file:" prefix and keyword, plus a trailing comment and quotes, which sshd also ignores.
  kex_values = kex_lines.map { |l| l.sub(/\A.*?:(?=[[:space:]]*kexalgorithms[[:space:]=])/i, '').strip.sub(/^kexalgorithms[[:space:]=]+/i, '').sub(/[[:space:]]+#.*\z/, '').delete(%q("')).strip }.uniq

  describe 'SSHD KexAlgorithms in the files sshd reads' do
    it 'are set, not commented out' do
      expect(kex_values).not_to be_empty, 'No uncommented KexAlgorithms line found'
    end
    it 'have no conflicting values' do
      expect(kex_values.length).to be <= 1, "Conflicting KexAlgorithms lines:\n\t#{kex_lines.join("\n\t")}"
    end
    it 'match the approved list in exact order' do
      bad = kex_values.reject { |value| meets_rule.call(value) }
      expect(bad).to be_empty, "SSHD KexAlgorithms:\n\t#{bad.join("\n\t")}\ndo not meet the approved value:\n\t#{expected_kex.join(',')}"
    end
  end

  # sshd -T reports the effective value but exits non-zero in images without /run/sshd, so use it only when it runs.
  sshd_t = command('/usr/sbin/sshd -T')
  if sshd_t.exit_status.zero?
    effective_kex = sshd_t.stdout.lines.map(&:split).find { |k, _| k == 'kexalgorithms' }&.last.to_s
    describe 'Effective SSHD KexAlgorithms (sshd -T)' do
      it 'match the approved list in exact order' do
        expect(meets_rule.call(effective_kex)).to be(true),"Effective KexAlgorithms:\n\t#{effective_kex}\ndo not meet the approved value:\n\t#{expected_kex.join(',')}"
      end
    end
  end
end
