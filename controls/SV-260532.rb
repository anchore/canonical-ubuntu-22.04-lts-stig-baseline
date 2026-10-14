control 'SV-260532' do
  title 'Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions, which have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', %q(Verify the SSH server is configured to only use MACs that employ FIPS 140-3 approved ciphers by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs'
     /etc/ssh/sshd_config:MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com

If "MACs" does not contain only the hashes "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to only use MACs that employ FIPS 140-3 approved hashes.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com

Restart the SSH server for the changes to take effect:

     $ sudo systemctl reload sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-260532'
  tag rid: 'SV-260532r991554_rule'
  tag stig_id: 'UBTU-22-255055'
  tag fix_id: 'F-64169r953408_fix'
  tag cci: ['CCI-001453', 'CCI-002421', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized Ubuntu', impact: 0.0) {
    !virtualization.container_system? || file('/etc/ssh/sshd_config').exist?
  }

  approved_macs = input('approved_openssh_server_conf')['macs']
  # DISA: a finding unless MACs contains only the approved hashes in exact order.
  meets_rule = ->(value) { value == approved_macs }

  # DISA greps every file sshd reads (sshd -dd), Include targets too. `sshd -T -dd` lists them even in
  # images where sshd -T cannot finish; fall back to the default files if it lists none. Comment lines are skipped.
  config_files = command("/usr/sbin/sshd -T -dd 2>&1 | awk '/load_server_config: filename/ {print $NF}'").stdout.split
  config_files = ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/*.conf'] if config_files.empty?
  macs_lines = command("grep -iHs -E '^[[:space:]]*macs([[:space:]]|=)' #{config_files.join(' ')}").stdout.lines.map(&:strip)
  # Drop the "file:" prefix and keyword, plus a trailing comment and quotes, which sshd also ignores.
  macs_values = macs_lines.map { |l| l.sub(/\A.*?:(?=[[:space:]]*macs[[:space:]=])/i, '').strip.sub(/^macs[[:space:]=]+/i, '').sub(/[[:space:]]+#.*\z/, '').delete(%q("')).strip }.uniq

  describe 'OpenSSH server MACs in the files sshd reads' do
    it 'are set, not commented out' do
      expect(macs_values).not_to be_empty, 'No uncommented MACs line found'
    end
    it 'have no conflicting values' do
      expect(macs_values.length).to be <= 1, "Conflicting MACs lines:\n\t#{macs_lines.join("\n\t")}"
    end
    it 'match the approved list in exact order' do
      bad = macs_values.reject { |value| meets_rule.call(value) }
      expect(bad).to be_empty, "OpenSSH server MACs:\n\t#{bad.join("\n\t")}\ndo not meet the approved value:\n\t#{approved_macs}"
    end
  end

  # sshd -T reports the effective value but exits non-zero in images without /run/sshd, so use it only when it runs.
  sshd_t = command('/usr/sbin/sshd -T')
  if sshd_t.exit_status.zero?
    effective_macs = sshd_t.stdout.lines.map(&:split).find { |k, _| k == 'macs' }&.last.to_s
    describe 'Effective OpenSSH server MACs (sshd -T)' do
      it 'match the approved list in exact order' do
        expect(meets_rule.call(effective_macs)).to be(true), "Effective MACs:\n\t#{effective_macs}\ndo not meet the approved value:\n\t#{approved_macs}"
      end
    end
  end
end
