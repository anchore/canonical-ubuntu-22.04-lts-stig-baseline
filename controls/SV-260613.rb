control 'SV-260613' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to audit the execution of the module management program "kmod" by using the following command:

     $ sudo auditctl -l | grep kmod
     -w /bin/kmod -p x -k module

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of the module management program "kmod".

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /bin/kmod -p x -k modules

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-64342r953650_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag gid: 'V-260613'
  tag rid: 'SV-260613r991586_rule'
  tag stig_id: 'UBTU-22-654055'
  tag fix_id: 'F-64250r953651_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/bin/kmod'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('x')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
