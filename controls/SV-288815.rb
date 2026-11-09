control 'SV-288815' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the useradd command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
  
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "useradd" command by using the following command:  
  
$ sudo auditctl -l | grep -w useradd 
-a always,exit -S all -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-useradd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "useradd" command.   
  
Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:  
  
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd 
    
To reload the rules file, issue the following command:  
  
$ sudo augenrules --load 
 
Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  tag check_id: 'C-93504r1261431_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-288815'
  tag rid: 'SV-288815r1261433_rule'
  tag stig_id: 'UBTU-22-654126'
  tag fix_id: 'F-93409r1261432_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/usr/sbin/useradd'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  # The check text says the key is arbitrary, so it is not checked
  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
    end
  end
end
