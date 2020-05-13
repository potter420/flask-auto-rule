import itertools
import re
import boto3

class SecurityRules():
    def __init__(self):
        self.ec2Client = boto3.client('ec2')
        self.refresh_rules()
    
    def normalize_rules(self):
        return list(itertools.chain.from_iterable(
            [[dict(**iprange, FromPort = permission.get('FromPort',None),
                    ToPort = permission.get('FromPort',None), IpProtocol = permission.get('IpProtocol',None)) 
                  for iprange in permission['IpRanges']] 
                 for permission in self.securityGroup['SecurityGroups'][0]['IpPermissions']])
            )
    
    def refresh_rules(self):
        self.securityGroup = self.ec2Client.describe_security_groups()
        self.groupId = self.securityGroup['SecurityGroups'][0]['GroupId']
        self.normalizedRules = self.normalize_rules()
        return 0
    
    def query_rules(self, keyword, by = 'Description'):
        if by == 'Description':
            pattern = re.compile(keyword)
            return [rule for rule in self.normalizedRules if pattern.search(rule[by])]
        else:
            raise NotImplementedError('Query by %s is not implemented' %by)
            
    def authorize_rule(self, ipPermissions):
        self.ec2Client.authorize_security_group_ingress(
            GroupId = self.groupId,
            IpPermissions = ipPermissions
        )
    
    def revoke_rule(self, ipPermissions):
        self.ec2Client.revoke_security_group_ingress(
            GroupId = self.groupId,
            IpPermissions = ipPermissions
        )
    
    def update_rule_by_description(self, description, ipRanges):
        rule = {'CidrIp': None,
                'Description': None,
                'FromPort': None,
                'ToPort': None,
                'IpProtocol': None}
        if self.query_rules(description):
            rule = self.query_rules(description)[0]
            oldIpPermissions=[
                {
                    'FromPort': rule['FromPort'] or 5555,
                    'IpProtocol': rule['IpProtocol'] or 'tcp',
                    'IpRanges': [
                        {
                            'CidrIp': rule['CidrIp'],
                            'Description': rule['Description'],
                        },
                    ],
                    'ToPort': rule['ToPort'] or 5555,
                },
            ]
            self.revoke_rule(oldIpPermissions)
        
        newIpPermissions=[
            {
                'FromPort': rule['FromPort'] or 0,
                'IpProtocol': rule['IpProtocol'] or '-1',
                'IpRanges': [
                    {
                        'CidrIp': ipRanges,
                        'Description': rule['Description'] or description.replace('(?i)',''),
                    },
                ],
                'ToPort': rule['ToPort'] or 0,
            },
        ]
        
        
        self.authorize_rule(newIpPermissions)
        self.refresh_rules()