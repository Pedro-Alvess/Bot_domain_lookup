import whois
import dns.resolver
from abuse_dictionary import hosts_abuse_info

class whois_lookup():
    def __init__(self, domain):
        """
        This class is responsible for manipulating and retriving information from a domain's whois.
        """
        self.domain = whois.extract_domain(domain)
        self.info = whois.whois(self.domain)
        self.abuse_info = {'abuse link': None, 'email 1': None, 'email 2': None}
        self._dns_info = {'A': [], 'MX': [], 'NS': [], 'SOA': []}

    def get_whois(self):
        """
        Return a dictionary with whois information.
        """
        return self.info
    
    def get_abuse_contact(self):
        """
        Return a dictionary with abuse contact.
        """
        if self.domain[-3:] == '.br':

            self.abuse_info['abuse link'] = 'http://www.cert.br/'
            self.abuse_info['email 1'] = 'cert@cert.br'
            self.abuse_info['email 2'] = 'mail-abuse@cert.br'
            
            return self.abuse_info

        elif 'whois_server' in self.info:
            host = self.info['whois_server']

            if host in hosts_abuse_info:

                self.abuse_info['abuse link'] = hosts_abuse_info[host]['abuse link']
                self.abuse_info['email 1'] = hosts_abuse_info[host]['email 1']
                self.abuse_info['email 2'] = hosts_abuse_info[host]['email 2']
            
            return self.abuse_info
        else:
            return None
    
    def get_dns_info(self):
        record_types = ['A', 'MX', 'NS', 'SOA']

        for record_type in record_types:
            try: 
                response = dns.resolver.resolve(self.domain, record_type)

                for record in response:
                    dns_record = {'Value': str(record)}  # Converta o valor para string
                    if hasattr(record, 'ttl'):
                        dns_record['TTL'] = record.ttl

                    self._dns_info[record_type].append(dns_record) 
            
            except dns.resolver.NXDOMAIN:
                print('ERROR: DNS Info - Domain not found')
                continue

            except dns.resolver.NoAnswer:
                print(f'ERROR: DNS Info - No records of "{record_type}" type to the domain {self.domain}')
                continue
       
            except dns.resolver.NoNameservers:
                print('DNS severs not available')
                continue
    
            except Exception as e:
                print(f'ERROR: DNS Info - type "{record_type}" - {e}')
                continue
    
        
        return self._dns_info
