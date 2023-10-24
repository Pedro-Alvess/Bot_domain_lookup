import whois
from abuse_dictionary import hosts_abuse_info

class whois_lookup():
    def __init__(self, domain):
        """
        This class is responsible for manipulating and retriving information from a domain's whois.
        """
        self.domain = whois.extract_domain(domain)
        self.info = whois.whois(self.domain)
        self.abuse_info = {'abuse link': None, 'email 1': None, 'email 2': None}

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
        
