import requests
from api_keys import public_key

class reputation_analysis():
    def __init__(self, domain):
        """
        """
        self.domain = domain
        
        self.VT_key = public_key['VirusTotal']
        self.VT_response = None

        try:
            pass
            #self.__reponse_VT()
            #commented so as not to reach the api quota limit
        except Exception as e:
             print(f"Error making a request to the VirusTotal API: {e}")


    def __reponse_VT(self):
        """
        Contact and request domain evaluation at VirusTotal.
        """
        url = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={self.VT_key}&resource={self.domain}'
        self.VT_response = requests.get(url)
        
        if self.VT_response.status_code != 200:
            raise Exception("Unable to connect to VirusTotal api.")
        else:
            self.VT_response = self.VT_response.json()

    def get_reputation_VT(self):
        """
        """

        try:
            self.reputation_VT = {
                "Reputation Score":{
                    "Bad Reputation": self.VT_response['positives'],
                    "Total verified": self.VT_response['total']
                },
                "Scanners":{}
            }

            if "scans" in self.VT_response:
                for scanner, result in self.VT_response["scans"].items():
                    if result["detected"]:
                        if result["result"] != "clean":
                            self.reputation_VT['Scanners'][scanner] = result['result']

            return self.reputation_VT
        
        except Exception as e:
            raise Exception("Error extracting data from VirusTotal report.")
        

print(reputation_analysis('arsaconcretos.com').get_reputation_VT())
            



