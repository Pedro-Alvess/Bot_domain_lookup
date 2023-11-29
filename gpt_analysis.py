import openai
from reputation import reputation_analysis
from whois_info import whois_lookup
from httpxx import httpx_handler
from api_keys import public_key
from rich.console import Console
import threading
import os
from database import database_handler


class gpt_analysis():
    
    def __init__(self, domain:str, virustotal = True, whois = True, whois_abuse = True, screenshot = True, technology = True, DNS_info = True):
        """
        This module retrieves information from all the other modules 
        and at the end summarizes a descriptive report on the case.
        """
        self._gpt = openai
        self._gpt.api_key = public_key['ChatGPT']
        self._domain = domain

        self._vt_status = virustotal
        self._wh_status = whois
        self._wh_ab_status = whois_abuse
        self._ss_status = screenshot
        self._tc_status = technology
        self._dns_info = DNS_info

        self._gpt_prompt = f"Crie um breve relatorio explicativo para o domínio {domain}, considerando as informações a seguir:"

        self._whois = whois_lookup(self._domain)
        self._httpx = httpx_handler(self._domain)
        self._db = database_handler()

        self._console = Console()

    def __function_handler(self):
        """
        This method is responsible for validating and calling all the other modules 
        that will serve as input for the GPT chat analysis.
        """

        #
        # The order in which the information is entered into 'self._gpt_prompt' directly
        # affects the order in which the data is displayed.
        #
        
        if self._wh_status:
            self._console.log("Validating Whois information...")
            self._gpt_prompt += f"\nInformações do Whois: {self._whois.get_whois()}"
        
        if self._dns_info:
            self._console.log("Validating DNS information...")
            self._gpt_prompt += f"\nInformações do DNS: {self._whois.get_dns_info()}"

        if self._wh_ab_status:
            wh_ab_response = self._whois.get_abuse_contact()

            if wh_ab_response != None:
                self._gpt_prompt += f"\nInformações para abuso do domínio: {wh_ab_response}"

        if self._vt_status:
           self._console.log("Validating VirusTotal information...")
           self._vt_response = reputation_analysis(self._domain).get_reputation_VT()

           if self._vt_response != None:
               self._gpt_prompt += f"\nReputação no VirusTotal: {self._vt_response}"
        
        if self._tc_status:
            self._console.log("Validating technologies used on the page...")
            tc_response = self._httpx.get_technology()

            if tc_response != None:
                self._gpt_prompt += f"\nTecnologias que a página utiliza: {tc_response}"
        
        if self._ss_status:
            self._console.log("Rendering images...")
            self._httpx.generate_screenshot()

            ss_reponse = self._httpx.get_ss_path()
            if ss_reponse != None:
                self._gpt_prompt += f"\nCaminho para visualizar a screenshot da página web: {ss_reponse}"
                
                self._console.log("Loading image...")
                threading.Thread(target=self._httpx.open_img()) #Executes the function of opening the image in a different thread.      



    def get_reponse(self):
        """
        This function is responsible for generating the domain health report with the help of GPT Chat.
        """
        with self._console.status("[bold green]Working on tasks...") as status:
            self.__function_handler()

            self._console.log("Summarizing answer...")
            gpt_reponse = self._gpt.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Você é um assistente de cybersecurity, experiente em analisar dados de dominios como whois, reputação do Virus Total e informações do DNS para gerar relatórios breves sobre a saúde do domínio/URL investigado. Ao final da exposição dos dados analisados você sempre faz um teste de análise completa sobre o caso, correlacionando os dados das ferramentas e ao final apresenta um disclaimer solicitando análise de outro analistas de segurança. Toda a sua resposta deverá ser formatada com os marcadores de markdown e pode conter emojis ao longo do relatório. Após o título e antes do resto da análise e exposição das informações, você sempre irá destacar a classificação do domínio/URL em uma das três categorias: “Malicioso”, “Suspeito” ou “Não Malicioso”. Não se esqueça de colocar o título: “Análise preliminar”."},
                    {"role": "user", "content": self._gpt_prompt}
                    ]
                )
        
        gpt_reponse = gpt_reponse.choices[0].message["content"]
        
        self._console.log("Saving data...")
        if self._vt_status:
            self._db.insert_data(self._domain, gpt_reponse, self._vt_response)
            self._db.close()
            
        else:
            self._db.insert_data(self._domain, gpt_reponse)
            self._db.close()

        return gpt_reponse





