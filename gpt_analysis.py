import openai
from reputation import reputation_analysis
from whois_info import whois_lookup
from httpx import httpx_handler
from api_keys import public_key

class gpt_analysis():
    
    def __init__(self, domain:str, virustotal = True, whois = True, whois_abuse = True, screenshot = True, technology = True):
        """
        """
        self._gpt = openai
        self._gpt.api_key = public_key['ChatGPT']
        self._domain = domain

        self._vt_status = virustotal
        self._wh_status = whois
        self._wh_ab_status = whois_abuse
        self._ss_status = screenshot
        self._tc_status = technology

        self._gpt_prompt = f"Crie um breve relatorio explicativo para o domínio {domain}, considerando as informações a seguir:"

        self._whois = whois_lookup(self._domain)
        self._httpx = httpx_handler(self._domain)

    def __function_handler(self):
        """
        This method is responsible for validating and calling all the other modules 
        that will serve as input for the GPT chat analysis.
        """

        if self._wh_status:
            print("Validating Whois information...")
            self._gpt_prompt += f"\nInformações do Whois: {self._whois.get_whois()}"
        
        if self._wh_ab_status:
            wh_ab_response = self._whois.get_abuse_contact()

            if wh_ab_response != None:
                self._gpt_prompt += f"\nInformações para abuso do domínio: {wh_ab_response}"

        if self._vt_status:
           print("Validating VirusTotal information...")
           vt_response = reputation_analysis(self._domain).get_reputation_VT()

           if vt_response != None:
               self._gpt_prompt += f"\nReputação no VirusTotal: {vt_response}"
        
        if self._tc_status:
            print("Validating technologies used on the page...")
            tc_response = self._httpx.get_technology()

            if tc_response != None:
                self._gpt_prompt += f"\nTecnologias que a página utiliza: {tc_response}"
        
        if self._ss_status:
            print("Rendering images...\n\n")
            self._httpx.generate_screenshot()

            ss_reponse = self._httpx.get_ss_path()
            if ss_reponse != None:
                self._gpt_prompt += f"\nCaminho para visualizar a screenshot da página web: {ss_reponse}"


    def get_reponse(self):
        """
        """
        self.__function_handler()

        print("Summarizing answer...")
        gpt_reponse = self._gpt.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Você é um assistente de cybersecurity, experiente em analisar dados de dominios como whois e a reputação do Virus Total para gerar relatórios breves sobre a saúde do domínio investigado. Ao final da exposição dos dados analisados você sempre faz um teste de análise sobre o caso e apresenta um disclaimer solicitando análise de outro analistas de segurança. "},
                {"role": "user", "content": self._gpt_prompt}
                ]
            )
        
        return gpt_reponse.choices[0].message["content"]






