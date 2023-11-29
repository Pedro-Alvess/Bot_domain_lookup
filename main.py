from rich.console import Console
from rich.text import Text
from rich.markdown import Markdown
from gpt_analysis import gpt_analysis
from database import database_handler
from whois_info import whois_lookup
from httpxx import httpx_handler
from reputation import reputation_analysis
import os
import threading
import time
import keyboard



class main_handler():
    
    def __init__(self):
        """
        This class is responsible for manipulating the entire system.
        """

        self._console = Console()
        
        self._thread_key_ending = threading.Thread(target=self.__key_ending)
        self._thread_menu = threading.Thread(target=self.__menu)


        self._thread_key_ending.start()
        self._thread_menu.start()

        self._thread_menu.join()


    
    def __BMO(self, BMO_face:int):
        """
        Centers texts containing the BMO's face.
        """
        if BMO_face == 1:
            text = "(～￣▽￣)～   "
        elif BMO_face == 2:
            text = "（￣︶￣）↗　  "
        elif BMO_face == 3:
            text = "`(*>﹏<*)′　  "
        elif BMO_face == 4:
            text = "(✿ ◡ ‿ ◡ )   "
        elif BMO_face == 5:
            text = "ψ(｀∇´)ψ  "
        elif BMO_face == 6:
            text = "(￣y▽ ￣)╭    "


        widt = self._console.width

        initial_pos = (widt - len(text)) // 2
        bmo_text = Text()
        bmo_text.append(" " * initial_pos)

        return bmo_text.append(text)


    def __menu(self):
        """
        Generates the bot's main menu.
        """
        os.system('clear')
        
        self._console.print("**Pressione “esc” para encerrar o programa.\n")
        
        self._console.print(Markdown("# BMO - Análise de domínio\n"))
        self._console.print(self.__BMO(BMO_face = 1))

        self._console.print("Selecione uma opção:\n")

        self._console.print("1. Análise de domínio completo.")
        self._console.print("2. Análise de domínio personalizado.")
        self._console.print("3. Apagar informações do banco de dados.")

        self._console.print("\n\n>>> Escolha a opção desejada (número): ",end="")

        response = input()

        if response == "1": # 1. Análise de domínio completo.
            os.system('clear')

            self._console.print(Markdown("# Análise de domínio completo.\n"))
            self._console.print(self.__BMO(BMO_face = 6))
            self._console.print("\n>>> Insira o domínio para análise: ",end="")

            self._domain = input()

            gpt_reponse = gpt_analysis(self._domain).get_reponse()
            gpt_reponse = Markdown(gpt_reponse)

            self._console.print("\n\n")
            self._console.print(gpt_reponse)

            self.__loop()
            
        elif response == "2": # 2. Análise de domínio personalizado.
            os.system('clear')

            self._console.print(Markdown("# Análise de domínio personalizado\n"))
            self._console.print(self.__BMO(BMO_face = 2))

            self._console.print("\nInforme os módulos que gostaria de desabilitar:\n")

            self._console.print("1. Análise do GPT.")
            self._console.print("2. Informações do Virus Total.")
            self._console.print("3. Informações do Whois.")
            self._console.print("4. Informações de Abuso do Domínio.")
            self._console.print("5. Screenshot.")
            self._console.print("6. Tecnologias Usadas.")
            self._console.print("7. Informações do DNS. ")

            self._console.print("\n\n>>> Informe os números separados por vírgula, dos módulos que serão desabilitados: ",end="")
            response = input()

            response = response.split(',')

            virustotal = True
            whois = True
            whois_abuse = True
            screenshot = True
            technology = True
            DNS_info = True

            if "2" in response:
                virustotal = False
            if "3" in response:
                whois = False
            if "4" in response:
                whois_abuse = False
            if "5" in response:
                screenshot = False
            if "6" in response:
                technology = False
            if "7" in response:
                DNS_info = False

            self._console.print("\n\n>>> Insira o domínio para análise: ",end="")

            self._domain = input()


            if not "1" in response:
                gpt_reponse = gpt_analysis(self._domain,virustotal,whois,whois_abuse,screenshot,technology,DNS_info).get_reponse()
                gpt_reponse = Markdown(gpt_reponse)

                self._console.print("\n\n")

                self._console.print(gpt_reponse)
                

                self.__loop()
            else:
                with self._console.status("[bold green]Working on tasks...") as status:
                    
                    reputation = reputation_analysis(self._domain)
                    httpx = httpx_handler(self._domain)
                    whois_info = whois_lookup(self._domain)
                    

                    if not "2" in response: #virustotal 
                        self._console.print(Markdown("# Informações do VirusTotal\n"))
                        self.__print_nested_dict(reputation.get_reputation_VT())

                    if not "3" in response: #whois
                        self._console.print(Markdown("# Informações do whois\n"))
                        self.__print_nested_dict(whois_info.get_whois())

                    if not "4" in response: #whois_abuse
                        self._console.print(Markdown("# Informações de contato de abuso \n"))
                        self.__print_nested_dict(whois_info.get_abuse_contact())

                    if not "5" in response: #screenshot
                        self._console.print(Markdown("# Screenshot\n"))
                        httpx.generate_screenshot()
                        httpx.open_img()
                        self._console.print(Markdown(f"Caminho da imagem: {httpx.get_ss_path()}\n"))

                    if not "6" in response: #technology
                        self._console.print(Markdown("# Tecnologias usadas no domínio \n"))
                        self._console.print(httpx.get_technology())

                    if not "7" in response: #DNS_info
                        self._console.print(Markdown("# Informações do DNS \n"))
                        self.__print_nested_dict(whois_info.get_dns_info())

                
                self.__loop()



        elif response == "3": # 3. Apagar banco de dados.
            os.system('clear')

            self._console.print(Markdown("# Apagar informações do banco de dados.\n"))
            self._console.print(self.__BMO(BMO_face = 3))

            self._console.print("Esta ação irá apagar todos os dados do banco de dados.\n")
            print(">>> Você deseja prosseguir ? [s/n] ", end="")
            
            response = input()

            if response.upper() == 'S':
                os.system('clear')

                db = database_handler()
                db.del_all()
                db.close()

                self._console.print(self.__BMO(BMO_face = 5))
                self._console.print("Todos os dados do banco foram deletados.\n\n")
                time.sleep(2)

                self.__loop()

            else:
                os.system('clear')
                self._console.print("Operação cancelada!")
                self._console.print(self.__BMO(BMO_face = 4))
                time.sleep(2)

                self.__loop()

        else:
            print("\n\nERROR: Valor de entrada invalida...")
            self.__loop()
        
        

    def __loop(self):
        """
        This function is responsible for opening the main menu again.
        """
        self._console.print("\n\n>>> Você deseja voltar para o menu principal ? (s/n) ",end="")
        response = input()
        
        if response.upper() == "S":
            self.__menu()
        
        else:
            print("\n\nPrograma encerrado...")

            os.kill(os.getpid(), 2)

    def __print_nested_dict(self, dic, indent=0):
        """
        Transforms information from dictionaries into indented texts.
        """

        for key, value in dic.items():
            print("")
            if isinstance(value, dict):
                print("  " * indent + f"{key}:")
                self.__print_nested_dict(value, indent + 1)

            elif isinstance(value, list):
                print("  " * indent + f"{key}:")
                for item in value:
                    print("  " * (indent + 1) + f"- {item}")
            else:
                print("  " * indent + f"{key}: {value}")

    def __key_ending(self):
        """
        This function is responsible for interrupting the program if the "esc" key is pressed.
        """
        keyboard.wait("esc")

        print("\n\nTecla 'esc' pressionada. Encerrando programa...")
        
        os.kill(os.getpid(), 2)



main_handler()

