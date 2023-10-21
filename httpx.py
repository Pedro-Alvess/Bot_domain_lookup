import subprocess
import os
import whois

class httpx_handler():
    def __init__(self, domain):
        """
        It manipulates the httpx library, being able to take screenshots of web pages and identify the technologies used.
        """
        self._ss_command = f'httpx -screenshot -u {domain} -silent'
        self._td_command = f'httpx -td -u {domain} -silent'
        self._url = self.__get_url(domain)
        self._ss_path = f'output\\screenshot\\{self._url}'

    def get_ss_path(self):
        """
        Returns the path of the screenshot.
        """
        current_dir = f'{os.getcwd()}'
        return f'{current_dir}\\{self._ss_path}'
    
    def get_ss_relative_path(self):
        """
        Returns the relative path of the screenshot folder.
        """
        return self._ss_path

    def __get_url(self, domain):
        """
        Identifies the name of the file according to the searched domain.
        """

        if domain[:5] == "https" or domain[:4] == "http":
            parts = f'{domain}'.split('/')

            return parts[2]
        elif domain[:3] == 'www':
            parts = f'{domain}'.split('/')

            return parts[0]
        else:
            return f'{whois.extract_domain(domain)}'


    def get_screenshot(self):
        """
        Renders the DOM file with the help of the HTTPX tool, to generate a screenshot. 
        """
        try:
            subprocess.run(self._ss_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if not (os.path.exists(self._ss_path) and os.path.isdir(self._ss_path)):
                raise Exception("Couldn't get a screenshot of the page.")

        except subprocess.CalledProcessError as e:
            error_message = "The go tool has not been properly installed.\n\n" \
                "To install Go, please follow the official installation link: https://golang.org/dl/\n\n" \
                "After installing Go, you can install the httpx library with the following command:\n" \
                "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"


            print(f"Error: {e.args[-1]}")
            print(error_message)
        
        except Exception as e:
            print(f"Error: {e.args[-1]}")

    def get_technology(self):
        """
        Returns the technologies found on the site.
        """
        try:
            result = subprocess.run(self._td_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            output = result.stdout

            return output

        except subprocess.CalledProcessError as e:
            error_message = "The go tool has not been properly installed.\n\n" \
                "To install Go, please follow the official installation link: https://golang.org/dl/\n\n" \
                "After installing Go, you can install the httpx library with the following command:\n" \
                "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"


            print(f"Error: {e.args[-1]}")
            print(error_message)
