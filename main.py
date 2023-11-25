from rich.console import Console
from rich.markdown import Markdown
from gpt_analysis import gpt_analysis
from database import database_handler

console = Console()
console.print(Markdown("# Welcome to the domain analysis bot\n"))
console.print("\n>>> Enter the domain for analysis: ",end="")
domain = input()

#domain = 'andrettaorganizer.com.br'

db = database_handler()

gpt_reponse = gpt_analysis(domain, db).get_reponse()
gpt_reponse = Markdown(gpt_reponse)

db.close()

console.print("\n\n")
console.print(gpt_reponse)