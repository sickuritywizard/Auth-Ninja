from termcolor import colored
import datetime

def banner():
	x="""	     _         _   _           _   _ _        _       
            / \  _   _| |_| |__       | \ | (_)_ __  (_) __ _ 
           / _ \| | | | __| '_ \ _____|  \| | | '_ \ | |/ _` |
          / ___ \ |_| | |_| | | |_____| |\  | | | | || | (_| |
         /_/   \_\__,_|\__|_| |_|     |_| \_|_|_| |_|/ |\__,_|Ⓥ ②  
                                                   |__/       
	"""
 
	y = "+------------------------------------------------------+"     

	xtime = "[-]Time: "+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	z = f"								~SICKURITY_WIZARD\n"

	print(colored(x,'blue'),end="")
	print(colored(y,'white'))
	print(colored(z,'white'))
	# print(colored(xtime,'red'))