#!/usr/bin/env python3

import yaml, time, socket, os, sys, datetime, csv, re, subprocess
import random, string, argparse

# Here we define some functions we will use during analysis of IPs

def cdrive(host):
	command = 'net use m: \\\\' + host + '\c$'
	#if args.vlevel > 1:print(command)
	return subprocess.call(command) == 0
	
	# For testing purposes only
	#return random.choice([True, False])



def randomstring(stringLength=12):
	chars = ('abcdef0123456789')
	fakemac = ''.join(random.choice(chars) for i in range(stringLength))
	return "x" + fakemac

#

def ping(host):
	"""
	Returns True if host (str) responds to a ping request.
	Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
	"""
	# Option for the number of packets as a function of
	param = '-n' if os.system().lower()=='windows' else '-c'

	# Building the command. Ex: "ping -c 1 google.com"
	command = ['ping', '-n', '1', host]
	return subprocess.call(command) == 0
	
	#For testing purposes only
	# return random.choice([True, False])

#

def isOpen(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(3)
	try:
		s.connect((ip, int(port)))
		s.shutdown(socket.SHUT_RDWR)
		return True
	except:
		return False
	finally:
		s.close()
		
	# For testing purposes only
	# return random.choice([True, False])

# Get the local date

getdate = time.strftime("%d%b%Y", time.localtime())
gettime = time.strftime("%d%b%Y%H%M%S", time.localtime())
  
#  Create new log file per day.

logpath = ''
log = getdate + "-logfilename.txt"
if not os.path.isfile(log+log):
	logfile = open(logpath+log, "wb")
	listalerts = []
else:
	listalerts = []
	getalerts = open(logpath+log, "rb")
	for line in getalerts:
		listalerts.append(line.strip())
	getalerts.close()
	logfile = open(logpath+log, "ab")

# Here we are definining some variables of lists and dictionaries that we will use throughout the script

# Keep a list of all the sources for devices labeled for each type
listwhites=[]
listblacks=[]
listgreys=[]

# Keep a list of MAC addresses and information for each according to label.  
# The master dictionary is an index of all MAC with a reference to where any other dictionary that MAC is listed 
master={}
black={}
white={}
grey={}

# Dictionary for final results
finalresults={}

# Track column name and order of columns
columnum = {0:"MAC", 1:"IP", 2:"HOST",3:"Alive"}
columindex = 3

checkcolor=['white','grey','black']

# check to see if config file exists

if not os.path.isfile('c:/tools/files/rogue_config.yml'): 
	print('The config file does not exist.  Please provide a proper config file')
	sys.exit()


# this section parses the config yaml file.  Not very efficiently as I'm learning how to do this.

with open('c:/tools/files/rogue_config.yml') as f:
	logfile.write(timedate + ' Config file opened.')
	sys.exit()
	indexnum=0
	data = yaml.load(f, Loader=yaml.FullLoader)
	for k,v in data.items():
		if k == 'ports': 
			portcheck = v
			continue
		if k == 'RemoteAccess': 
			ra = v
			continue
		if k == 'Rogue_Score':
			roguescore = v
			continue
		if k == 'Good_Score':
			goodscore = v 
			continue
		if k == 'Output':
			outinfo = v
			continue
		if k == 'CAM_Table':
			caminfo = v
			continue
		indexnum+=1
		name=""
		file=""
		MAC_C=""
		IP_C=""
		color=""
		weight=""
		for k1, v1 in v.items():
			print(k1, '-', v1)
			if k1 == "enabled" : enabled=v1
			if k1 == "name": name = v1
			if k1 == "filename": file = v1
			if k1 == "MAC_Column" : temp1 = v1
			if temp1 == -1: MAC_C= 'skip'
			elif v1 > -1: MAC_C = v1
			else:
				print('The column given is not in the correct format, please fix your config file.  This source will be disabled and will not be used.')
				enabled = 0
			if k1 == "IP_Column" : temp1=v1
			if temp1 == -1: IP_C= 'skip'
			elif v1 > -1: IP_C = v1
			else:
				print('The column given is not in the correct format, please fix your config file.  This source will be disabled and will not be used.')
				enabled = 0
			if k1 == "Host_Column" : temp1=v1
			if temp1 == -1: Host_C= 'skip'
			elif v1 > -1: Host_C = v1
			else:
				print('The column given is not in the correct format, please fix your config file. Script will include this source, but will not use hostname')
				Host_C = 'skip'
			if k1 == "color" : temp1 = v1.lower()
			if temp1 not in checkcolor:
				print('please provide a color of white, grey, OR black')
				logfile.write(timedate + ": " + temp1 + " is not a valid color.")
				enabled=0
			else: color=v1.lower()
			
			if k1 == "weight" : weight=v1

		# check to see if this source is enabled.  if not, skip
		if enabled == 0:
			print(name + "-  This source is disabled, skipping\n")
			logfile.write(timedate + ": " + name + "-  This source is disabled, skipping\n")
			continue
		#if args.vlevel > 2: print('All preliminary information has now been collected.\n')
		# try to open the file with the MAC and other information
		try: 
			testopen = open(file, 'r')
			logfile.write(timedate + ": " + name + "-  This source is enabled and the file opened")
		except:
			print("Could not open file for " + file + ".  Please verify file exists.  Will skip this file\n")
			logfile.write(timedate + ": The file for source "+name+" could not be opened.  Please check that the file " + file + " exists.")
			#time.sleep(3)
			continue
		columindex +=1
		columnum[columindex]=name
		#columns = columns + ',' + name
		if color == 'grey':
			listgreys.append(name)
			for line in testopen:
				if 'MAC' in line: continue
				#print(line)
				getinfo = line.split(',')
				MAC = getinfo[MAC_C].strip()
				if MAC != 'skip':
					MAC = re.sub(r':','',MAC)
				if IP != 'skip':
					IP = getinfo[IP_C].strip()
				if HOST != 'skip':
					HOST = getinfo[Host_C].strip()
				if MAC not in master:
					grey[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
					master[MAC] = str(indexnum)
				else:
					temp = master[MAC]
					newindexnum = temp + "," + str(indexnum)
					master[MAC] = newindexnum
					grey[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
				indexnum+=1
		elif color == 'white':
			listwhites.append(name)
			for line in testopen:
				if 'MAC' in line: continue
				#print(line)
				getinfo = line.split(',')
				MAC = getinfo[MAC_C].strip()
				MAC = re.sub(r':','',MAC)
				IP = getinfo[IP_C]
				HOST = getinfo[Host_C]
				if MAC not in master:
					white[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
					master[MAC] = str(indexnum)
				else:
					temp = master[MAC]
					newindexnum = temp + "," + str(indexnum)
					master[MAC] = newindexnum
					white[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
				indexnum+=1
		elif color == 'black':
			listblacks.append(name)
			for line in testopen:
				if 'MAC' in line: continue
				#print(line)
				getinfo = line.split(',')
				MAC = getinfo[MAC_C].strip()
				MAC = re.sub(r':','',MAC)
				IP = getinfo[IP_C]
				HOST = getinfo[Host_C]
				if MAC not in master: 
					black[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
					master[MAC] = str(indexnum)
				else:
					temp = master[MAC]
					newindexnum = temp + "," + str(indexnum)
					master[MAC] = newindexnum
					black[str(indexnum)]=name+','+MAC+','+IP+','+HOST+','+str(weight)
				indexnum+=1
		else: 
			print("Your color: " + color + " is an invalid color. Skipping this source.")
			continue

# print("This is the master list: \n ")
# print(master)
# print("\nThis is the grey list: \n")
# print(grey)
# print("\nThis is the white list: \n")
# print(white)
# print("\nThis is the black list: \n")
# print(black)

for y in portcheck:
	for a, b in y.items():
		if a=="appname":
			columnname=b
			if b not in columnum: 
				columindex += 1
				columnum[columindex]=columnname
#

for a,b in ra.items():
	if a=="weight": driveweight=b
	if a=="types": 
		racolumnname="Remote Access"
		print(racolumnname)
	if a=="enabled" : 
		if b == 1:
			ra_check=1
			if racolumnname not in columnum: 
				columindex += 1
				columnum[columindex]=racolumnname
		if b==0: ra_check=0


columindex+=1
columnum[columindex]="Manufacturer" 
columindex+=1
columnum[columindex]="Total Weight"
#columns = columns +',Total Weight'

#print(columnum)

# set up for getting dictionary of oui's to companies
oui = {}

getoui = open('C:/Tools/files/oui.csv', encoding="utf8")

for line in getoui:
	if 'Registry' in line: continue
	#print(str(line))
	splitline = str(line).split(',')
	oui[splitline[1]]=splitline[2]
#
camtable = {}
try: 
	caminfo
	skipcam = 0
except NameError:
	skipcam = 1

if skipcam == 0:
	for a,b in caminfo.items():
		if a=='filename':camfile = b
		if a=='MAC_Column':
			if b == -1: MAC_C= 'skip'
			if b > -1: MAC_C = b
			else:
				print('The column given is not correct, please fix your config file')
				enabled = 0
		if a=='switch_Column':switch_C = b
		if a=='port_Column': port_C=b
		if a=='enabled': camcheck=b

	if camcheck==1:
		getcaminfo = open(camfile,'r')
		if 'Switch' not in columnum: 
			columindex += 1
			columnum[columindex]='Switch'
		if 'Switch Port' not in columnum: 
			columindex += 1
			columnum[columindex]='Switch Port'
		for line in getcaminfo:
			if 'MAC' in line: continue
			linecaminfo = line.split(',')
			camtable[linecaminfo[MAC_C]] = linecaminfo[switch_C]+','+linecaminfo[port_C]
	else: skipcam = 1


print(portcheck)
print(driveweight)
print(roguescore)
print(goodscore)

knownrogue={}
knowngood={}
unknown={}
rowresults={}
MAC=''
IP=''
weight=''

# create results output

for y in outinfo:
	for a, b in y.items():
		if a == "type": outtype=b

if outtype == 'file':
	for y in outinfo:
		for a, b in y.items():
			if a == "name": outdestplace = b

	outdest = open(outdestplace, 'w')
	toprow = ''
	for n, m in columnum.items():
		if m == "MAC": toprow = m
		else:
			toprow = toprow + ',' + m
	outdest.write(toprow+'\n')



# now start analyzing machines in grey list
print(grey)
for k in grey:
	#print(k)
	stuff = grey[k].split(',')
	row = ''
	print(stuff)
	MAC = stuff[1]
	IP = stuff[2]
	HOST = stuff[3]
	weight= stuff[4]
	rowresults = {0:MAC,1:IP,2:HOST}
	# print(MAC)
	# print(IP)
	# print(weight)
	if MAC in white:
		# get all instances of MAC in whitelist by checking against master list
		indx = master[MAC]
		idx = indx.split(',')
		for id in idx:
			if id in white:
				reasons = white[id]
				reason = reasons.split(',')
				name = reason[0]
				getcolnum = [key for (key, value) in columnum.items() if value==name]
				print(getcolnum)
				time.sleep(1)
				rowresults[getcolnum[0]]='Y-' + name
		# add MAC to known good
		info = values + ',MAC in whitelist'
		knowngood[MAC]=info
	elif MAC in black:
		# get all instances of MAC in whitelist by checking against master list
		indx = master[MAC]
		idx = indx.split(',')
		for id in idx:
			if id in black:
				reasons = black[id]
				reason = reasons.split(',')
				name = reason[0]
				getcolnum = [key for (key, value) in columnum.items() if value==name]
				print(getcolnum)
				#time.sleep(1)
				#columns = columns+','+name
				rowresults[getcolnum[0]]='Y-' + name
		# add MAC to known rogue
		info = values + ',MAC in blacklist'
		knownrogue[MAC]=info
	else:
		# futher analysis must be done
		totalweight = 0
		if MAC in master:
			getindexnumbers = master[MAC]
		else:
			print('MAC is not in master.  There must be an error')
		getindex = getindexnumbers.split(',')
		
		for x in getindex:
			print(x)
			if x in grey:
				print(grey[x])
				getstuff = grey[x].split(',')
				addweight = getstuff[4]
				totalweight = totalweight + int(addweight)
				name = getstuff[0]
				print(name)
				print(columnum)
				getcolnum = [key for (key, value) in columnum.items() if value==name]
				#print(getcolnum[0])
				#time.sleep(1)
				rowresults[getcolnum[0]]='Y-' + name
				#columns = columns+','+name
				#row = row+','+'Y-'+name
		
		alive = ping(IP)
		rowresults[3]=str(alive)
		if alive == True:
			if ra_check==1:
				check_cdrive = cdrive(IP)
				getcolnum = [key for (key, value) in columnum.items() if value==racolumnname]
				print("This is the column number: " + str(getcolnum[0]))
				rowresults[getcolnum[0]] = "RA - " + str(check_cdrive)
				if check_cdrive == True: totalweight = totalweight + driveweight
			
			if skipcam == 0:
				if MAC in camtable:
					getcolnum = [key for (key, value) in columnum.items() if value=='Switch']
					camcolumns = camtable[MAC].split(',')
					rowresults[getcolnum[0]] = camcolumns[0].strip()
					getcolnum = [key for (key, value) in columnum.items() if value=='Switch Port']
					rowresults[getcolnum[0]] = camcolumns[1].strip()+'\n'
				else:
					getcolnum = [key for (key, value) in columnum.items() if value=='Switch']
					rowresults[getcolnum[0]] = 'unknown'
					getcolnum = [key for (key, value) in columnum.items() if value=='Switch Port']
					rowresults[getcolnum[0]] = 'unknown'

			for y in portcheck:
				for a, b in y.items():
					print(a)
					print(b)
					if a=="appname":columnname=b
					if a=="port":port=b 
					if a=="weight":addweight=b
					#columns = columns+','+columnname
					
				checkport = isOpen(IP, port)
				getcolnum = [key for (key, value) in columnum.items() if value==columnname]
				if checkport == True:
					totalweight = totalweight + int(addweight)
					rowresults[getcolnum[0]]='Y-'+columnname
				else:
					rowresults[getcolnum[0]]='N-'+columnname
		else:
			rowresults[4] = "False"
			for y in portcheck:
				for a, b in y.items():
					print(a)
					print(b)
					if a=="appname":columnname=b
					#columns = columns+','+columnname
				getcolnum = [key for (key, value) in columnum.items() if value==columnname]
				rowresults[getcolnum[0]]='N-'+columnname
				
		print(totalweight)
		getcolnum = [key for (key, value) in columnum.items() if value=='Total Weight']
		rowresults[getcolnum[0]]=str(totalweight)
		getcolnum = [key for (key, value) in columnum.items() if value=='Manufacturer']
		try: 
			whatoui1 = oui[MAC[:6]]
			whatoui = re.sub(r'"','',whatoui1)
		except KeyError: whatoui = 'unknown'
		rowresults[getcolnum[0]]=str(whatoui)
		print('\n\n')
		print(columnum)
		lencolumnum = len(columnum)
		print(rowresults)
		outrow =''
		for i in range (0, lencolumnum):
			if i ==0: outrow = rowresults[i]
			else:
				try: outrow = outrow + ',' + rowresults[i]
				except KeyError: outrow = outrow + ',N/A'
		print('\nThis is the outrow\n'+outrow)
		outdest.write(outrow+'\n')
		# time.sleep(2)
		if totalweight > goodscore:
			print('This MAC had been determined to be good and will be added to good list')
			
			knowngood[MAC]=grey[k] + ',' + str(totalweight)
		elif totalweight < roguescore:
			print('This MAC has been determined to be a rogue and will be added to the known bad list')
			knownrogue[MAC]=grey[k] + ',' + str(totalweight)
		else:
			print('The total score of the MAC was not enough to determine if it is good or bad and thus warrents additional investigation')
			unknown[MAC]=grey[k] + ',' + str(totalweight)
		
# print('knownrogue')
# print(knownrogue)
# print('knowngood')
# print(knowngood)
# print('unknown')
# print(unknown)
# print('results')
