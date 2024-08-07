#Standard Python libraries required for most functionality
import os #For enumeration
import requests #For querying API
import urllib.parse #For processing API response
from dataclasses import dataclass  #For CVE and CVEList dataclass
from typing import List #For the CVE_list attribute 'entries'
import argparse #For accepting user flags
import sys #for graceful exits
import threading #for faster querying
#Note that RequestLab imports are used later on. This is so the program works fine without RequestLab installed if the user does not need PDF output



@dataclass
class CVE:
    exploit_links: List[str];
    cve_ID: str
    cvss3_score: float = 0.0
    impact3_score: float = 0.0
    exploitability3_score: float = 0.0
    summary: str = "placeholder"
    kernel_matched: bool = False
    
    def printInfo(self, file_handler = None): #By default, optional argument file_handler will be None.
        print("CVE ID: " + self.cve_ID)
        print("CVSS3 Score: " + str(self.cvss3_score))
        print("Impact3 Score: " + str(self.impact3_score))
        print("Exploitability3 Score: " + str(self.exploitability3_score))
        print("Summary: " + self.summary)
        print("Kernel matched: " + str(self.kernel_matched))

        if file_handler != None:
            file_handler.write("―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――" + "\n")
            file_handler.write("CVE ID: " + self.cve_ID+ "\n")
            file_handler.write("CVSS3 Score: " + str(self.cvss3_score) + "\n")
            file_handler.write("Impact3 Score: " + str(self.impact3_score) + "\n")
            file_handler.write("Exploitability3 Score: " + str(self.exploitability3_score) + "\n")
            file_handler.write("Summary: " + self.summary + "\n")
            file_handler.write("Kernel matched: " + str(self.kernel_matched) + "\n")
        
        if len(self.exploit_links) > 0: #if any exploit links exist for this CVE
            print("Exploit-DB links: ")
            for link in self.exploit_links:
                print(link)
                if file_handler != None: file_handler.write(link + "\n")
    
    def getExploitLinks(self): #Returns an array of tuples, containing cve_ID + links to exploit code from Exploit-db for this CVE. Also adds them to the attribute exploit_links.
        exploit_link_list = [] #We will return this list
        response = requests.get("https://cvepremium.circl.lu/api/cve/" + self.cve_ID)
        if (response.status_code != 200):
            print("Something went wrong with the request... received status code %d for URL %s" % (response.status_code, "https://cvepremium.circl.lu/api/cve/" + str(self.cve_ID)))
            return response.status_code;
        else: 
            results = response.json()
            try:
                data = results['refmap']
                if 'exploit-db' in data:
                    for id in data['exploit-db']:
                        self.exploit_links.append("https://www.exploit-db.com/exploits/" + str(id)) #Add it to the list of exploits for this CVE
                        exploit_link_list.append([self.cve_ID, "https://www.exploit-db.com/exploits/" + str(id)])
                    return exploit_link_list
                else: return -1 #No exploits available for this CVE
            except: return -1; #Likely some key error from missing refmap
        
@dataclass
class CVE_list:
    entries: List[CVE]

    def add_CVE(self, cve_ID, cvss3_score, impact3_score, exploitability3_score, summary, kernel_matched):
        try:
            self.entries.append(CVE([], cve_ID, cvss3_score, impact3_score, exploitability3_score, summary, kernel_matched)) #Note the first argument is an empty list. This is a list to store exploit links, which will later be filled
            return 1
        except: #will occur if an invalid parameter is passed
            return -1

                  
    def displayCVEs(self, limit, kernel_matched_only, file_handler): #filename is by default None, in which case we do not output.
        if limit > len(self.entries): limit = len(self.entries); #limit should not be higher than the number of elements on the list. This will correct it if it is.
        if kernel_matched_only == True: print("Displaying kernel-matched CVEs only...");
        for index, current_CVE in  enumerate(self.entries):
            if (current_CVE.kernel_matched == True) or (kernel_matched_only == False):
                print("―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
                if file_handler != None: 
                    current_CVE.printInfo(file_handler)
                else: 
                    current_CVE.printInfo()
                if index == limit - 1: break;
        if file_handler != None: file_handler.close()
    
    def fetchExploitLinks(self): #Queries the Circl database for Exploit DB links for all CVEs in the list. Returns a list of tuples: CVE ID followed by exploit links.
        exploitLinkList = []
        print("Fetching exploit links for %d exploits..." % (len(self.entries)))
        for index, current_CVE in  enumerate(self.entries):
            result = current_CVE.getExploitLinks()
            if result != -1: exploitLinkList.append(current_CVE.getExploitLinks()) #-1 is returned if no exploits were found
        print("All exploit links fetched.")
        return exploitLinkList
                        
    def sortBy(self, sort_parameter):
        pass
        #Implement sorting here! When object is fully implemented
    def filter(self, filter_parameter):
        pass
        #Implement filtering here; add 'filtered' attribute to CVE so it's essentially "dead" after being filtered out.
    def count(self):
        pass
        #Count should only count non-filtered CVEs\
            
        
def enumerateDistribution(): #Returns distribution and release
    distribution = os.popen("lsb_release -i").read().rstrip() #This gives output in the form "Distributor ID:\tUbuntu"
    if distribution == "": #lsb_release does not work
        #Then we rely on cat /etc/os-release and grep the necessary info
        distribution = os.popen("cat /etc/os-release | grep 'ID=' | grep -v '_'").read().rstrip().replace("\"", "")
        distribution = distribution[3:]
        release = os.popen("cat /etc/os-release | grep 'VERSION' | grep -v '_'").read().rstrip().replace("\"", "")
        release = release[8:]
    else: #lsb_release works as intended
        distribution = distribution[distribution.rfind("\t")+1:] #So we index the :\t (+1 since it's 2 characters) and take everything after it
        release = os.popen("lsb_release -r").read().rstrip() #This gives output in the form "Release:\t22.04
        release = release[release.rfind("\t")+1:] #So we index the :\t (+1 since it's 2 characters) and take everything after it
    return distribution + " " +  release #Returns "Ubuntu" + " " + "22.04"

def enumerateKernelVersion(): #Returns kernel version
    # uname --kernel-release provides output in the form "5.15.0-89-generic"
    kernel_version, dash, release_info = os.popen("uname --kernel-release").read().partition('-') #this will split the output into 3 parts where the first hyphen is
    #So kernel_version would be "5.15.0", dash would be "-", and release_info would be "89-generic"
    return kernel_version #we only really care about kernel_version, so we only return that

def printBanner():
    file_handler = open("./osaker.txt", "r")
    print(file_handler.read()) 
    file_handler.close()

def downloadExploit(fileName, downloadURL):
    print("Downloading " + downloadURL + "...")
    urllib.request.urlretrieve(downloadURL, fileName) 
    print("Download finished.")
    
def queryCPE(search_term):
    response = requests.get("https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=" + search_term) 
    if (response.status_code != 200):
        print("Something went wrong... got error %d" % (response.status_code))
        return -1
    else: 
        CPE_list = []
        raw_results = response.json()
        for search_result in raw_results['products']:
            current_result = search_result['cpe'] #Can't index a JSON twice in Python. Syntax thing. It's really annoying.
            CPE_value = current_result['cpeName']
            CPE_list.append(CPE_value)
    #We may get none, 1 or many possible CPE values.
    if (len(CPE_list) == 0):
        return -1
    elif (len(CPE_list) == 1):
        print("Found one CPE value: ")
        print(CPE_list[0])
        return(CPE_list[0])
    else:
        print("Found multiple CPE values: ")
        for index, CPE in enumerate(CPE_list): print("%d. %s" % (index + 1, CPE))
        return(CPE_list[int(input("Select which CPE to use (1,2,3,etc.): ")) - 1])

def boundaryCheck(value, lower_bound, upper_bound): #Checks if value is within certain boundaries. Returns True if failed.
    return True if (value > upper_bound or value < lower_bound) else False; 
    
#Before anything, parse the user arguments    
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("-kV", "--kernel-version", dest = "kernel_version", default = "undefined", help="Kernel version to search. Will automatically enumerate from machine if not provided. Example argument: 5.15.0")
arg_parser.add_argument("-dV", "--distribution-version", dest = "distribution_version", default = "undefined", help="Distribution name and version to search. Will automatically enumerate from machine if not provided. Example argument: Ubuntu 22.10")
arg_parser.add_argument("-kM", "--kernel-match", dest = "kernel_match", action='store_true', help="Filter out exploits that do not include the kernel CPE as a vulnerable configuration. Recommended for minimising false positives.")
arg_parser.add_argument("-cvss", "--cvss-filter", dest = "CVSS_filter", default = 5, help="Filters out exploits below the provided CVSS level. Scale 0-10, default 5.")
arg_parser.add_argument("-imp", "--impact-filter", dest = "impact_filter", default = 3, help="Filters out exploits below the provided impact level. Scale 0-6, default 3.")
arg_parser.add_argument("-exp", "--exp-filter", dest = "exploitability_filter", default = 1.5, help="Filters out exploits below the provided exploitability level. Scale 0-3, default 1.5.")
arg_parser.add_argument("-d", "--display-limit", dest = "display_limit", default = 20, help="Limit to how many results can be displayed. Default 20.")
arg_parser.add_argument("-o", "--outputTXT",dest = "outputFileName", default = None, help="Output the CVE list to a .txt file.")
arg_parser.add_argument("-oPDF", "--outputPDF",dest = "outputPDFName", default = None, help="Output the CVE list to a PDF file. Requires ReportLab Python library to be installed.")
arg_parser.add_argument("-dL", "--download-exploits", dest = "download_exploits", action='store_true', help="Downloads any exploit code found.")
user_arguments = arg_parser.parse_args()

#Quick boundary check on filters
if boundaryCheck(float(user_arguments.CVSS_filter), 0, 10): print("Invalid CVSS filter. Exiting..."); sys.exit(1)
if boundaryCheck(float(user_arguments.impact_filter), 0, 6): print("Invalid Impact filter. Exiting..."); sys.exit(1)
if boundaryCheck(float(user_arguments.exploitability_filter), 0, 3): print("Invalid Exploitability filter. Exiting..."); sys.exit(1)

#Weird fix here: for PDF output, we need .txt output. If the user just wants PDF and no txt, we need to make a temporary txt file to convert to PDF.
if user_arguments.outputPDFName != None and user_arguments.outputFileName == None: user_arguments.outputFileName = "temp_output"

#printBanner()
print("OS Exploit Retrieval Tool v1.0\n")

#First, enumerate distibution and versions

if (user_arguments.kernel_version == "undefined"):
    print("No kernel version provided - enumerating...")
    try:
        kernel_version = enumerateKernelVersion()
    except:
        print("Critical error: automatic kernel enumeration failed. Try manual input instead.")
        sys.exit(1)
else:
    kernel_version = user_arguments.kernel_version

#Quick fix: if the kernel version ends with a '.0', trim off the last 2 characters. For some reason, NVD's API does not 
#return any kernel CPEs if attaching a .0 on the end e.g. kernel 6.1.0 won't return any results, but 6.1 will
if kernel_version[-2:] == ".0": kernel_version = kernel_version[:-2]

if (user_arguments.distribution_version == "undefined"):
    print("No distribution version provided - enumerating...")
    try:
        distribution = enumerateDistribution()
    except:
        print("Critical error: automatic distribution enumeration failed. Try manual input instead.")
        sys.exit(1)
else:
    distribution = user_arguments.distribution_version

print("Target machine: " + distribution + " running kernel version " + kernel_version + ".")

#We use NVD's API to find the CPEs we need
print("Searching the NVD database for CPEs for kernel version " + kernel_version + "...")
kernel_CPE = queryCPE("linux kernel " + kernel_version)
if (kernel_CPE == -1): print("Critical error: no CPEs found for kernel version. Try manual input instead.");sys.exit(1);
print("Searching the NVD database for CPEs for distribution " + distribution + "...")
distribution_CPE = queryCPE(distribution)
if (distribution_CPE == -1): print("Critical error: no CPEs found for distribution version. Try manual input instead.");sys.exit(1);
print("CPEs confirmed.")

#If output flag was used, then we create the file_handler here, and also write in the distribution + kernel versions
if user_arguments.outputFileName != None:
    try:
        file_handler = open("./" + str(user_arguments.outputFileName), "w")
        print("Successfully created output file.")
        file_handler.write("Operating System And Kernel Attack tool v1.0 Output\n")
        file_handler.write("Arguments: \n")
        file_handler.write("Kernel: " + kernel_version + "\n")
        file_handler.write("Kernel CPE: " + kernel_CPE + "\n")
        file_handler.write("Distribution: " + distribution + "\n")
        file_handler.write("Distribution CPE: " + distribution_CPE + "\n")
        file_handler.write("Minimum CVSS: " + str(user_arguments.CVSS_filter) + "\n")
        file_handler.write("Minimum Impact: " + str(user_arguments.CVSS_filter) + "\n")
        file_handler.write("Minimum Exploitability: " + str(user_arguments.CVSS_filter) + "\n")
        file_handler.write("Kernel-matched exploits only: " + str(user_arguments.kernel_match) + "\n")
    except: 
        print("Error: output file not created. Check you have permissions to create files in this directory. Proceeding without output.")
        file_handler = None
else:
    file_handler = None #Just create a dummy.

#Then, we use Circl's API to get the CVE list
print("Querying Circl API...")
response = requests.get("https://cvepremium.circl.lu/api/cvefor/" + urllib.parse.quote(distribution_CPE) + "?limit=500") 
if (response.status_code != 200):
    print("Something went wrong... got error %d" % (response.status_code))
else: 
    total_exploit_counter = 0
    kernelmatch_exploit_counter = 0
    final_CVE_list = CVE_list([]) #We initialise an empty list first
    results = response.json()
    for current_CVE in results:
        attack_vector = ""
        try:
            CVE_access = current_CVE['access']
            attack_vector = CVE_access['vector']
        except:
            CVE_access = current_CVE['exploitability3']
            attack_vector = CVE_access['attackvector']
        
        if (attack_vector != 'LOCAL'or current_CVE['cvss3'] < float(user_arguments.CVSS_filter) 
            or current_CVE['impactScore3'] < float(user_arguments.impact_filter) or current_CVE['exploitabilityScore3'] < float(user_arguments.exploitability_filter)): 
            #Only process LOCAL exploits that meet user filters
            pass
        else:
            #Now, here, we check if the kernel is in the CPE list i.e. kernel matching
            vulnerable_configurations = current_CVE["vulnerable_configuration"] #List of vulnerable CPEs for a given CVE; we check if our kernel's CPE is in here. If it is, it is much more likely the exploit will work
            kernel_matched = False
            for config in vulnerable_configurations:
                if config['id'] == kernel_CPE: 
                    kernelmatch_exploit_counter += 1
                    kernel_matched = True
                    break; #We don't need to check the rest.

            final_CVE_list.add_CVE(current_CVE['id'], current_CVE['cvss3'], current_CVE['impactScore3'], current_CVE['exploitabilityScore3'], current_CVE['summary'], kernel_matched)
            total_exploit_counter += 1
    
    print("%d exploits found for this distribution that satisfy the filters." % (total_exploit_counter))
    print("Of these, %d are kernel matched." % (kernelmatch_exploit_counter))

    #If no exploits were found due to user filters
    if total_exploit_counter == 0: print("No exploits satisfied user filters - try lowering them. Exiting..."); SystemExit(1); 
    
    allExploitLinksList = final_CVE_list.fetchExploitLinks() #Fetch the exploits, and store them in this list for later
    final_CVE_list.displayCVEs(int(user_arguments.display_limit), user_arguments.kernel_match, file_handler) #Display CVE information
    print("Finished!")
    #Everything has been written, so close the file.    
    if user_arguments.outputFileName != None: file_handler.close()
    
    
    #Finally, we download the exploits if the user provides the -dL flag.
    if user_arguments.download_exploits == True:
        """
        allExploitLinksList is in the format:
        [['CVE-2016-1247', 'https://www.exploit-db.com/exploits/40768']], [['CVE-2016-5195', 'https://www.exploit-db.com/exploits/40611'], ['CVE-2016-5195', 'https://www.exploit-db.com/exploits/40616'],...]]]
        Each CVE has its own tuple of exploits - these tuples also include the CVE ID for easier processing.
        """
        if (len(allExploitLinksList) == 0):
            print("No exploits were found to download.")
        else:
            print("Beginning downloads...")
            for CVE_entry in allExploitLinksList:
                for exploit in CVE_entry:
                    cve_id = exploit[0]
                    exploitDB_link = exploit[1].replace("exploits", "download")
                    download_thread = threading.Thread(target=downloadExploit, args=("./" + cve_id + "-" + exploitDB_link[36:], exploitDB_link)) #This [36:] adds just the exploit number found in the URL
                    download_thread.start()
                    
    #If the user wants PDF output, then we process it here
    if user_arguments.outputPDFName != None:
        try:
            #Below are all the libraries required for PDF output; try catch will catch missing libraries
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
            from reportlab.lib.units import inch
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            doc = SimpleDocTemplate(
                "./" + user_arguments.outputPDFName,
                pagesize=A4,
                )
            styles = getSampleStyleSheet()
            flowables = []
            current_style = ""
            spacer = Spacer(1, 0.25*inch)
            file_reader = open("./" + str(user_arguments.outputFileName), "r")
            #Iterate through every line in the .txt file, and add it to a PDF.
            for line in file_reader:
                if line[0:1] == "―": #Convert ASCII lines into proper lines (HTML HR tag lines), and add white space before and after.
                    flowables.append(spacer)
                    flowables.append(HRFlowable(width='100%', thickness=0.2, color=colors.black))
                    flowables.append(spacer)
                else:
                    current_style = "Heading1" if line[0:6] == "CVE ID" else "Normal" #Set CVE IDs to big headings for readability
                    current_paragraph = Paragraph(line, styles[current_style])
                    flowables.append(current_paragraph)
            file_reader.close() #Close the file after all reading is done
            doc.build(flowables) #Compile the entire document
            if user_arguments.outputFileName == "temp_output": os.remove("./temp_output") #Remove the temporary txt we used for our output (if we used one)
        except:
            print("Error creating PDF output - did you install the ReportLab library?")
            print(sys.exc_info())
    
       
    

