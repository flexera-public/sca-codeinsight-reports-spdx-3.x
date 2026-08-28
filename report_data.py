'''
Copyright 2020 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Fri Aug 07 2020
File : report_data.py
'''

import logging, re

import common.api.project.get_child_projects
import common.api.project.get_project_information
import common.api.project.get_inventory_summary
import common.api.license.license_lookup
import common.api.component.get_component_details
import common.api.inventory.get_inventory_details

logger = logging.getLogger(__name__)

#-------------------------------------------------------------------#
def gather_data_for_report(baseURL, projectID, authToken, reportData):
    logger.info("Entering gather_data_for_report")

    reportOptions = reportData["reportOptions"]
    # Parse report options
    includeChildProjects = reportOptions["includeChildProjects"]  # True/False
    includeComplianceInformation = reportOptions["includeComplianceInformation"]  # True/False
    cvssVersion = reportOptions["cvssVersion"]  # 2.0/3.x
    maxVersionsBack = reportOptions["maxVersionsBack"]  # Postive Int value

    projectList = [] # List to hold parent/child details for report
    inventoryData = {}  # Create a dictionary containing the inventory data using inventoryID as keys
    projectData = {} # Create a dictionary containing the project level summary data using projectID as keys
    licenseDetails = {} # Dictionary to store license details to avoid multiple lookups for same id
    projectReviewStatus = {}
    totalInventoryCount = 0

    # Get the list of parent/child projects start at the base project
    projectHierarchy = common.api.project.get_child_projects.get_child_projects_recursively(baseURL, projectID, authToken)

    # Create a list of project data sorted by the project name at each level for report display  
    # Add details for the parent node
    nodeDetails = {}
    nodeDetails["parent"] = "#"  # The root node
    nodeDetails["projectName"] = projectHierarchy["name"]
    nodeDetails["projectID"] = projectHierarchy["id"]
    nodeDetails["projectLink"] = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + str(projectHierarchy["id"]) + "&tab=projectInventory"
    topLevelProjectName = projectHierarchy["name"]

    projectList.append(nodeDetails)

    if includeChildProjects == "true":
        projectList = create_project_hierarchy(projectHierarchy, projectHierarchy["id"], projectList, baseURL)
    else:
        logger.debug("Child hierarchy disabled")

    projectInventoryCount = {}

    #  Gather the details for each project and summerize the data
    for project in projectList:

        projectID = project["projectID"]
        projectName = project["projectName"]
        projectLink = project["projectLink"]

        # Get project information with rollup summary data
        try:
            projectInformation = common.api.project.get_project_information.get_project_information_summary(baseURL, projectID, authToken)
        except:
            logger.error("    No Project Information Returned for %s!" %projectName)
            print("No Project Information Returned for %s." %projectName)

        # Get project summary information
        if cvssVersion == "3.x":
            projectInventorySummary = common.api.project.get_inventory_summary.get_project_inventory_with_v3_summary(baseURL, projectID, authToken)
        else:
            projectInventorySummary = common.api.project.get_inventory_summary.get_project_inventory_with_v2_summary(baseURL, projectID, authToken)
        
        if not projectInventorySummary:
            logger.warning("    Project %s contains no inventory items" %projectName)
            print("Project %s contains no inventory items." %projectName)

        projectInventoryCount[projectName] = len(projectInventorySummary)
        totalInventoryCount += len(projectInventorySummary)

        # Create empty dictionary for project level data for this project
        projectData[projectName] = {}

        #############################################
        #  This area will be replaced by 2020R4 APIs
        numApproved = 0
        numRejected = 0
        numDraft = 0
        currentItem=0

        for inventoryItem in projectInventorySummary:
            currentItem +=1

            complianceIssues = {}

            inventoryID = inventoryItem["id"]
            inventoryItemName = inventoryItem["name"]

            logger.debug("Processing inventory items %s of %s" %(currentItem, len(projectInventorySummary)))
            logger.debug("    Project:  %s   Inventory Name: %s  Inventory ID: %s" %(projectName, inventoryItemName, inventoryID))
            
            componentName = inventoryItem["componentName"]
            componentID = inventoryItem["componentId"]
            componentVersionId = inventoryItem.get("componentVersionId", "")
            inventoryPriority = inventoryItem["priority"]
            componentVersionName = inventoryItem["componentVersionName"]
            selectedLicenseID = inventoryItem["selectedLicenseId"]
            selectedLicenseName = inventoryItem["selectedLicenseSPDXIdentifier"]

            # Sentinel values Code Insight uses when no single license is selected
            # (WIP, Unknown, or a multi-license expression item)
            isSentinelLicenseID = str(selectedLicenseID) in ("N/A", "-1", "-2", "69")

            if selectedLicenseID in licenseDetails.keys():
                selectedLicenseName = licenseDetails[selectedLicenseID]["selectedLicenseName"]
                selectedLicenseUrl = licenseDetails[selectedLicenseID]["selectedLicenseUrl"]
                selectedLicensePriority = licenseDetails[selectedLicenseID]["selectedLicensePriority"]
            else:
                if not isSentinelLicenseID:
                    logger.debug("        Fetching license details for %s with ID %s" %(selectedLicenseName, selectedLicenseID))
                    licenseInformation = common.api.license.license_lookup.get_license_details(baseURL, selectedLicenseID, authToken)
                    licenseURL = licenseInformation["url"]
                    spdxIdentifier = licenseInformation["spdxIdentifier"]
                    licensePriority = licenseInformation["priority"]

                    if spdxIdentifier != "" and spdxIdentifier != "N/A":
                        licenseName = spdxIdentifier
                    else:
                        licenseName = licenseInformation["shortName"]

                    # There is not specific selected license just let it be blank
                    if licenseName == "I don't know":
                        licenseName = ""

                    licenseDetails[selectedLicenseID] = {}
                    licenseDetails[selectedLicenseID]["selectedLicenseName"] = licenseName
                    licenseDetails[selectedLicenseID]["selectedLicenseUrl"] = licenseURL
                    licenseDetails[selectedLicenseID]["selectedLicensePriority"] = licensePriority

                    selectedLicenseName = licenseName
                    selectedLicenseUrl = licenseURL
                    selectedLicensePriority = licensePriority

                else:
                    # Typically a WIP item
                    selectedLicenseName = ""
                    selectedLicenseUrl = ""
                    selectedLicensePriority = ""

            # For sentinel-ID items, check /inventories/{id} for its license expression
            # (e.g. "MIT OR Apache-2.0"). Not cached: a single component version can
            # legitimately have different license expressions across different
            # inventory items, so the expression must be fetched per inventory item.
            licenseExpression = ""
            if isSentinelLicenseID:
                try:
                    inventoryItemDetails = common.api.inventory.get_inventory_details.get_inventory_item_details_no_vuln_data(inventoryID, baseURL, authToken)
                    licenseExpressionDetails = inventoryItemDetails.get("licenseExpressionDetails")
                    if licenseExpressionDetails:
                        licenseExpression = licenseExpressionDetails.get("licenseExpression", "") or ""
                except:
                    logger.warning("Unable to fetch license expression for inventory item %s." %inventoryItemName)

            # Prefer a resolved license expression over the single-license name
            if licenseExpression:
                selectedLicenseName = licenseExpression
                selectedLicenseUrl = ""

            # If there is no specific version just leave it blank
            if componentVersionName == "N/A":
                componentVersionName = ""
            
            componentUrl = inventoryItem["url"]
            inventoryReviewStatus = inventoryItem["reviewStatus"] 
            inventoryLink = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + str(projectID) + "&tab=projectInventory&pinv=" + str(inventoryID)

            try:
                if cvssVersion == "3.x":
                    vulnerabilities = inventoryItem["vulnerabilitySummary"][0]["CvssV3"]
                else:
                    vulnerabilities = inventoryItem["vulnerabilitySummary"][0]["CvssV2"]
                vulnerabilityData = create_inventory_summary_dict(vulnerabilities, cvssVersion)
            except:
                logger.debug("No vulnerabilies for %s - %s" %(componentName, componentVersionName))
                vulnerabilityData = {'numTotalVulnerabilities': 0, 'numCriticalVulnerabilities': 0, 'numHighVulnerabilities': 0, 'numMediumVulnerabilities': 0, 'numLowVulnerabilities': 0, 'numNoneVulnerabilities': 0}

            # # If there is a SPDX value use that otherwise use the full name based on the             
            # if selectedLicenseSPDXIdentifier == "":
            #     selectedLicenseName = selectedLicenseID
            # else:
            #     selectedLicenseName = selectedLicenseSPDXIdentifier

            ############################################################################################
            # Determine if there are any compliance issues to report on
            if includeComplianceInformation:
                
                # Check review status
                if inventoryReviewStatus == "Rejected":
                    complianceIssues["Item rejected"] = "This item has been rejected for use. Please consult with your legal and/or security team for further guidance."
                elif inventoryReviewStatus == "Draft":
                    complianceIssues["Item not reviewed"] =  "This item has not been reviewed for use. Please consult with your legal and/or security team for further guidance."


                # Check if there is vulnerability data
                if sum(vulnerabilityData.values()) > 0:
                    complianceIssues["Security vulnerabilities"] = "This item has associated security vulnerabilites. Please consult with your security team for further guidance."

                
                # License compliance issue
                if selectedLicensePriority == 1:
                    complianceIssues["P1 license"] = "This item has a viral or strong copyleft license. Depnding on your usage there may be additional oblilgations. Please consult with your legal team.."

                # Component version compliance issue
                if componentVersionName == "":
                    complianceIssues["Unknown version"] = "This item has an unknown version. Additional analysis is recommended."
                else:
                    if componentID == "55720":  # Is it the linux kernel?
                        # The API call for the versions of linux takes a long time due to teh massive number of versions so bypass
                        logger.debug("Linux kernel so skipping version analysis")
                        complianceIssues["Version not analyzed"] = "This versions for this component have not beeen analyzed. Manual inspection is suggested"
                    elif componentID == "6682478":  # Is it the vim-vim?
                        # The API call for the versions of vim-vim takes a long time due to the massive number of versions so bypass
                        logger.debug("vim-vim so skipping version analysis")
                        complianceIssues["Version not analyzed"] = "This versions for this component have not beeen analyzed. Manual inspection is suggested"
                    else:
                    #    Determine if there are any issues with the version
                        componentVersionDetails = getVersionDetails(componentVersionName, componentID, baseURL, authToken)
                        numberVersionsBack = componentVersionDetails["numberVersionsBack"]

                        if int(numberVersionsBack) >= int(maxVersionsBack):
                            latestVersion = componentVersionDetails["latestVersion"]
                            complianceIssues["Old version"] = "The latest version is " + latestVersion + ". Your version is " + str(numberVersionsBack) + " versions back from the latest version. You should consider upgrading to a more recent version of this component."
                        elif numberVersionsBack == -1:
                            complianceIssues["Invalid Version"] = componentVersionName + " is not a valid version for the current component." 
                
                # Was there a license selected?
                if selectedLicenseName == "":
                    complianceIssues["Unspecified license"] = "This item has does not have a license associated with it. Additional analysis is recommended."


            # Store the data for the inventory item for reporting
            inventoryData[inventoryID] = {
                "projectName" : projectName,
                "inventoryItemName" : inventoryItemName,
                "componentName" : componentName,
                "componentVersionName" : componentVersionName,
                "selectedLicenseName" : selectedLicenseName,
                "vulnerabilityData" : vulnerabilityData,
                "inventoryPriority" : inventoryPriority,
                "componentUrl" : componentUrl,
                "selectedLicenseUrl" : selectedLicenseUrl,
                "inventoryReviewStatus" : inventoryReviewStatus,
                "inventoryLink" : inventoryLink,
                "projectLink" : projectLink,
                "complianceIssues" : complianceIssues
            }

            #############################################
            # Sum up inventory review status data
            if inventoryReviewStatus == "Approved":
                numApproved += 1
            elif inventoryReviewStatus == "Rejected":
                numRejected += 1
            elif inventoryReviewStatus == "Draft":
                numDraft += 1
            else:
                logger.error("Unknown inventoryReview Status: %s" %inventoryReviewStatus)

        # Group all inventory based data into a dict wit the project name as the key
        projectData[projectName]["numApproved"] = numApproved
        projectData[projectName]["numRejected"] = numRejected
        projectData[projectName]["numDraft"] = numDraft
        projectData[projectName]["numP1Licenses"] = projectInformation["licenses"]["P1"]
        projectData[projectName]["numP2Licenses"] = projectInformation["licenses"]["P2"]
        projectData[projectName]["numP3Licenses"] = projectInformation["licenses"]["P3"]
        projectData[projectName]["numNALicenses"] = projectInformation["licenses"]["Unknown"]

        # Determine the state of the project based on the "worst" status of inventory
        if numRejected > 0:
            project.update({"projectReviewStatus": "Rejected"})
            projectReviewStatus[projectID] = "Rejected"
        elif numDraft > 0:
            project.update({"projectReviewStatus": "Draft"})
            projectReviewStatus[projectID] = "Draft"
        else:
            project.update({"projectReviewStatus": "Approved"})
            projectReviewStatus[projectID] = "Approved"

        if cvssVersion == "3.x":
            projectData[projectName]["numCriticalVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV3"]["Critical"]
            projectData[projectName]["numHighVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV3"]["High"]
            projectData[projectName]["numMediumVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV3"]["Medium"]
            projectData[projectName]["numLowVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV3"]["Low"]
            projectData[projectName]["numNoneVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV3"]["None"]
        else:
            projectData[projectName]["numHighVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV2"]["High"]
            projectData[projectName]["numMediumVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV2"]["Medium"]
            projectData[projectName]["numLowVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV2"]["Low"]
            projectData[projectName]["numNoneVulnerabilities"] = projectInformation["vulnerabilities"]["CvssV2"]["Unknown"]

        projectData[projectName]["projectLink"] = projectLink

    # Roll up the inventortory data at a project level for display charts
    projectSummaryData = create_project_summary_data_dict(projectData)
    projectSummaryData["includeComplianceInformation"] = includeComplianceInformation
    projectSummaryData["cvssVersion"] = cvssVersion

    # Roll up the individual project data to the application level
    applicationSummaryData = create_application_summary_data_dict(projectSummaryData)

    # Roll up the project review status based on the status of child projects
    projectReviewStatus = roll_up_project_review_level(projectHierarchy, projectReviewStatus, 1)

    # Build up the data to return for the
    reportData["topLevelProjectName"] = topLevelProjectName
    reportData["projectHierarchy"] = projectHierarchy
    reportData["projectName"] = projectHierarchy["name"]
    reportData["projectID"] = projectHierarchy["id"]
    reportData["inventoryData"] = inventoryData
    reportData["projectList"] =projectList
    reportData["projectSummaryData"] = projectSummaryData
    reportData["applicationSummaryData"] = applicationSummaryData
    reportData["projectInventoryCount"] = projectInventoryCount
    reportData["totalInventoryCount"] = totalInventoryCount
    reportData["projectReviewStatus"] = projectReviewStatus

    logger.info("Exiting gather_data_for_report")

    return reportData
  
#----------------------------------------------------------------------
def create_inventory_summary_dict(vulnerabilities,cvssVersion):
    logger.info("Entering create_inventory_summary_dict")
    
    vulnerabilityData = {}
    vulnerabilityData["numTotalVulnerabilities"] = sum(vulnerabilities.values())

    vulnerabilityData["numHighVulnerabilities"] = vulnerabilities["High"]
    vulnerabilityData["numMediumVulnerabilities"] = vulnerabilities["Medium"]
    vulnerabilityData["numLowVulnerabilities"] = vulnerabilities["Low"]

    if cvssVersion == "2.0":
        vulnerabilityData["numNoneVulnerabilities"] = vulnerabilities["Unknown"]
    elif cvssVersion == "3.x":
        vulnerabilityData["numCriticalVulnerabilities"] = vulnerabilities["Critical"]
        vulnerabilityData["numNoneVulnerabilities"] = vulnerabilities["None"]

    return vulnerabilityData

#----------------------------------------------#
def create_project_hierarchy(project, parentID, projectList, baseURL):
    logger.debug("Entering create_project_hierarchy")

    # Are there more child projects for this project?
    if len(project["childProject"]):

        # Sort by project name of child projects
        for childProject in sorted(project["childProject"], key = lambda i: i['name'] ) :

            uniqueProjectID = str(parentID) + "-" + str(childProject["id"])
            nodeDetails = {}
            nodeDetails["projectID"] = childProject["id"]
            nodeDetails["parent"] = parentID
            nodeDetails["uniqueID"] = uniqueProjectID
            nodeDetails["projectName"] = childProject["name"]
            nodeDetails["projectLink"] = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + str(childProject["id"]) + "&tab=projectInventory"

            projectList.append( nodeDetails )

            create_project_hierarchy(childProject, uniqueProjectID, projectList, baseURL)

    return projectList


#----------------------------------------------------------------------------------------#
def create_project_summary_data_dict(projectData):
    logger.debug("Entering get_project_summary_data")

   # For the chart data we need to create lists where each element is in the correct order based on the 
   # project name order.  i.e. one list will # of approved items for each project in the correct order
    projectSummaryData = {}

    # Create empty lists for each metric that we need for the report
    for projectName in projectData:
        for metric in projectData[projectName]:
            if metric not in  ["P1InventoryItems", "projectLink"]:  # We don't care about these for now
                projectSummaryData[metric] = []

    # Grab the data for each project and add it in the correct order
    for projectName in projectData:
        for metric in projectData[projectName]:
            if metric not in  ["P1InventoryItems", "projectLink", "cvssVersion"]:  # We don't care about these for now
                projectSummaryData[metric].append(projectData[projectName][metric])

    projectSummaryData["projectNames"] = list(projectData.keys())
    
    logger.debug("Exiting get_project_summary_data")
    return projectSummaryData
    
#----------------------------------------------------------------------------------------#
def create_application_summary_data_dict(projectSummaryData):
    logger.debug("Entering get_application_summary_data")

    applicationSummaryData = {}

    # For each metric sum the data up
    for metric in projectSummaryData:
        if metric == "cvssVersion":
            applicationSummaryData[metric] = projectSummaryData[metric]

        elif metric != "projectNames" and metric != "includeComplianceInformation":
            applicationSummaryData[metric] = sum(projectSummaryData[metric])

    logger.debug("Exiting get_application_summary_data")
    return applicationSummaryData

#----------------------------------------------------------------------------------------#
def getVersionDetails(componentVersionName, componentID, baseURL, authToken):
    logger.debug("Entering getVersionDetails")

    componentVersionDetails = {}

    # Is it a valid component
    if componentID == "N/A":
        return componentVersionDetails

    versionDetails = common.api.component.get_component_details.get_component_details_v3_summary(baseURL, componentID, authToken)

    componentVersionList = versionDetails["data"]["versionList"]

    # Are there any versions?
    if not len(componentVersionList):
        return componentVersionDetails

    componentVersions = [] # To hold just the version names that can be processed
    ignoreVersions = ["unknown", "custom", "any version", "sample"]

    # Extract just the version names for comparison purposes
    for version in componentVersionList:
        versionName = version["name"]

        if versionName.lower() not in ignoreVersions:
            componentVersions.append(versionName)
        else:
            logger.warning("        The version %s is contained in the ingnoreVersions list" %versionName)

    componentVersions.sort(key=natural_sort)

    # In case there is a combination of version types 1.2 vs snapshot etc
    # move the ones starting with text to the begining of the list
    insertLocation = 0
    for version in componentVersions:
        if len(version) and version[0].isalpha():
            componentVersions.remove(version)
            componentVersions.insert(insertLocation , version)
            insertLocation +=1

    totalNumberVersions = len(componentVersions)

    if totalNumberVersions > 0:
        # There is at least one version available
        try:
            selectedVersionIndex = componentVersions.index(componentVersionName)
            numberVersionsBack = totalNumberVersions-selectedVersionIndex - 1 # How far back from most recent release
        except:
            logger.error("    versionName %s is not a valid version for the component with ID %s" %(componentVersionName, componentID))
            numberVersionsBack = -1
    
        componentVersionDetails["latestVersion"] = componentVersions[-1]
        componentVersionDetails["numberVersionsBack"] = numberVersionsBack

    else:
        # The version that was selected must be in the ignoreVersions list above
        componentVersionDetails["totalNumberVersions"] = 1
        componentVersionDetails["latestVersion"] = componentVersionName
        componentVersionDetails["numberVersionsBack"] = 0

    
    componentVersionDetails["currentVersion"] = componentVersionName
  
    logger.debug("        componentVersionDetails: %s" %componentVersionDetails)    

    return componentVersionDetails

#----------------------------------------------------------------------------------------#
def roll_up_project_review_level(projectHierarchy, projectReviewStatus, recursionLevel):
    recursionIndent = recursionLevel * " "
    logger.debug("%s Entering roll_up_project_review_level" %recursionIndent)

    parentProjectID = projectHierarchy['id']
    parentProjectName = projectHierarchy['name']
    parentProjectReviewStatus = projectReviewStatus[parentProjectID]

    logger.debug("%s %s - Initial project review status: %s" %(recursionIndent, parentProjectName, parentProjectReviewStatus))

    childProject = projectHierarchy["childProject"]

    recursionLevel +=1
    recursionIndent = recursionLevel * " "

    for project in childProject:

        # Get the most recent value for the parent project review status in case a child already changed it
        parentProjectReviewStatus = projectReviewStatus[parentProjectID]
      
        projectReviewStatus = roll_up_project_review_level(project, projectReviewStatus, recursionLevel)

        childProjectID = project["id"]
        childProjectReviewSatus = projectReviewStatus[childProjectID]

        logger.debug("%s %s - Current project review status: %s   Current child status:  %s" %(recursionIndent, parentProjectName, parentProjectReviewStatus, childProjectReviewSatus))

        # Does the parent project status need to change to the a child project?
        if childProjectReviewSatus == "Rejected":
            logger.debug("        Change %s to rejected" %parentProjectName)
            projectReviewStatus[parentProjectID] = "Rejected"
        elif childProjectReviewSatus == "Draft" and parentProjectReviewStatus == "Approved":
            logger.debug("        Change %s to draft" %parentProjectName)
            projectReviewStatus[parentProjectID] = "Draft"

    logger.debug("%s %s - Final project review status: %s" %(recursionIndent, parentProjectName, parentProjectReviewStatus))
    
    return projectReviewStatus

#-----------------------------
#  These two functions are used for naturally sorting the version names
#  which was pulled from the web
#  https://www.tutorialspoint.com/How-to-correctly-sort-a-string-with-a-number-inside-in-Python

def atoi(text):
    return int(text) if text.isdigit() else text

def natural_sort(text):
    return [ atoi(c) for c in re.split('(\d+)',text) ]

    