'''
Copyright 2023 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Tue Aug 29 2023
Modified By : sarthak
Modified On: Oct Mon 07 2025
File : report_data.py
'''

import logging, unicodedata, uuid, hashlib, datetime, re
import report_data_db
import SPDX_license_mappings

logger = logging.getLogger(__name__)
#-------------------------------------------------------------------#
def gather_data_for_report(projectID, reportData):
    logger.info("Entering gather_data_for_report")
    reportOptions = reportData["reportOptions"]
    includeChildProjects = reportOptions["includeChildProjects"]  # True/False
    creatorName = reportOptions.get("creatorName", "OrganizationName")
    namespaceMap = "urn:spdx:"
    inventoryLinks = []
    project_Name = report_data_db.get_projects_data(projectID)
    topLevelProjectName = project_Name
    documentName = project_Name.replace(" ", "_")
    documentNamespace  = f"{namespaceMap}-{documentName}-{str(uuid.uuid1())}"
    
    # SPDX 3.0.1 structure
    reportDetails = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": []
    }
    
    # Track added spdxIds to prevent duplicates
    added_spdx_ids = set()
    
    creation_info_node= {
      "@id": "_:creationInfo_0",
      "type": "CreationInfo",
      "specVersion": "3.0.1",
      "created": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
      "createdBy": [ f"{namespaceMap}{creatorName}" ],
      "createdUsing": [
        "Tool: Revenera SCA - Code Insight"
      ]
    }

    reportDetails["@graph"].append(creation_info_node)

    if includeChildProjects:
        projectList = report_data_db.get_child_projects(projectID)
    else:
        projectList = []
        projectList.append(projectID)

    for project in projectList:
        projectID = project
        projectName = report_data_db.get_projects_data(projectID)

        print("        Collect data for project: %s" %projectName)

        print("            Collect inventory details.")
        logger.info("            Collect inventory details")
        inventoryItems = report_data_db.get_inventory_data(projectID)
        if inventoryItems is None:
            inventoryItems = []
        inventoryItemsCustom = report_data_db.get_inventory_data_custom(projectID)
        if inventoryItemsCustom is not None and inventoryItemsCustom != []:
            inventoryItems += inventoryItemsCustom
        print("            Inventory has been collected.")
        logger.info("            Inventory has been collected.")      
        
        # To check inventory type between License Only or WIP
        inventoriesNotInRepo = report_data_db.get_inventories_not_in_repo(projectID)    # To handle WIP and License Only inventories
        inventoryItems += inventoriesNotInRepo

        for inventoryItem in inventoryItems:
            fileHashes = []
            inventoryCopyrights = []  # Initialize inventory-level copyright collection
            inventoryID = inventoryItem["inventoryID"]
            inventoryItemName = inventoryItem["inventoryItemName"]
            inventoryLink = f"{namespaceMap}ProjectId-{projectID}-InventoryId-{inventoryID}"
            if inventoryLink not in inventoryLinks:
                inventoryLinks.append(inventoryLink)

            inventoryAssociatedServerScannedFiles = report_data_db.get_server_scanned_files(projectID, inventoryID)
            if inventoryAssociatedServerScannedFiles is not None:
                for inventoryAssociatedFile in inventoryAssociatedServerScannedFiles:
                    fileHashes.append(inventoryAssociatedFile.get("fileSHA1"))
                    fileid = inventoryAssociatedFile['fileId']
                    fileName = inventoryAssociatedFile["filePath"].split("/")[-1]
                    file_spdx_id = f"{namespaceMap}ProjectId-{projectID}-FileId-{fileid}"
                    package_associated_Copyrights = report_data_db.get_project_copyright_evidence(projectID, fileid)
                    
                    # Single copyright processing for both file and inventory
                    fileCopyright = "NOASSERTION"  # Default for file
                    if package_associated_Copyrights and isinstance(package_associated_Copyrights, list) and len(package_associated_Copyrights) > 0:
                        copyright_values = [item.get("COPYRIGHT") for item in package_associated_Copyrights if item.get("COPYRIGHT")]
                        if copyright_values:
                            fileCopyright = " | ".join(copyright_values)  # For this specific file
                            inventoryCopyrights.extend(copyright_values)  # Add to inventory collection
                    
                    # Only add if this spdxId hasn't been added before
                    if file_spdx_id not in added_spdx_ids:
                        package_file_associated_node = {
                            "spdxId": file_spdx_id,
                            "type": "software_File",
                            "software_copyrightText": fileCopyright,  # Use file-specific copyright
                            "verifiedUsing" : [ {
                            "type" : "Hash",
                            "algorithm" : "md5",
                            "hashValue" : inventoryAssociatedFile.get("fileMD5")
                            }, {
                            "type" : "Hash",
                            "algorithm" : "sha1",
                            "hashValue" : inventoryAssociatedFile.get("fileSHA1")
                            } ],
                            "name": fileName,
                            "software_primaryPurpose": "source",
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(package_file_associated_node)
                        added_spdx_ids.add(file_spdx_id)
                    
                    package_relationship_file_node = {
                        "spdxId": f"{namespaceMap}{projectID}-{inventoryItemName}-{fileName}",
                        "type": "Relationship",
                        "relationshipType": "contains",
                        "from": inventoryLink,
                        "to": [file_spdx_id],
                        "creationInfo": "_:creationInfo_0"
                    }
                    package_associated_license = report_data_db.get_file_license_evidence(projectID, fileid)
                    if package_associated_license is not None and isinstance(package_associated_license, list):
                        for license_item in package_associated_license:
                            if license_item.get("LICENSE"):
                                license = license_item["LICENSE"]
                                # Check if the license is in SPDX mappings
                                if license in SPDX_license_mappings.LICENSEMAPPINGS:
                                    license = SPDX_license_mappings.LICENSEMAPPINGS[license]
                                license_spdx_id = f"{namespaceMap}{projectID}-{license}"
                                # Only add license if spdxId is unique
                                if license_spdx_id not in added_spdx_ids:
                                    package_file_license_node = {
                                        "spdxId": license_spdx_id,
                                        "type": "simplelicensing_LicenseExpression",
                                        "simplelicensing_licenseExpression": license,
                                        "creationInfo": "_:creationInfo_0"
                                    }
                                    reportDetails["@graph"].append(package_file_license_node)
                                    added_spdx_ids.add(license_spdx_id)

                                license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-{license}"
                                if license_rel_spdx_id not in added_spdx_ids:
                                    package_file_license_relationship_node = {
                                        "spdxId": license_rel_spdx_id,
                                        "type": "Relationship",
                                        "relationshipType": "hasConcludedLicense",
                                        "from": inventoryLink,
                                        "to": [license_spdx_id],
                                        "creationInfo": "_:creationInfo_0"
                                    }
                                    reportDetails["@graph"].append(package_file_license_relationship_node)
                                    added_spdx_ids.add(license_rel_spdx_id)

                    # Only add relationship if spdxId is unique
                    rel_spdx_id = package_relationship_file_node["spdxId"]
                    if rel_spdx_id not in added_spdx_ids:
                        reportDetails["@graph"].append(package_relationship_file_node)
                        added_spdx_ids.add(rel_spdx_id)
            
            inventoryAssociatedRemoteScannedFiles = report_data_db.get_remote_scanned_files(projectID, inventoryID)
            if inventoryAssociatedRemoteScannedFiles is not None:
                for inventoryAssociatedFile in inventoryAssociatedRemoteScannedFiles:
                    fileHashes.append(inventoryAssociatedFile.get("fileSHA1"))
                    fileid = inventoryAssociatedFile['fileId']
                    fileName = inventoryAssociatedFile["filePath"].split("/")[-1]
                    file_spdx_id = f"{namespaceMap}ProjectId-{projectID}-FileId-{fileid}-remote"
                    
                    # Get copyright info for this remote file
                    fileCopyright = " | ".join(sorted(list(set(report_data_db.get_project_copyright_evidence(projectID, fileid)))))
                    
                    # Also collect for inventory-level aggregation
                    inventoryCopyrights.extend(report_data_db.get_project_copyright_evidence(projectID, fileid))
                    
                    # Only add if this spdxId hasn't been added before
                    if file_spdx_id not in added_spdx_ids:
                        package_file_associated_node = {
                            "spdxId": file_spdx_id,
                            "type": "software_File",
                            "software_copyrightText": fileCopyright,
                            "name": fileName,
                            "software_primaryPurpose": "source",
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(package_file_associated_node)
                        added_spdx_ids.add(file_spdx_id)
                    
                    package_relationship_file_node = {
                        "spdxId": f"{namespaceMap}{inventoryItemName}-{fileName}-remote",
                        "type": "Relationship",
                        "relationshipType": "contains",
                        "from": inventoryLink,
                        "to": [file_spdx_id],
                        "creationInfo": "_:creationInfo_0"
                    }
                    # Only add relationship if spdxId is unique
                    rel_spdx_id = package_relationship_file_node["spdxId"]
                    if rel_spdx_id not in added_spdx_ids:
                        reportDetails["@graph"].append(package_relationship_file_node)
                        added_spdx_ids.add(rel_spdx_id)
            # Create a hash of the file hashes for PackageVerificationCode 
            try:
                stringHash = ''.join(sorted(fileHashes))
            except:
                logger.error("Failure sorting file hashes for %s" %inventoryItemName)
                logger.debug(stringHash)
                stringHash = ''.join(fileHashes)
            
            packageVerificationCodeValue = (hashlib.sha1(stringHash.encode('utf-8'))).hexdigest()
            
            # Format inventory copyrights as pipe-separated string
            if inventoryCopyrights:
                # Remove duplicates and filter out empty values
                unique_copyrights = [c for c in set(inventoryCopyrights) if c and c.strip()]
                if unique_copyrights:
                    inventoryCopyrightsFormatted = " | ".join(sorted(unique_copyrights))
                else:
                    inventoryCopyrightsFormatted = "NOASSERTION"
            else:
                inventoryCopyrightsFormatted = "NOASSERTION"
            
            # Handle componentName safely - some inventory items might not have it (e.g., License Only)
            componentName = inventoryItem.get("componentName", inventoryItem.get("inventoryItemName", "Unknown")).strip()
            forge = inventoryItem.get("forge", "")
            
            # Create supplier organization entity
            supplier_string = create_supplier_string(forge, componentName)
            supplier_spdx_id = f"{namespaceMap}{projectID}-{supplier_string.replace('Organization: ', '').replace(':', '-').replace(' ', '-')}"
            
            # Only add supplier organization if not already added
            if supplier_spdx_id not in added_spdx_ids:
                supplier_name = supplier_string.replace("Organization: ", "").strip()
                if  supplier_name == "Undetermined":
                    supplier_name = "unknown provenance"
                supplier_node = {
                    "spdxId": supplier_spdx_id,
                    "type": "Organization",
                    "name": supplier_name,
                    "creationInfo": "_:creationInfo_0"
                }
                reportDetails["@graph"].append(supplier_node)
                added_spdx_ids.add(supplier_spdx_id)
            
            # Handle componentDescription safely - some inventory items might not have it
            componentDescription = inventoryItem.get("componentDescription")
            if componentDescription is not None:
                componentDescription = componentDescription.replace("\n", " - ")
                usageText = inventoryItem.get("usageText")
                if usageText is not None:
                    componentDescription += " - " + usageText
            else:
                componentDescription = ""
            componentDescription = (
                unicodedata.normalize("NFKD", componentDescription)
                .encode("ASCII", "ignore")
                .decode("utf-8")
            )
            package_node = {
                "spdxId": inventoryLink,
                "type": "software_Package",
                "software_copyrightText" : inventoryCopyrightsFormatted,
                "suppliedBy" : supplier_spdx_id,
                "verifiedUsing": [
                    {
                    "type": "PackageVerificationCode",
                    "algorithm": "sha1",
                    "hashValue": packageVerificationCodeValue
                    }
                ],
                "name":  project_Name + "-"+ componentName,
                "software_downloadLocation": inventoryItem.get("componentUrl") if inventoryItem.get("componentUrl") is not None else inventoryItem.get("selectedLicenseUrl", "NOASSERTION"),
                "software_packageVersion" : inventoryItem.get("componentVersionName") if inventoryItem.get("componentVersionName") is not None else "N/A",
                "description" : componentDescription,
                "creationInfo": "_:creationInfo_0"
            }
            
            # Only add package if spdxId is unique
            if inventoryLink not in added_spdx_ids:
                reportDetails["@graph"].append(package_node)
                added_spdx_ids.add(inventoryLink)

            # Process package-level licenses (declared licenses from component)
            componentId = inventoryItem.get("componentId")
            if componentId is not None:
                possibleLicenses = report_data_db.get_component_possible_Licenses(componentId)
                if possibleLicenses is not None and isinstance(possibleLicenses, list):
                    for license in possibleLicenses:
                        licenseName = license.get("licenseName")
                        
                        # Determine possibleLicenseSPDXIdentifier based on available fields
                        if license.get("spdxIdentifier") is None and license.get("shortName") != "" and license.get("shortName") is not None:
                            possibleLicenseSPDXIdentifier = license["shortName"]
                        elif license.get("spdxIdentifier") is not None:
                            possibleLicenseSPDXIdentifier = license["spdxIdentifier"]
                        else:
                            possibleLicenseSPDXIdentifier = licenseName
                        
                        # Handle Public Domain as NONE
                        if licenseName == "Public Domain":
                            logger.info("        Added to NONE declaredLicenses since Public Domain.")
                            license_spdx_id = f"{namespaceMap}{projectID}-NONE"
                            if license_spdx_id not in added_spdx_ids:
                                none_license_node = {
                                    "spdxId": license_spdx_id,
                                    "type": "simplelicensing_LicenseExpression",
                                    "simplelicensing_licenseExpression": "NONE",
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(none_license_node)
                                added_spdx_ids.add(license_spdx_id)
                            
                            # Create relationship
                            license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-NONE-{inventoryID}"
                            if license_rel_spdx_id not in added_spdx_ids:
                                license_relationship_node = {
                                    "spdxId": license_rel_spdx_id,
                                    "type": "Relationship",
                                    "relationshipType": "hasConcludedLicense",
                                    "from": inventoryLink,
                                    "to": [license_spdx_id],
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(license_relationship_node)
                                added_spdx_ids.add(license_rel_spdx_id)
                        
                        # Check if license is in SPDX mappings
                        elif possibleLicenseSPDXIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                            logger.info("        \"%s\" maps to SPDX ID: \"%s\"" % (possibleLicenseSPDXIdentifier, SPDX_license_mappings.LICENSEMAPPINGS[possibleLicenseSPDXIdentifier]))
                            spdx_mapped_license = SPDX_license_mappings.LICENSEMAPPINGS[possibleLicenseSPDXIdentifier]
                            license_spdx_id = f"{namespaceMap}{projectID}-{spdx_mapped_license}"
                            
                            if license_spdx_id not in added_spdx_ids:
                                license_node = {
                                    "spdxId": license_spdx_id,
                                    "type": "simplelicensing_LicenseExpression",
                                    "simplelicensing_licenseExpression": spdx_mapped_license,
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(license_node)
                                added_spdx_ids.add(license_spdx_id)
                            
                            # Create relationship
                            license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-{spdx_mapped_license}-{inventoryID}"
                            if license_rel_spdx_id not in added_spdx_ids:
                                license_relationship_node = {
                                    "spdxId": license_rel_spdx_id,
                                    "type": "Relationship",
                                    "relationshipType": "hasConcludedLicense",
                                    "from": inventoryLink,
                                    "to": [license_spdx_id],
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(license_relationship_node)
                                added_spdx_ids.add(license_rel_spdx_id)
                        
                        else:
                            # License not in SPDX mappings - create CustomLicense with LicenseRef
                            logger.warning("        \"%s\" is not a valid SPDX identifier for Declared License. - Using LicenseRef." % (possibleLicenseSPDXIdentifier))
                            
                            # Clean up the identifier
                            possibleLicenseSPDXIdentifier = possibleLicenseSPDXIdentifier.split("(", 1)[0].rstrip()  # Remove everything after (
                            possibleLicenseSPDXIdentifier = re.sub('[^a-zA-Z0-9 \n\.]', '-', possibleLicenseSPDXIdentifier)  # Replace special chars with dash
                            possibleLicenseSPDXIdentifier = possibleLicenseSPDXIdentifier.replace(" ", "-")  # Replace space with dash
                            licenseReference = "LicenseRef-%s" % possibleLicenseSPDXIdentifier
                            
                            # Priority: noticeText > asFoundLicenseText > possibleLicenseSPDXIdentifier
                            extractedText = (inventoryItem.get("noticeText") or 
                                           inventoryItem.get("asFoundLicenseText") or 
                                           possibleLicenseSPDXIdentifier)
                            
                            custom_license_spdx_id = f"{namespaceMap}{licenseReference}"
                            
                            # Create CustomLicense element (SPDX 3.x equivalent of hasExtractedLicensingInfos)
                            if custom_license_spdx_id not in added_spdx_ids:
                                custom_license_node = {
                                    "spdxId": custom_license_spdx_id,
                                    "type": "expandedlicensing_CustomLicense",
                                    "simplelicensing_licenseText": extractedText,
                                    "name": possibleLicenseSPDXIdentifier,
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(custom_license_node)
                                added_spdx_ids.add(custom_license_spdx_id)
                            
                            # Create relationship between package and custom license
                            custom_license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-{licenseReference}-{inventoryID}"
                            if custom_license_rel_spdx_id not in added_spdx_ids:
                                custom_license_relationship_node = {
                                    "spdxId": custom_license_rel_spdx_id,
                                    "type": "Relationship",
                                    "relationshipType": "hasConcludedLicense",
                                    "from": inventoryLink,
                                    "to": [custom_license_spdx_id],
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(custom_license_relationship_node)
                                added_spdx_ids.add(custom_license_rel_spdx_id)

            # Process inventory-specific selected license (the license chosen for this specific inventory item)
            selectedLicenseName = inventoryItem.get("selectedLicenseName")
            selectedLicenseSPDXIdentifier = inventoryItem.get("selectedLicenseSPDXIdentifier")
            shortName = inventoryItem.get("shortName")
            
            if selectedLicenseName is not None and selectedLicenseName != "":
                # Determine the SPDX identifier to use
                if selectedLicenseSPDXIdentifier is not None and selectedLicenseSPDXIdentifier != "":
                    selectedIdentifier = selectedLicenseSPDXIdentifier
                elif shortName is not None and shortName != "":
                    selectedIdentifier = shortName
                else:
                    selectedIdentifier = selectedLicenseName
                
                # Handle Public Domain as NONE
                if selectedLicenseName == "Public Domain":
                    logger.info("        Added to NONE concludedLicense for selected license since Public Domain.")
                    license_spdx_id = f"{namespaceMap}{projectID}-NONE"
                    if license_spdx_id not in added_spdx_ids:
                        none_license_node = {
                            "spdxId": license_spdx_id,
                            "type": "simplelicensing_LicenseExpression",
                            "simplelicensing_licenseExpression": "NONE",
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(none_license_node)
                        added_spdx_ids.add(license_spdx_id)
                    
                    # Create relationship
                    license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-NONE-selected-{inventoryID}"
                    if license_rel_spdx_id not in added_spdx_ids:
                        license_relationship_node = {
                            "spdxId": license_rel_spdx_id,
                            "type": "Relationship",
                            "relationshipType": "hasConcludedLicense",
                            "from": inventoryLink,
                            "to": [license_spdx_id],
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(license_relationship_node)
                        added_spdx_ids.add(license_rel_spdx_id)
                
                # Check if license is in SPDX mappings
                elif selectedIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                    logger.info("        Selected license \"%s\" maps to SPDX ID: \"%s\"" % (selectedIdentifier, SPDX_license_mappings.LICENSEMAPPINGS[selectedIdentifier]))
                    spdx_mapped_license = SPDX_license_mappings.LICENSEMAPPINGS[selectedIdentifier]
                    license_spdx_id = f"{namespaceMap}{projectID}-{spdx_mapped_license}"
                    
                    if license_spdx_id not in added_spdx_ids:
                        license_node = {
                            "spdxId": license_spdx_id,
                            "type": "simplelicensing_LicenseExpression",
                            "simplelicensing_licenseExpression": spdx_mapped_license,
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(license_node)
                        added_spdx_ids.add(license_spdx_id)
                    
                    # Create relationship
                    license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-{spdx_mapped_license}-selected-{inventoryID}"
                    if license_rel_spdx_id not in added_spdx_ids:
                        license_relationship_node = {
                            "spdxId": license_rel_spdx_id,
                            "type": "Relationship",
                            "relationshipType": "hasConcludedLicense",
                            "from": inventoryLink,
                            "to": [license_spdx_id],
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(license_relationship_node)
                        added_spdx_ids.add(license_rel_spdx_id)
                
                else:
                    # License not in SPDX mappings - create CustomLicense with LicenseRef
                    logger.warning("        Selected license \"%s\" is not a valid SPDX identifier. - Using LicenseRef." % (selectedIdentifier))
                    
                    # Clean up the identifier
                    cleanedIdentifier = selectedIdentifier.split("(", 1)[0].rstrip()  # Remove everything after (
                    cleanedIdentifier = re.sub('[^a-zA-Z0-9 \n\.]', '-', cleanedIdentifier)  # Replace special chars with dash
                    cleanedIdentifier = cleanedIdentifier.replace(" ", "-")  # Replace space with dash
                    licenseReference = "LicenseRef-%s" % cleanedIdentifier
                    
                    # Priority: noticeText > asFoundLicenseText > selectedIdentifier
                    extractedText = (inventoryItem.get("noticeText") or 
                                   inventoryItem.get("asFoundLicenseText") or 
                                   selectedIdentifier)
                    
                    custom_license_spdx_id = f"{namespaceMap}{licenseReference}"
                    
                    # Create CustomLicense element
                    if custom_license_spdx_id not in added_spdx_ids:
                        custom_license_node = {
                            "spdxId": custom_license_spdx_id,
                            "type": "expandedlicensing_CustomLicense",
                            "simplelicensing_licenseText": extractedText,
                            "name": cleanedIdentifier,
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(custom_license_node)
                        added_spdx_ids.add(custom_license_spdx_id)
                    
                    # Create relationship between package and custom license
                    custom_license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-{licenseReference}-selected-{inventoryID}"
                    if custom_license_rel_spdx_id not in added_spdx_ids:
                        custom_license_relationship_node = {
                            "spdxId": custom_license_rel_spdx_id,
                            "type": "Relationship",
                            "relationshipType": "hasConcludedLicense",
                            "from": inventoryLink,
                            "to": [custom_license_spdx_id],
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(custom_license_relationship_node)
                        added_spdx_ids.add(custom_license_rel_spdx_id)

            # add dependency relationship if applicable at package level
            if inventoryItem.get("parentInventory") is not None:
                parentPackageID = inventoryItem.get("parentInventory")
                if inventoryItem.get("dependencyScope") == 0:
                    scope = "runtime"
                else:
                    scope = "build"

                parent_rel_spdx_id = f"{namespaceMap}{parentPackageID}-isParentRelOf-{inventoryID}"
                
                parent_relationship_node = {
                    "spdxId" : parent_rel_spdx_id,
                    "type" : "LifecycleScopedRelationship",
                    "relationshipType" : "dependsOn",
                    "scope" : scope,
                    "to" : [ f"{namespaceMap}ProjectId-{projectID}-InventoryId-{parentPackageID}" ],
                    "from" : inventoryLink,
                    "creationInfo" : "_:creationInfo_0"
                }
                if parent_rel_spdx_id not in added_spdx_ids:
                    reportDetails["@graph"].append(parent_relationship_node)
                    added_spdx_ids.add(parent_rel_spdx_id)

    spdx_document_info_node = {
      "spdxId": documentNamespace,
      "type": "SpdxDocument",
      "name":  project_Name + " SPDX Document",
      "dataLicense": f"{namespaceMap}SPDXRef-CC0",
      "rootElement": inventoryLinks,
      "creationInfo": "_:creationInfo_0"
    }

    cco_license_info_node={
      "spdxId": f"{namespaceMap}SPDXRef-CC0",
      "type": "simplelicensing_LicenseExpression",
      "simplelicensing_licenseExpression": "CC0-1.0",
      "creationInfo": "_:creationInfo_0"
    }

    organization_info_node = {
      "spdxId": f"{namespaceMap}SPDXRef-Organization-{creatorName}",
      "type": "Organization",
      "name": creatorName,
      "creationInfo": "_:creationInfo_0"
    }

    # Only add nodes if their spdxIds are unique
    if spdx_document_info_node["spdxId"] not in added_spdx_ids:
        reportDetails["@graph"].append(spdx_document_info_node)
        added_spdx_ids.add(spdx_document_info_node["spdxId"])
    
    if cco_license_info_node["spdxId"] not in added_spdx_ids:
        reportDetails["@graph"].append(cco_license_info_node)
        added_spdx_ids.add(cco_license_info_node["spdxId"])

    if organization_info_node["spdxId"] not in added_spdx_ids:
        reportDetails["@graph"].append(organization_info_node)
        added_spdx_ids.add(organization_info_node["spdxId"])

    reportData["topLevelProjectName"] = topLevelProjectName
    reportData["reportDetails"] = reportDetails
    reportData["projectList"] = projectList
    return reportData

#-------------------------------------------------------
def create_supplier_string(forge, componentName):


    if forge in ["github", "gitlab"]:
        # Is there a way to determine Person vs Organization?
        supplier = "Organization: %s:%s" %(forge, componentName)
    elif forge in ["other"]:
        supplier = "Organization: Undetermined" 
    else:
        if forge != "":
            supplier = "Organization: %s:%s" %(forge, componentName)
        else:
            # Have a default value just in case one can't be created
            supplier = "Organization: Undetermined" 
   
    return supplier