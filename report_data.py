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
def derive_cvss_severity(score):
    # Qualitative rating scale shared by CVSS v3.x and v4.0 (FIRST.org spec)
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score == 0.0:
        return "none"
    elif score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"
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
                    fileSHA1 = inventoryAssociatedFile.get("fileSHA1")
                    if fileSHA1:
                        fileHashes.append(fileSHA1)
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
                    # Process file-level license evidence from scanning
                    # Per SPDX 3.0.1: File-level licenses are hasConcludedLicense because they represent
                    # the tool's analysis/conclusion, not declarations within the file itself
                    package_associated_license = report_data_db.get_file_license_evidence(projectID, fileid)
                    if package_associated_license is not None and isinstance(package_associated_license, list) and len(package_associated_license) > 0:
                        file_license_expressions = []
                        
                        for license_item in package_associated_license:
                            if license_item.get("LICENSE"):
                                license = license_item["LICENSE"]
                                # Check if the license is in SPDX mappings
                                if license in SPDX_license_mappings.LICENSEMAPPINGS:
                                    license = SPDX_license_mappings.LICENSEMAPPINGS[license]
                                
                                file_license_expressions.append(license)
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
                        
                        # Create a single concluded license relationship with OR expression if multiple licenses
                        if file_license_expressions:
                            file_license_expression = create_license_expression(file_license_expressions, use_or=True)
                            file_license_expr_spdx_id = f"{namespaceMap}{projectID}-file-concluded-{fileid}"
                            
                            # Create the license expression node if needed
                            if len(file_license_expressions) > 1 and file_license_expr_spdx_id not in added_spdx_ids:
                                file_license_expr_node = {
                                    "spdxId": file_license_expr_spdx_id,
                                    "type": "simplelicensing_LicenseExpression",
                                    "simplelicensing_licenseExpression": file_license_expression,
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(file_license_expr_node)
                                added_spdx_ids.add(file_license_expr_spdx_id)
                            
                            # Create hasConcludedLicense relationship from package to file licenses
                            license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-file-{fileid}-concluded"
                            if license_rel_spdx_id not in added_spdx_ids:
                                # Use the expression node if multiple licenses, otherwise the single license
                                target_license_id = file_license_expr_spdx_id if len(file_license_expressions) > 1 else f"{namespaceMap}{projectID}-{file_license_expressions[0]}"
                                
                                package_file_license_relationship_node = {
                                    "spdxId": license_rel_spdx_id,
                                    "type": "Relationship",
                                    "relationshipType": "hasConcludedLicense",
                                    "from": inventoryLink,
                                    "to": [target_license_id],
                                    "comment": f"License concluded from file-level analysis of {fileName}",
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
                    fileSHA1 = inventoryAssociatedFile.get("fileSHA1")
                    if fileSHA1:
                        fileHashes.append(fileSHA1)
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
            # Filter out any non-string / empty values defensively so we never
            # attempt to join None into the SPDX verification code input.
            validFileHashes = sorted(h for h in fileHashes if isinstance(h, str) and h)
            if len(validFileHashes) != len(fileHashes):
                logger.warning(
                    "Skipped %d file(s) with missing SHA1 for inventory item %s",
                    len(fileHashes) - len(validFileHashes),
                    inventoryItemName,
                )
            stringHash = ''.join(validFileHashes)
            
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

            # Add all custom inventory fields as SPDX 3.x Annotation nodes (one per field)
            custom_fields = report_data_db.get_all_custom_field_values(inventoryID)
            for custom_field in custom_fields:
                field_label = custom_field["label"]
                field_value = custom_field["value"]
                safe_label = re.sub(r'[^a-zA-Z0-9]', '-', field_label)
                annotation_spdx_id = f"{namespaceMap}Annotation-{safe_label}-{inventoryID}"
                if annotation_spdx_id not in added_spdx_ids:
                    annotation_node = {
                        "spdxId": annotation_spdx_id,
                        "type": "Annotation",
                        "annotationType": "other",
                        "subject": inventoryLink,
                        "statement": f"{field_label}: {field_value}",
                        "creationInfo": "_:creationInfo_0"
                    }
                    reportDetails["@graph"].append(annotation_node)
                    added_spdx_ids.add(annotation_spdx_id)

            # Process package-level licenses (declared licenses from component metadata)
            # Per SPDX 3.0.1: hasDeclaredLicense = license info found IN the package itself
            # (e.g., LICENSE file, README, package metadata, manifest files)
            componentId = inventoryItem.get("componentId")
            declared_license_ids = []  # Track declared licenses for comparison
            
            if componentId is not None:
                possibleLicenses = report_data_db.get_component_possible_Licenses(componentId)
                if possibleLicenses is not None and isinstance(possibleLicenses, list) and len(possibleLicenses) > 0:
                    # Collect all declared license identifiers for potential OR expression
                    declared_licenses_for_expression = []
                    
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
                            declared_license_ids.append(license_spdx_id)
                            declared_licenses_for_expression.append("NONE")
                            
                            if license_spdx_id not in added_spdx_ids:
                                none_license_node = {
                                    "spdxId": license_spdx_id,
                                    "type": "simplelicensing_LicenseExpression",
                                    "simplelicensing_licenseExpression": "NONE",
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(none_license_node)
                                added_spdx_ids.add(license_spdx_id)
                        
                        # Check if license is in SPDX mappings
                        elif possibleLicenseSPDXIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                            logger.info("        \"%s\" maps to SPDX ID: \"%s\"" % (possibleLicenseSPDXIdentifier, SPDX_license_mappings.LICENSEMAPPINGS[possibleLicenseSPDXIdentifier]))
                            spdx_mapped_license = SPDX_license_mappings.LICENSEMAPPINGS[possibleLicenseSPDXIdentifier]
                            license_spdx_id = f"{namespaceMap}{projectID}-{spdx_mapped_license}"
                            declared_license_ids.append(license_spdx_id)
                            declared_licenses_for_expression.append(spdx_mapped_license)
                            
                            if license_spdx_id not in added_spdx_ids:
                                license_node = {
                                    "spdxId": license_spdx_id,
                                    "type": "simplelicensing_LicenseExpression",
                                    "simplelicensing_licenseExpression": spdx_mapped_license,
                                    "creationInfo": "_:creationInfo_0"
                                }
                                reportDetails["@graph"].append(license_node)
                                added_spdx_ids.add(license_spdx_id)
                        
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
                            declared_license_ids.append(custom_license_spdx_id)
                            declared_licenses_for_expression.append(licenseReference)
                            
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
                    
                    # Create hasDeclaredLicense relationship with proper license expression
                    # Multiple licenses typically represent alternatives (OR) not conjunctions (AND)
                    if declared_license_ids:
                        license_expression = create_license_expression(declared_licenses_for_expression, use_or=True)
                        license_expr_spdx_id = f"{namespaceMap}{projectID}-declared-{inventoryID}"
                        
                        if license_expr_spdx_id not in added_spdx_ids:
                            license_expr_node = {
                                "spdxId": license_expr_spdx_id,
                                "type": "simplelicensing_LicenseExpression",
                                "simplelicensing_licenseExpression": license_expression,
                                "creationInfo": "_:creationInfo_0"
                            }
                            reportDetails["@graph"].append(license_expr_node)
                            added_spdx_ids.add(license_expr_spdx_id)
                        
                        # Create hasDeclaredLicense relationship
                        declared_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-declared-{inventoryID}"
                        if declared_rel_spdx_id not in added_spdx_ids:
                            declared_license_relationship_node = {
                                "spdxId": declared_rel_spdx_id,
                                "type": "Relationship",
                                "relationshipType": "hasDeclaredLicense",
                                "from": inventoryLink,
                                "to": [license_expr_spdx_id],
                                "creationInfo": "_:creationInfo_0"
                            }
                            reportDetails["@graph"].append(declared_license_relationship_node)
                            added_spdx_ids.add(declared_rel_spdx_id)

            # Process inventory-specific selected license (concluded license based on user determination)
            # Per SPDX 3.0.1: hasConcludedLicense = license determined by SPDX data creator
            # after analyzing the software artifact and other information
            selectedLicenseName = inventoryItem.get("selectedLicenseName")
            selectedLicenseSPDXIdentifier = inventoryItem.get("selectedLicenseSPDXIdentifier")
            shortName = inventoryItem.get("shortName")
            concluded_license_spdx_id = None  # Track for comparison with declared
            
            if selectedLicenseName is not None and selectedLicenseName != "":
                # Determine the SPDX identifier to use
                if selectedLicenseSPDXIdentifier is not None and selectedLicenseSPDXIdentifier != "":
                    selectedIdentifier = selectedLicenseSPDXIdentifier
                elif shortName is not None and shortName != "":
                    selectedIdentifier = shortName
                else:
                    selectedIdentifier = selectedLicenseName
                
                # Prepare comment if concluded differs from declared
                concluded_comment = None
                
                # Handle Public Domain as NONE
                if selectedLicenseName == "Public Domain":
                    logger.info("        Added to NONE concludedLicense for selected license since Public Domain.")
                    concluded_license_spdx_id = f"{namespaceMap}{projectID}-NONE"
                    concluded_expression = "NONE"
                    
                    if concluded_license_spdx_id not in added_spdx_ids:
                        none_license_node = {
                            "spdxId": concluded_license_spdx_id,
                            "type": "simplelicensing_LicenseExpression",
                            "simplelicensing_licenseExpression": "NONE",
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(none_license_node)
                        added_spdx_ids.add(concluded_license_spdx_id)
                
                # Check if license is in SPDX mappings
                elif selectedIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                    logger.info("        Selected license \"%s\" maps to SPDX ID: \"%s\"" % (selectedIdentifier, SPDX_license_mappings.LICENSEMAPPINGS[selectedIdentifier]))
                    spdx_mapped_license = SPDX_license_mappings.LICENSEMAPPINGS[selectedIdentifier]
                    concluded_license_spdx_id = f"{namespaceMap}{projectID}-{spdx_mapped_license}"
                    concluded_expression = spdx_mapped_license
                    
                    if concluded_license_spdx_id not in added_spdx_ids:
                        license_node = {
                            "spdxId": concluded_license_spdx_id,
                            "type": "simplelicensing_LicenseExpression",
                            "simplelicensing_licenseExpression": spdx_mapped_license,
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(license_node)
                        added_spdx_ids.add(concluded_license_spdx_id)
                
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
                    
                    concluded_license_spdx_id = f"{namespaceMap}{licenseReference}"
                    concluded_expression = licenseReference
                    
                    # Create CustomLicense element
                    if concluded_license_spdx_id not in added_spdx_ids:
                        custom_license_node = {
                            "spdxId": concluded_license_spdx_id,
                            "type": "expandedlicensing_CustomLicense",
                            "simplelicensing_licenseText": extractedText,
                            "name": cleanedIdentifier,
                            "creationInfo": "_:creationInfo_0"
                        }
                        reportDetails["@graph"].append(custom_license_node)
                        added_spdx_ids.add(concluded_license_spdx_id)
                
                # Check if concluded license differs from declared licenses
                # Per SPDX 3.0.1: If concluded != declared, a written explanation SHOULD be provided
                if declared_license_ids and concluded_license_spdx_id not in declared_license_ids:
                    concluded_comment = f"Concluded license '{concluded_expression}' selected from available declared licenses based on analysis and user determination."
                
                # Create hasConcludedLicense relationship
                license_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-concluded-selected-{inventoryID}"
                if license_rel_spdx_id not in added_spdx_ids:
                    license_relationship_node = {
                        "spdxId": license_rel_spdx_id,
                        "type": "Relationship",
                        "relationshipType": "hasConcludedLicense",
                        "from": inventoryLink,
                        "to": [concluded_license_spdx_id],
                        "creationInfo": "_:creationInfo_0"
                    }
                    # Add comment if concluded differs from declared
                    if concluded_comment:
                        license_relationship_node["comment"] = concluded_comment
                    
                    reportDetails["@graph"].append(license_relationship_node)
                    added_spdx_ids.add(license_rel_spdx_id)

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

            # Process vulnerabilities for this component
            # Per SPDX 3.0.1: Vulnerability class represents security vulnerabilities
            component_version_id = inventoryItem.get("component_version_id")
            if component_version_id is not None:
                vulnerabilities = report_data_db.get_component_version_vdr_vulnerabilities(projectID, component_version_id)
                
                if vulnerabilities is not None and isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
                    for vuln in vulnerabilities:
                        vuln_id = vuln.get("vulnerabilityId")
                        vuln_name = vuln.get("vulnerabilityName")
                        
                        if vuln_name:
                            # Create unique SPDX ID for vulnerability
                            vuln_spdx_id = f"{namespaceMap}Vulnerability-{vuln_name}"
                            
                            # Only add vulnerability if not already added
                            if vuln_spdx_id not in added_spdx_ids:
                                # Build vulnerability node according to SPDX 3.0.1
                                vulnerability_node = {
                                    "spdxId": vuln_spdx_id,
                                    "type": "security_Vulnerability",
                                    "creationInfo": "_:creationInfo_0"
                                }
                                
                                # Add description
                                vuln_desc = vuln.get("vulnerabilityDescription")
                                if vuln_desc:
                                    vulnerability_node["description"] = vuln_desc
                                
                                # Add summary (brief description)
                                if vuln_desc:
                                    # Create a summary - first sentence or first 100 chars
                                    summary = vuln_desc.split('.')[0] if '.' in vuln_desc else vuln_desc[:100]
                                    vulnerability_node["summary"] = summary
                                
                                # Add externalIdentifier for CVE
                                if vuln_name:
                                    external_id = {
                                        "type": "ExternalIdentifier",
                                        "identifier": vuln_name,
                                        "externalIdentifierType": "cve"
                                    }
                                    # Add CVE locator URL if this is a CVE identifier
                                    if vuln_name.startswith("CVE-"):
                                        external_id["identifierLocator"] = [f"https://www.cve.org/CVERecord?id={vuln_name}"]
                                    vulnerability_node["externalIdentifier"] = [external_id]
                                
                                # Add externalRef for advisory URLs
                                external_refs = []
                                if vuln.get("vulnerabilityUrl"):
                                    external_refs.append({
                                        "type": "ExternalRef",
                                        "locator": [vuln.get("vulnerabilityUrl")],
                                        "externalRefType": "securityAdvisory"
                                    })
                                if external_refs:
                                    vulnerability_node["externalRef"] = external_refs
                                
                                # Add published date - convert MM/DD/YYYY to ISO format
                                if vuln.get("publishedDate"):
                                    try:
                                        pub_date = vuln.get("publishedDate")
                                        # Parse MM/DD/YYYY and convert to ISO format
                                        dt = datetime.datetime.strptime(pub_date, "%m/%d/%Y")
                                        vulnerability_node["security_publishedTime"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                                    except:
                                        pass
                                
                                # Add vulnerability node to report
                                reportDetails["@graph"].append(vulnerability_node)
                                added_spdx_ids.add(vuln_spdx_id)
                            
                            # Create relationship from package to vulnerability
                            vuln_rel_spdx_id = f"{namespaceMap}{inventoryItemName}-hasVulnerability-{vuln_name}"
                            if vuln_rel_spdx_id not in added_spdx_ids:
                                vulnerability_relationship = {
                                    "spdxId": vuln_rel_spdx_id,
                                    "type": "Relationship",
                                    "relationshipType": "hasAssociatedVulnerability",
                                    "from": inventoryLink,
                                    "to": [vuln_spdx_id],
                                    "creationInfo": "_:creationInfo_0"
                                }
                                
                                reportDetails["@graph"].append(vulnerability_relationship)
                                added_spdx_ids.add(vuln_rel_spdx_id)
                            
                            # Create CVSS v4 assessment relationship - score, severity and vectorString are all required (1..1) by the spec,
                            # so only emit when vector+score are both present (severity is derived from score if not supplied)
                            if vuln.get("vulnerabilityCvssV4Vector") and vuln.get("vulnerabilityCvssV4Score"):
                                cvssv4_severity = vuln.get("vulnerabilityCvssV4Severity")
                                cvssv4_severity = cvssv4_severity.lower() if cvssv4_severity else derive_cvss_severity(vuln.get("vulnerabilityCvssV4Score"))
                                if cvssv4_severity:
                                    cvssv4_rel_spdx_id = f"{namespaceMap}CvssV4Assessment-{vuln_name}-{inventoryItemName}"
                                    if cvssv4_rel_spdx_id not in added_spdx_ids:
                                        cvssv4_assessment = {
                                            "spdxId": cvssv4_rel_spdx_id,
                                            "type": "security_CvssV4VulnAssessmentRelationship",
                                            "relationshipType": "hasAssessmentFor",
                                            "from": vuln_spdx_id,
                                            "to": [inventoryLink],
                                            "security_assessedElement": inventoryLink,
                                            "security_score": str(vuln.get("vulnerabilityCvssV4Score")),
                                            "security_vectorString": vuln.get("vulnerabilityCvssV4Vector"),
                                            "security_severity": cvssv4_severity,
                                            "creationInfo": "_:creationInfo_0"
                                        }
                                        
                                        # Add published time
                                        if vuln.get("publishedDate"):
                                            try:
                                                pub_date = vuln.get("publishedDate")
                                                dt = datetime.datetime.strptime(pub_date, "%m/%d/%Y")
                                                cvssv4_assessment["security_publishedTime"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                                            except:
                                                pass
                                        
                                        reportDetails["@graph"].append(cvssv4_assessment)
                                        added_spdx_ids.add(cvssv4_rel_spdx_id)
                            
                            # Create CVSS v3 assessment relationship - score, severity and vectorString are all required (1..1) by the spec,
                            # so only emit when vector+score are both present (severity is derived from score if not supplied)
                            if vuln.get("vulnerabilityCvssV3Vector") and vuln.get("vulnerabilityCvssV3Score"):
                                cvssv3_severity = vuln.get("vulnerabilityCvssV3Severity")
                                cvssv3_severity = cvssv3_severity.lower() if cvssv3_severity else derive_cvss_severity(vuln.get("vulnerabilityCvssV3Score"))
                                if cvssv3_severity:
                                    cvssv3_rel_spdx_id = f"{namespaceMap}CvssV3Assessment-{vuln_name}-{inventoryItemName}"
                                    if cvssv3_rel_spdx_id not in added_spdx_ids:
                                        cvssv3_assessment = {
                                            "spdxId": cvssv3_rel_spdx_id,
                                            "type": "security_CvssV3VulnAssessmentRelationship",
                                            "relationshipType": "hasAssessmentFor",
                                            "from": vuln_spdx_id,
                                            "to": [inventoryLink],
                                            "security_assessedElement": inventoryLink,
                                            "security_vectorString": vuln.get("vulnerabilityCvssV3Vector"),
                                            "security_score": str(vuln.get("vulnerabilityCvssV3Score")),
                                            "security_severity": cvssv3_severity,
                                            "creationInfo": "_:creationInfo_0"
                                        }
                                        
                                        # Add published time
                                        if vuln.get("publishedDate"):
                                            try:
                                                pub_date = vuln.get("publishedDate")
                                                dt = datetime.datetime.strptime(pub_date, "%m/%d/%Y")
                                                cvssv3_assessment["security_publishedTime"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                                            except:
                                                pass
                                        
                                        reportDetails["@graph"].append(cvssv3_assessment)
                                        added_spdx_ids.add(cvssv3_rel_spdx_id)
                            
                            # Create CVSS v2 assessment relationship - score and vectorString are both required (1..1) by the spec
                            # (v2 has no severity property). Emitted independently of v3/v4 - SPDX models each CVSS version
                            # as its own concrete relationship type.
                            if vuln.get("vulnerabilityCvssV2Vector") and vuln.get("vulnerabilityCvssV2Score"):
                                cvssv2_rel_spdx_id = f"{namespaceMap}CvssV2Assessment-{vuln_name}-{inventoryItemName}"
                                if cvssv2_rel_spdx_id not in added_spdx_ids:
                                    cvssv2_assessment = {
                                        "spdxId": cvssv2_rel_spdx_id,
                                        "type": "security_CvssV2VulnAssessmentRelationship",
                                        "relationshipType": "hasAssessmentFor",
                                        "from": vuln_spdx_id,
                                        "to": [inventoryLink],
                                        "security_assessedElement": inventoryLink,
                                        "security_vectorString": vuln.get("vulnerabilityCvssV2Vector"),
                                        "security_score": str(vuln.get("vulnerabilityCvssV2Score")),
                                        "creationInfo": "_:creationInfo_0"
                                    }
                                    
                                    # Add published time
                                    if vuln.get("publishedDate"):
                                        try:
                                            pub_date = vuln.get("publishedDate")
                                            dt = datetime.datetime.strptime(pub_date, "%m/%d/%Y")
                                            cvssv2_assessment["security_publishedTime"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                                        except:
                                            pass
                                    
                                    reportDetails["@graph"].append(cvssv2_assessment)
                                    added_spdx_ids.add(cvssv2_rel_spdx_id)

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
def create_license_expression(licenses, use_or=True):
    """
    Create a proper SPDX license expression from a list of licenses.
    
    Args:
        licenses: List of license identifiers
        use_or: If True, use OR operator (for license alternatives/choices)
               If False, use AND operator (when both licenses apply)
    
    Returns:
        String with proper SPDX license expression
    """
    if not licenses or len(licenses) == 0:
        return None
    
    if len(licenses) == 1:
        return licenses[0]
    
    # Remove duplicates while preserving order
    unique_licenses = []
    for lic in licenses:
        if lic not in unique_licenses:
            unique_licenses.append(lic)
    
    if len(unique_licenses) == 1:
        return unique_licenses[0]
    
    # Use OR for alternatives (most common case - component offers choice of licenses)
    # Use AND only when explicitly needed (both licenses apply simultaneously)
    operator = " OR " if use_or else " AND "
    
    # Wrap each license in parentheses if it contains operators
    formatted_licenses = []
    for lic in unique_licenses:
        if " OR " in lic or " AND " in lic:
            formatted_licenses.append(f"({lic})")
        else:
            formatted_licenses.append(lic)
    
    return operator.join(formatted_licenses)

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