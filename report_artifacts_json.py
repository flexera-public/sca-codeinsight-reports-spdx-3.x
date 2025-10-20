'''
Copyright 2023 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Fri Aug 18 2023
File : report_artifacts_json.py
'''
import logging, json
logger = logging.getLogger(__name__)

#--------------------------------------------------------------------------------#

def generate_json_report(reportData):
    logger.info("    Entering generate_json_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    reportDetails = reportData["reportDetails"]

    jsonFile = reportFileNameBase + ".spdx.json"

    # Write the SPDX 3.0.1 JSON-LD structure
    try:
        with open(jsonFile, "w", encoding="utf-8") as report_ptr:
            json.dump(reportDetails, report_ptr, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to open file {jsonFile}: {e}")
        logger.error(f"Failed to open file {jsonFile}: {e}")
        return {"errorMsg": f"Failed to open file {jsonFile}: {e}"}

    logger.info("    Exiting generate_json_report")
    return jsonFile
