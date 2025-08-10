---
layout: post
title: Monitoring & Assessing Browser Extension Installations
date: 2024-01-22
categories: [Detection Engineering]
tags: [Detection-Engineering, Browser-Extensions, KQL, CrowdStrike, Azure-Logic-Apps]
---

This guide aims to offer a practical approach to enhance browser security using Azure and Kusto Query Language (KQL). As the use of browser extensions continues to grow, so does the potential for security risks. These extensions, while often helpful, can introduce vulnerabilities and pose threats to online security. We will delve into the process of identifying installed browser extensions and evaluating the associated risks.

## Detecting Browser Extension Installations with KQL

To begin, let’s explore a straightforward method using Kusto Query Language (KQL) to detect the installation of browser extensions. When a browser extension is installed, a .crx file gets generated within the “Webstore Downloads” directory, a subdirectory found within the installation location of Chromium-based browsers. This means we can monitor this directory for new .crx entries to detect newly installed browser extensions. The KQL query below extracts the Extension ID, which serves as a unique identifier for each extension.

```kql
ASimFileEventLogs
| where TargetFilePath contains "Webstore Downloads" and TargetFilePath endswith ".crx"
| extend ExtensionId = extract(@"(?i)Downloads[\\/]|Webstore Downloads[\\/](.+?)_\d+\.crx", 1, TargetFilePath)
```

Let’s break down the KQL query:

* ``ASimFileEventLogs``: As we use CrowdStrike as our Endpoint Detection and Response (EDR) solution, we’ll make use of the CrowdStrike logs that are sent to our SIEM (Sentinel). In this case we are using the normalized CS logs.

* ``| where TargetFilePath contains "Webstore Downloads" and TargetFilePath endswith ".crx"``: Filters the logs to only include events where a .crx file (Chrome extension package) was downloaded in the Webstore Downloads directory.

* ``| extend ExtensionId = extract(@"(?i)Downloads[\\/]|Webstore Downloads[\\/](.+?)_\d+\.crx", 1, TargetFilePath)``: Here, we create a new column, ExtensionId. The magic happens with the extract function, utilizing a regular expression which works for both Windows and macOS environments.

* ``(?i)``:  Enables case-insensitive matching.

* ``(Downloads[\\/]|Webstore Downloads[\\/])``:  Matches either "Downloads/" or "Webstore Downloads/`, covering both operating systems.

* ``(.+?)``: Captures the Extension ID dynamically.

* ``_\d+\.crx``: Matches an underscore, followed by one or more digits (extension version), and ends with ".crx".

CrowdStrike also has a ``CrxFileWrittenV2`` event, but it includes a lot of noise, like .tmp files that get created during extension installations. So you end up filtering on the filepath anyway, hence why I didn't use this event.

## Enhancing Extension Data with Azure Logic Apps

The above KQL query, only gives us the extension id though. So to get more information about the installed extension, we integrated Azure Logic Apps into the workflow. Triggered by the detection alert with the KQL query above, the Logic App performs a GET request with the following URL structure: [https://chrome.google.com/webstore/detail/](https://chrome.google.com/webstore/detail/)<TEXT>/<extension_id>. “TEXT” can be filled in by any random string.

For example:

    curl -X GET "https://chrome.google.com/webstore/detail/TEXT/mcebeofpilippmndlpcghpmghcljajna"

When we use “TEXT” in the url (or any other random string), it’s expected that the request should redirect to the correct browser extension details. However, because Logic Apps don’t support redirection, the first HTTP request gets a 302 error. But, in the response of this request, we can see the full and correct location of the extension. So to work around this, we set up a “run after” condition for the HTTP request. By extracting the full correct URL from the initial GET request and initiating another GET request with the extracted url, we now receive a 200 response that contains all the extension information we require.

![](https://cdn-images-1.medium.com/max/2918/1*Bsdl-hXQaxixHwpkm-Cm4g.png)

The GET request response holds the HTML of the extension’s webpage. So, with the “Compose” action in the logic app, we filtered out the extension name and version.

* Filter extension version:
  first(split(last(split(body('GET_ExtensionName'), '<meta itemprop="version" content="')), '"'))

* Filter extension name:
  split(outputs('Get_ExtensionDetails')['headers']['Location'], '/')[5]

## Assessing the risk with CRXcavator

Our next aim is to get a handle on any potential risks the browser extension might bring. To tackle this, we have used the [https://api.crxcavator.io/v1/report/](https://api.crxcavator.io/v1/report/) API. This external tool simplifies things by handing us a neat risk score for each extension. The structure of the API call is as follow:

    https://api.crxcavator.io/v1/report/<extension_id>/<extension_version>

Here’s an overview of the logic app’s flow that handles the CRXcavator API call.

![](https://cdn-images-1.medium.com/max/2552/1*VpWxnopvlzk4rCE88c1Otw.png)

## Conclusion

To wrap it up, this solution presents a comprehensive method for detecting, and evaluating the risk of installed browser extensions. You can now send alerts that specifically detail the risk information of each installed browser extension, enabling you to take timely and targeted actions.
