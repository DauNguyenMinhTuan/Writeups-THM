# Wireshark: The Basics

## Description

Learn the basics of Wireshark and how to analyse protocols and PCAPs.
* Category: Walkthrough

## Introduction

Wireshark is an open-source, cross-platform network packet analyser tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools.

## Tool Overview

### Use Cases

Wireshark is one of the most potent traffic analyser tools available in the wild. There are multiple purposes for its use:
* Detecting and troubleshooting network problems, such as network load failure points and congestion.
* Detecting security anomalies, such as rogue hosts, abnormal port usage, and suspicious traffic.
* Investigating and learning protocol details, such as response codes and payload data.

Wireshark is not an Intrusion Detection System (IDS). It only allows analysts to discover and investigate the packets in depth. It also doesn't modify packets; it reads them. Hence, detecting any anomaly or network problem highly relies on the analyst's knowledge and investigation skills.

### GUI and Data

Wireshark GUI opens with a single all-in-one page, which helps users investigate the traffic in multiple ways. At first glance, five sections stand out.

| **Toolbar** | The main toolbar contains multiple menus and shortcuts for packet sniffing and processing, including filtering, sorting, summarising, exporting and merging. |
| **Display Filter Bar** | The main query and filtering section. |
| **Recent Files** | List of the recently investigated files. We can recall listed files with a double-click. |
| **Capture Filter and Interfaces** | Capture filters and available sniffing points (network interfaces). The network interface is the connection point between a computer and a network. The software connection (e.g., lo, eth0 and ens33) enables networking hardware. |
| **Status Bar** | Tool status, profile and numeric packet information. |

### Loading PCAP Files

As we open a PCAP file, we can see the processed filename, detailed number of packets and packet details. Packet details are shown in three different panes, which allow us to discover them in different formats.

| **Packet List Pane** | Summary of each packet (source and destination addresses, protocol, and packet info). We can click on the list to choose a packet for further investigation. Once we select a packet, the details will appear in the other panels. |
| **Packet Details Pane** | Detailed protocol breakdown of the selected packet. |
| **Packet Bytes Pane** | Hex and decoded ASCII representation of the selected packet. It highlights the packet field depending on the clicked section in the details pane. |

### Colouring Packets

Along with quick packet information, Wireshark also colour packets in order of different conditions and the protocol to spot anomalies and protocols in captures quickly. This glance at packet information can help track down exactly what we're looking for during analysis. We can create custom colour rules to spot events of interest by using display filters.

Wireshark has two types of packet colouring methods: temporary rules that are only available during a program session and permanent rules that are saved under the preference file (profile) and available for the next program session.

We can use the "right-click menu" or "**View $\rarr$ Coloring Rules**" menu to create permanent colouring rules. The "**Colourise Packet List**" menu activates/deactivates the colouring rules. Temporary packet colouring is done with the "right-click menu" or "**View $\rarr$ Conversation Filter**" menu.

### Traffic Sniffing

We can use the blue "**shark button**" to start network sniffing (capturing traffic), the red button will stop the sniffing, and the green button will restart the sniffing process. The status bar will also provide the used sniffing interface and the number of collected packets.

### Merge PCAP Files

Wireshark can combine two pcap files into one single file. We can use the "**File $\rArr$ Merge**" menu path to merge a pcap with the processed one. When we choose the second file, Wireshark will show the total number of packets in the selected file. Once we click "open", it will merge the existing pcap file with the chosen one and create a new pcap file. Note that we need to save the "merged" pcap file before working on it.

### View File Details

Knowing the file details is helpful. Especially when working with multiple pcap files, sometimes we will need to know and recall the file details (File hash, capture time, capture file comments, interface and statistics) to identify the file, classify and prioritise it.

We can view the details by following "**Statistics $\rarr$ Capture File Properties**" or by clicking the "**pcap icon located on the left bottom**" of the window.

## Packet Dissection

Packet dissection is also known as protocol dissection, which investigates packet details by decoding available protocols and fields. Wireshark supports a long list of protocols for dissection, and we can also write our dissection scripts.

### Packet Details

We can click on a packet in the packet list pane to open its details (double-click will open details in a new window). Packets consist of 5 to 7 layers based on the OSI model.

Each time we click a detail, it will highlight the corresponding part in the packet bytes pane.

**The Frame (Layer 1)**: This will show us what frame/packet we are looking at and details specific to the Physical layer of the OSI model.

**Source [MAC] (Layer 2)**: This will show us the source and destination MAC Addresses; from the Data Link layer of the OSI model.

**Source [IP] (Layer 3)**: This will show us the source and destination IPv4 Addresses; from the Network layer of the OSI model.

**Protocol (Layer 4)**: This will show us details of the protocol used (UDP/TCP) and source and destination ports; from the Transport layer of the OSI model.

**Protocol Errors**: This continuation of the 4th layer shows specific segments from TCP that needed to be reassembled.

**Application Protocol (Layer 5)**: This will show details specific to the protocol used, such as HTTP, FTP, and SMB. From the Application layer of the OSI model.

**Application Data**: This extension of the 5th layer can show the application-specific data.

## Packet Navigation

### Packet Numbers

Wireshark calculates the number of investigated packets and assigns a unique number for each packet. This helps the analysis process for big captures and makes it easy to go back to a specific point of an event.

### Go to Packet

Packet numbers do not only help to count the total number of packets or make it easier to find/investigate specific packets. This feature not only navigates between packets up and down; it also provides in-frame packet tracking and finds the next packet in the particular part of the conversation. We can use the "**Go**" menu and toolbar to view specific packets.

### Find Packets

Apart from packet number, Wireshark can find packets by packet content. We can use the "**Edit $\rarr$ Find Packet**" menu to make a search inside the packets for a particular event of interest. This helps analysts and administrators to find specific intrusion patterns or failure traces.

There are two crucial points in finding packets. The first is knowing the input type. This functionality accepts four types of inputs (Display filter, Hex, String and Regex). String and regex searches are the most commonly used search types. Searches are case insensitive, but we can set the case sensitivity in our search by clicking the radio button.

The second point is choosing the search field. We can conduct searches in the three panes (packet list, packet details, and packet bytes), and it is important to know the available information in each pane to find the event of interest.

### Mark Packets

Marking packets is another helpful functionality for analysts. We can find/point to a specific packet for further investigation by marking it. It helps analysts point to an event of interest or export particular packets from the capture. We can use the "**Edit**" or the "right-click" menu to mark/unmark packets.

Marked packets will be shown in black regardless of the original colour representing the connection type. Note that marked packet information is renewed every file session, so marked packets will be lost after closing the capture file.

### Packet Comments

Similar to packet marking, commenting is another helpful feature for analysts. We can add comments for particular packets that will help the further investigation or remind and point out important/suspicious points for other layer analysts. Unlike packet marking, the comments can stay within the capture file until the operator removes them.

### Export Packets

Capture files can contain thousands of packets in a single file. As mentioned earlier, Wireshark is not an IDS, so sometimes, it is necessary to separate specific packages from the file and dig deeper to resolve an incident. This functionality helps analysts share the only suspicious packages (decided scope). Thus redundant information is not included in the analysis process. We can use the "**File**" menu to export packets.

### Export Objects (Files)

Wireshark can extract files transferred through the wire. For a security analyst, it is vital to discover shared files and save them for further investigation. Exporting objects are available only for selected protocol's streams (DICOM, HTTP, IMF, SMB and TFTP).

### Time Display Format

Wireshark lists the packets as they are captured, so investigating the default flow is not always the best option. By default, Wireshark shows the time in "Seconds Since Beginning of Capture", the common usage is using the UTC Time Display Format for a better view. We can use the "**View $\rarr$ Time Display Format**" menu to change the time display format.

### Expert Info

Wireshark also detects specific states of protocols to help analysts easily spot possible anomalies and problems. Note that these are only suggestions, and there is always a chance of having false positives/negatives. Expert info can provide a group of categories in three different severities. Details are shown in the table below.

| **Severity** | **Colour** | **Info** |
| - | - | - |
| **Chat** | <span style="color:blue">**Blue**</span> | Information on usual workflow. |
| **Note** | <span style="color:cyan">**Cyan**</span> | Notable events like application error codes. |
| **Warn** | <span style="color:yellow">**Yellow**</span> | Warnings like unusual error codes or problem statements. |
| **Error** | <span style="color:red">**Red**</span> | Problems like malformed packets. |

Frequently encountered information groups are listed in the table below.

| **Group** | **Info** |
| - | - |
| **Checksum** | Checksum errors. |
| **Comment** | Packet comment detection. |
| **Deprecated** | Deprecated protocol usage. |
| **Malformed** | Malformed packet detection. |

We can use the "**lower left bottom section**" in the status bar or "**Analyse $\rarr$ Expert Information**" menu to view all available information entries via a dialogue box. It will show the packet number, summary, group protocol and total occurrence.

## Packet Filtering

Wireshark has a powerful filter engine that helps analysts to narrow down the traffic and focus on the event of interest. Wireshark has two types of filtering approaches: capture and display filters.

Capture filters are used for "**capturing**" only the packets valid for the used filter. Display filters are used for "**viewing**" the packets valid for the used filter.

Filters are specific queries designed for protocols available in Wireshark's official protocol reference. While the filters are only the option to investigate the event of interest, there are two different ways to filter traffic and remove the noise from the capture file. The first one uses queries, and the second uses the right-click menu. Wireshark provides a powerful GUI, and there is a golden rule for analysts who don't want to write queries for basic tasks: "**If you can click on it, you can filter and copy it**".

### Apply as Filter

This is the most basic way of filtering traffic. While investigating a capture file, we can click on the field we want to filter and use the "right-click menu" or "**Analyse $\rarr$ Apply as Filter**" menu to filter the specific value.

Once we apply the filter, Wireshark will generate the required filter query, apply it, show the packets according to our choice, and hide the unselected packets from the packet list pane. Note that the number of total and displayed packets are always shown on the status bar.

### Conversation Filter

When we use the "Apply as a Filter" option, we will filter only a single entity of the packet. This option is a good way of investigating a particular value in packets. However, suppose we want to investigate a specific packet number and all linked packets by focusing on IP addresses and port numbers. In that case, the "Conversation Filter" option helps us view only the related packets and hide the rest of the packets easily. We can use the"right-click menu" or "**Analyse $\rarr$ Conversation Filter**" menu to filter conversations.

### Colourise Conversation

This option is similar to the "Conversation Filter" with one difference. It highlights the linked packets without applying a display filter and decreasing the number of viewed packets. This option works with the "Colouring Rules" option and changes the packet colours without considering the previously applied colour rule. We can use the "right-click menu" or "**View $\rarr$ Colourise Conversation**" menu to colourise a linked packet in a single click. Note that we can use the "**View $\rarr$ Colourise Conversation $\rarr$ Reset Colourisation**" menu to undo this operation.

### Prepare as Filter

Similar to "Apply as Filter", this option helps analysts create display filters using the "right-click" menu. However, unlike the previous one, this model doesn't apply the filters after the choice. It adds the required query to the pane and waits for the execution command (enter) or another chosen filtering option by using the "**.. and/or..**" from the "right-click menu".

### Apply as Column

By default, the packet list pane provides basic information about each packet. We can use the "right-click menu" or "**Analyse $\rarr$ Apply as Column**" menu to add columns to the packet list pane. Once we click on a value and apply it as a column, it will be visible on the packet list pane. This function helps analysts examine the appearance of a specific value/field across the available packets in the capture file. We can enable/disable the columns shown in the packet list pane by clicking on the top of the packet list pane.

### Follow Stream

Wireshark displays everything in packet portion size. However, it is possible to reconstruct the streams and view the raw traffic as it is presented at the application level. Following the protocol, streams help analysts recreate the application-level data and understand the event of interest. It is also possible to view the unencrypted protocol data like usernames, passwords and other transferred data.

We can use the "right-click menu" or "**Analyse $\rarr$ Follow TCP/UDP/HTTP Stream**" menu to follow traffic streams. Streams are shown in a separate dialogue box; packets originating from the server are highlighted with blue, and those originating from the client are highlighted with red.

Once we follow a stream, Wireshark automatically creates and applies the required filter to view the specific stream. Once a filter is applied, the number of the viewed packets will change. We will need to use the "**X button**" located on the right upper side of the display filter bar to remove the display filter and view all available packets in the capture file.