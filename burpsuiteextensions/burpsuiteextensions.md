# Burp Suite: Extensions

## Description

Learn how to use Extensions to broaden the functionality of Burp Suite.
* Category: Walkthrough

## The Extensions Interface

The Extensions interface in Burp Suite provides an overview of the extensions loaded into the tool. Let's take a look at the different components of this interface:
1. **Extensions List**: The top box displays a list of the extensions that are currently installed in Burp Suite for the current project. It allows us to activate or deactivate individual extensions.
2. **Managing Extensions**: On the left side of the Extensions interface, there are options to manage extensions:
   * **Add**: We can use this button to install new extensions from files on our disk. These files can be custom-coded modules or modules obtained from external sources that are not available in the official BApp store.
   * **Remove**: This button allows us to uninstall selected extensions from Burp Suite.
   * **Up/Down**: These buttons control the order in which installed extensions are listed. The order determines the sequence in which extensions are invoked when processing traffic. Extensions are applied in descending order, starting from the top of the list and moving down. The order is essential, especially when dealing with extensions that modify requests, as some may conflict or interfere with others.
3. **Details**, **Output**, and **Errors**: Towards the bottom of the window, there are sections for the currently selected extension:
   * **Details**: This section provides information about the selected extension, such as its name, version, and description.
   * **Output**: Extensions can produce output during their execution, and this section displays any relevant output or results.
   * **Errors**: If an extension encounters any errors during execution, they will be shown in this section. This can be useful for debugging and troubleshooting extension issues.

In summary, the Extensions interface in Burp Suite allows users to manage and monitor the installed extensions, activate or deactivate them for specific projects, and view important details, output, and errors related to each extension. By using extensions, Burp Suite becomes a powerful and customizable platform for various security testing and web application assessment tasks.

## The BApp Store

In Burp Suite, the BApp Store (Burp App Store) allows us to easily discover and integrate official extensions seamlessly into the tool. Extensions can be written in various languages, with Java and Python being the most common choices. Java extensions integrate automatically with the Burp Suite framework, while Python extensions require the Jython interpreter.

## Jython

To use Python modules in Burp Suite, we need to include the Jython Interpreter JAR file, which is a Java implementation of Python. The Jython Interpreter enables us to run Python-based extensions within Burp Suite.

Steps to integrate Jython into Burp Suite on our local machine:
1. **Download Jython JAR**: Visit the Jython website and download the standalone JAR archive. Look for the Jython Standalone option. Save the JAR file to a location on our disk.
2. **Configure Jython in Burp Suite**: Open Burp Suite and switch to the Extensions module. Then, go to the Extensions settings sub-tab.
3. **Python Environment**: Scroll down to the "Python environment" section.
4. **Set Jython JAR Location**: In the "Location of Jython standalone JAR file" field, set the path to the downloaded Jython JAR file.

Once we have completed these steps, Jython will be integrated with Burp Suite, allowing us to use Python modules in the tool. This integration significantly increases the number of available extensions and enhances our capabilities in performing various security testing and web application assessment tasks.

## The Burp Suite API

In the Burp Suite Extensions module, we have access to a wide range of API endpoints that allow us to create and integrate our modules with Burp Suite. These APIs expose various functionalities, enabling us to extend the capabilities of Burp Suite to suit our specific needs.

To view the available API endpoints, navigate to the APIs sub-tab within the Extensions module. Each item listed in the left-hand panel represents a different API endpoint that can be accessed from within extensions.

The Extensions APIs give developers significant power and flexibility when writing custom extensions. We can use these APIs to seamlessly interact with Burp Suite's existing functionality and tailor our extensions to perform specific tasks.

Burp Suite supports multiple languages for writing extensions, such as:
1. Java (Natively): we can directly use Java to write extensions for Burp Suite, taking advantage of the powerful APIs available.
2. Python (via Jython): we can utilize Jython, which is a Java implementation of Python to create Burp Suite extensions.
3. Ruby (via JRuby): Developers familiar with Ruby can leverage JRuby, a Java implementation of Ruby, to build Burp Suite extensions.

It's important to note that coding our extensions for Burp Suite can be a complex task. However, suppose we are interested in exploring this area further and creating custom extensions. In that case, PortSwigger provides a comprehensive reference that is an excellent resource for developing Burp Suite extensions.