The idea is to track the origin IP of a website that is masked by a Web Application Firewall (WAF) by tracing its HTTP responses from the targeted IP address or CIDR range. 
The scanned HTTP responses will contain keywords similar to the website hidden behind the WAF. Of course, before obtaining the target IP address/CIDR, we need to gather clues first. 
For example, from the website's SMTP domain, followed by scanning the entire allocated IP address range.

Use Python 3.12.1
