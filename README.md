# NMAP-GPT

The purpose of this tool is to help new security professionals actively learn the considerations they might make based on the open ports on an NMAP scan. 

The script sends the output of the NMAP scan to the OpenAI API and provides insight on what security considerations should be made for those open ports.


```python3
python3 nmap-gpt.py example.com -p 80
```

## Example

I used instacart since they have an open bug bounty program on hackerone: https://hackerone.com/instacart/

![image](https://user-images.githubusercontent.com/63926014/218787405-c4fdd27d-06b6-44e6-ae97-174033dd2288.png)

